'use strict';
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const { run } = require('../publication-engine'), F = require('../deployment-files'), R = require('../sepolia-rpc');
const { fake } = require('./public-publisher-support');
test('all 6596 original fixture commitments and 68 receipts reconcile without a new transaction', async () => {
    const f = fake(), result = await run({ ...f, mode: 'EXECUTE', progress: n => { if(n % 10 === 0) console.log('Fixture original receipts: ' + n + ' / 68'); }, readProgress: n => { if(n % 1000 === 0 || n === 6596) console.log('Fixture officer readback: ' + n + ' / 6596'); } });
    assert.equal(result.status, 'PASSED'); assert.equal(result.officers, 6596); assert.equal(result.original_valid_transactions, 68);
    assert.equal(f.state.records.size, 6596); assert.equal(f.state.broadcasts.length, 68);
    for (const ch of f.plan.chunks) ch.handles.forEach((h, i) => assert.equal(f.state.records.get(h), ch.commitments[i]));
    const reconciled = await run({ ...f, mode: 'RECONCILE' }); assert.equal(reconciled.status, 'PASSED'); assert.equal(reconciled.submitted_transactions_this_run, 0); assert.equal(f.state.broadcasts.length, 68);
});
for (const point of ['AFTER_PREPARE', 'AFTER_BROADCAST', 'AFTER_RECEIPT', 'AFTER_READBACK']) test('original signed transaction survives ' + point, async () => {
    const f = fake(); f.publicationBudget = '0.005'; await assert.rejects(run({ ...f, mode: 'EXECUTE', interrupt: (p, i) => { if (p === point && i === 0) throw new Error('interrupt fixture'); } }));
    const before = F.read(path.join(f.directory, '00-PREPARED.json'));
    const result = await run({ ...f, mode: 'EXECUTE' }); assert.equal(result.status, 'FUNDING_OR_BUDGET_REQUIRED');
    assert.equal(F.read(path.join(f.directory, '00-PREPARED.json')).raw_transaction, before.raw_transaction);
    assert.equal(new Set(f.state.broadcasts).size, 1);
});
test('validate cannot sign or broadcast; reconcile cannot prepare missing originals', async () => {
    const f = fake(); f.wallet = { address: f.wallet.address, signTransaction: () => assert.fail('signed') };
    assert.equal((await run({ ...f, mode: 'VALIDATE' })).status, 'READY');
    assert.equal((await run({ ...f, mode: 'RECONCILE' })).reason, 'ORIGINAL_TRANSACTION_NOT_PREPARED');
    assert.equal(f.state.broadcasts.length, 0); assert.equal(fs.existsSync(path.join(f.directory, '00-PREPARED.json')), false);
});
test('partial budget stops before preparing another transaction and can resume with explicitly reviewed budget', async () => {
    const f = fake(), first = await run({ ...f, mode: 'EXECUTE', publicationBudget: '0.005' });
    assert.equal(first.status, 'FUNDING_OR_BUDGET_REQUIRED'); assert.equal(f.state.broadcasts.length, 1);
    const original = F.read(path.join(f.directory, '00-PREPARED.json'));
    assert.equal((await run({ ...f, mode: 'EXECUTE', publicationBudget: '0.01' })).status, 'FUNDING_OR_BUDGET_REQUIRED');
    assert.equal(f.state.broadcasts.length, 2);
    assert.equal(F.read(path.join(f.directory, '00-PREPARED.json')).raw_transaction, original.raw_transaction);
});
test('insufficient wallet funds stop without signing', async () => {
    const f = fake(); f.state.balance = 1n;
    assert.equal((await run({ ...f, mode: 'EXECUTE' })).status, 'FUNDING_OR_BUDGET_REQUIRED'); assert.equal(f.state.broadcasts.length, 0);
});
test('unfinalized mined receipts cannot become complete', async () => {
    const f = fake(); f.state.finality = false;
    assert.equal((await run({ ...f, mode: 'EXECUTE' })).reason, 'ALL_ORIGINAL_TRANSACTIONS_REQUIRE_FINALITY');
    assert.equal(fs.existsSync(path.join(f.directory, 'PASSED.json')), false);
    f.state.finality = true; assert.equal((await run({ ...f, mode: 'RECONCILE' })).status, 'PASSED');
});
test('ambiguous broadcast preserves original signed bytes and never invents a receipt', async () => {
    const f = fake(); f.publicationBudget = '0.005'; f.state.failBroadcast = true; f.state.receipts = false;
    const first = await run({ ...f, mode: 'EXECUTE' }); assert.equal(first.status, 'PENDING');
    const prepared = F.read(path.join(f.directory, '00-PREPARED.json'));
    assert.ok(f.state.broadcasts.every(raw => raw === prepared.raw_transaction));
    f.state.receipts = true; f.state.failBroadcast = false;
    assert.equal((await run({ ...f, mode: 'EXECUTE' })).status, 'FUNDING_OR_BUDGET_REQUIRED');
});
const faults = {
    mainnet: (m, p, v) => m === 'eth_chainId' ? '0x1' : v,
    runtime: (m, p, v) => m === 'eth_getCode' ? '0x00' : v,
    gas_cap: (m, p, v) => m === 'eth_estimateGas' ? R.hex(16777216n) : v,
    failed_receipt: (m, p, v) => m === 'eth_getTransactionReceipt' && v ? { ...v, status: '0x0' } : v,
    changed_event: (m, p, v) => m === 'eth_getTransactionReceipt' && v ? { ...v, logs: [] } : v,
    changed_transaction: (m, p, v) => m === 'eth_getTransactionByHash' && v ? { ...v, input: '0x00' } : v,
    receipt_disagreement: (m, p, v, i) => m === 'eth_getTransactionReceipt' && v && i === 1 ? { ...v, gasUsed: '0x1' } : v,
    reorg: (m, p, v) => m === 'eth_getBlockByNumber' && p[0] !== 'latest' && p[0] !== 'finalized' && p[0] !== '0x0' && v ? { ...v, hash: '0x' + '00'.repeat(32) } : v,
    unrelated_nonce: (m, p, v) => m === 'eth_getTransactionCount' && p[1] === 'pending' ? '0x4' : v
};
for (const [name, tamper] of Object.entries(faults)) test('publisher rejects ' + name, async () => {
    const f = fake(); f.state.tamper = tamper; await assert.rejects(run({ ...f, mode: 'EXECUTE' }));
    assert.equal(fs.existsSync(path.join(f.directory, 'PASSED.json')), false);
});
test('changed stored officer commitment stops full final readback', async () => {
    const f = fake(); f.state.tamper = (m, p, v) => m === 'eth_call' && p[0].data.startsWith(require('ethers').id('readOfficer(bytes32,bytes32)').slice(0, 10)) ? '0x' + '00'.repeat(32) : v;
    await assert.rejects(run({ ...f, mode: 'EXECUTE' }), /commitment readback differs/);
    assert.equal(fs.existsSync(path.join(f.directory, 'PASSED.json')), false);
});
test('fresh gate expiry before broadcast preserves prepared original without submitting', async () => {
    const f = fake(); let expired = false;
    const result = await run({ ...f, mode: 'EXECUTE', guard: () => { if (expired) throw new Error('Fresh live gate required'); },
        interrupt: p => { if (p === 'AFTER_PREPARE') expired = true; } });
    assert.equal(result.reason, 'FRESH_AUTHORIZATION_REQUIRED');
    assert.equal(f.state.broadcasts.length, 0); assert.ok(fs.existsSync(path.join(f.directory, '00-PREPARED.json')));
});
test('altered saved signed bytes or configuration cannot reconcile', async () => {
    for (const field of ['raw_transaction', 'identity']) {
        const f = fake(); await assert.rejects(run({ ...f, mode: 'EXECUTE', interrupt: p => { if (p === 'AFTER_PREPARE') throw new Error('stop'); } }));
        const file = path.join(f.directory, '00-PREPARED.json'), value = F.read(file);
        if (field === 'raw_transaction') value[field] = '0x00'; else value.identity.config_sha256 = '0'.repeat(64);
        fs.writeFileSync(file, F.stable(value)); await assert.rejects(run({ ...f, mode: 'RECONCILE' })); assert.equal(f.state.broadcasts.length, 0);
    }
});
