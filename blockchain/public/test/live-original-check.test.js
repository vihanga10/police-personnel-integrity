'use strict';
// Fake Fabric and Sepolia clients only: no key, dataset or chain is touched.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');
const {run, validate} = require('../live-original-check');
const h = c => c.repeat(64), sha = b => crypto.createHash('sha256').update(b).digest('hex');
function files(t) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'live-check-')); t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
    const fabric = path.join(dir, 'gateway.json'), network = path.join(dir, 'network.json');
    fs.writeFileSync(fabric, '{"x":1}', {mode: 0o600}); fs.writeFileSync(network, JSON.stringify({rpc_urls: ['https://one.example/key', 'https://two.example/key']}), {mode: 0o600});
    return {fabric, network, fabric_sha256: sha(fs.readFileSync(fabric)), network_sha256: sha(fs.readFileSync(network))};
}
function job(f, over = {}) {
    return {batch: h('1'), handle: h('2'), commitment: h('3'), merkle_root: h('4'), contract: '0x' + '5'.repeat(40), chain_id: 11155111, sealing_block: 100, officers: 6596,
        fabric_config: f.fabric, fabric_sha256: f.fabric_sha256, network_config: f.network, network_sha256: f.network_sha256, ...over};
}
function deps({sepolia = {}, fabric = {}, calls = {}} = {}) {
    const s = {officer: '0x' + h('3'), root: '0x' + h('4'), count: 6596n, sealed: true, finalized: 150, fail: [], ...sepolia};
    const ethers = {
        FetchRequest: class { constructor(url) { this.url = url; } },
        JsonRpcProvider: class { constructor(request) { this.request = request; calls.urls = [...(calls.urls || []), request.url]; }
            async getBlock(tag) { assert.equal(tag, 'finalized'); return {number: s.finalized}; } destroy() {} },
        Contract: class { constructor(address, abi, provider) { this.provider = provider; calls.abi = abi;
            if (s.fail.includes(provider.request.url)) { this.fail = true; } }
            async readOfficer(batch, handle) { if (this.fail) { const e = new Error('connect ECONNREFUSED /secret/path'); e.code = 'NETWORK_ERROR'; throw e; } calls.read = [batch, handle]; return s.officer; }
            async readBatch(batch) { if (this.fail) throw Object.assign(new Error('x'), {code: 'NETWORK_ERROR'}); return [[ '0x' + h('9'), s.root, '0x' + h('8'), '0x' + h('7'), '0x' + h('6')], s.count, s.sealed]; } }};
    const f = {Org1MSP: {publication_id: h('2'), commitment: h('3'), batch_root: 'x', batch_publication_id: h('1')}, ...fabric.officer};
    f.Org2MSP = fabric.officer?.Org2MSP || {...f.Org1MSP};
    const batch = {Org1MSP: {metadata: {merkle_root: h('4'), officer_count: 6596}}, Org2MSP: {metadata: {merkle_root: h('4'), officer_count: 6596}}, ...fabric.batch};
    const connections = () => ({verifyNetwork: async () => { if (fabric.networkFails) throw Object.assign(new Error('/secret/genesis'), {code: 14}); },
        driver: {observe: async method => { if (fabric.observeFails) throw new Error('/secret/ledger path'); calls.fabricMethods = [...(calls.fabricMethods || []), method]; return method === 'ReadOfficer' ? f : batch; }},
        close: () => { calls.closed = (calls.closed || 0) + 1; }});
    return {ethers, connections};
}
test('both chains agree: the check passes, is read-only and submits nothing', async t => {
    const f = files(t), calls = {}, out = await run(job(f), deps({calls}));
    assert.equal(out.passed, true); assert.equal(out.read_only, true); assert.equal(out.transactions_submitted, 0);
    assert.deepEqual(out.fabric.organizations, ['Org1MSP', 'Org2MSP']); assert.equal(out.fabric.passed, true); assert.equal(out.sepolia.passed, true);
    assert.deepEqual(calls.fabricMethods.sort(), ['ReadBatch', 'ReadOfficer']); assert.deepEqual(calls.read, ['0x' + h('1'), '0x' + h('2')]); assert.equal(calls.closed, 1);
    assert.ok(calls.abi.every(line => /view returns/.test(line)), 'only view functions are ever called');
    assert.ok(!JSON.stringify(out).includes(f.fabric) && !JSON.stringify(out).includes('key'), 'no path or RPC key in the output');
});
test('a Sepolia mismatch of any kind fails the check', async t => {
    const f = files(t);
    for (const sepolia of [{officer: '0x' + h('a')}, {root: '0x' + h('b')}, {sealed: false}, {count: 6595n}, {finalized: 99}]) {
        const out = await run(job(f), deps({sepolia})); assert.equal(out.sepolia.status, 'READ'); assert.equal(out.sepolia.passed, false, Object.keys(sepolia)[0]); assert.equal(out.passed, false);
    }
});
test('a Fabric mismatch of any kind fails the check', async t => {
    const f = files(t), bad = {...{publication_id: h('2'), commitment: h('a'), batch_publication_id: h('1')}};
    for (const fabric of [{officer: {Org2MSP: bad}}, {officer: {Org1MSP: bad, Org2MSP: bad}}, {batch: {Org2MSP: {metadata: {merkle_root: h('b'), officer_count: 6596}}}},
        {batch: {Org1MSP: {metadata: {merkle_root: h('4'), officer_count: 1}}, Org2MSP: {metadata: {merkle_root: h('4'), officer_count: 1}}}}]) {
        const out = await run(job(f), deps({fabric})); assert.equal(out.fabric.status, 'READ'); assert.equal(out.fabric.passed, false, JSON.stringify(fabric)); assert.equal(out.passed, false);
    }
});
test('the second RPC is tried when the first is down; failures are reported as short codes, never raw messages', async t => {
    const f = files(t), calls = {}, out = await run(job(f), deps({calls, sepolia: {fail: ['https://one.example/key']}}));
    assert.equal(out.sepolia.passed, true); assert.deepEqual(calls.urls, ['https://one.example/key', 'https://two.example/key']);
    const down = await run(job(f), deps({sepolia: {fail: ['https://one.example/key', 'https://two.example/key']}}));
    assert.deepEqual(down.sepolia, {status: 'UNAVAILABLE', reason: 'NETWORK_ERROR'}); assert.equal(down.passed, false);
    for (const fabric of [{networkFails: true}, {observeFails: true}]) {
        const calls2 = {}, o = await run(job(f), deps({fabric, calls: calls2})); assert.equal(o.fabric.status, 'UNAVAILABLE'); assert.equal(o.passed, false); assert.equal(calls2.closed, 1, 'connection closed even on failure');
        assert.ok(/^[A-Z0-9_]+$/.test(o.fabric.reason) && !JSON.stringify(o).includes('secret'));
    }
});
test('a changed pinned configuration is refused before any chain is contacted', async t => {
    const f = files(t), calls = {}, out = await run(job(f, {fabric_sha256: h('0'), network_sha256: h('0')}), deps({calls}));
    assert.deepEqual(out.fabric, {status: 'UNAVAILABLE', reason: 'GATEWAY_CONFIG_DIFFERS'}); assert.deepEqual(out.sepolia, {status: 'UNAVAILABLE', reason: 'NETWORK_CONFIG_DIFFERS'});
    assert.equal(calls.closed, undefined); assert.equal(calls.urls, undefined);
});
test('a malformed job is rejected', async t => {
    const f = files(t);
    for (const over of [{batch: 'zz'}, {handle: h('G')}, {commitment: ''}, {contract: '0x12'}, {chain_id: 'x'}, {sealing_block: 0}, {officers: -1}, {fabric_sha256: 'abc'}])
        assert.throws(() => validate(job(f, over)), /JOB_INVALID/);
    assert.throws(() => validate(null), /JOB_INVALID/);
    await assert.rejects(run({}, deps()), /JOB_INVALID/);
});
