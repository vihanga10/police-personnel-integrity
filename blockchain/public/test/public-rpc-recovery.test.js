'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { endpoint, safeFailure } = require('../rpc-read-recovery');
const PRIVATE = 'https://private.invalid/API_SECRET personal-value';
function response(request, result = '0x1', error, status = 200) {
    return { ok: status === 200, status, body: { async cancel() {} },
        async text() { return JSON.stringify({ jsonrpc: '2.0', id: request.id,
            ...(error ? { error } : { result }) }); } };
}
function harness(reply) {
    const calls = [], waits = [];
    const rpc = endpoint(PRIVATE, { sleep: async ms => waits.push(ms),
        fetchImpl: async (url, options) => {
            const request = JSON.parse(options.body); calls.push(request);
            return reply(request, calls.length);
        } });
    return { rpc, calls, waits };
}
for (const fault of ['http429', 'http503', 'transport', 'rate'])
test('bounded original-parameter recovery for ' + fault, async () => {
    const h = harness((r, n) => {
        if (n === 1) {
            if (fault === 'transport') throw new Error(PRIVATE);
            if (fault === 'rate') return response(r, null, { code: -32005, message: 'rate limit exceeded ' + PRIVATE });
            return response(r, null, null, fault === 'http429' ? 429 : 503);
        }
        return response(r, '0x1234');
    });
    const params = [{ to: '0xaddress', data: '0xprivate' }, '0x1000'];
    assert.equal(await h.rpc.call('eth_call', params), '0x1234');
    assert.equal(h.calls.length, 2); assert.deepEqual(h.waits, [500]);
    assert.deepEqual(h.calls.map(c => c.params), [params, params]);
    assert.notEqual(h.calls[0].id, h.calls[1].id);
});

test('exhausted retries expose only fixed diagnostic fields', async () => {
    const h = harness(r => response(r, null, { code: -32005, message: 'too many requests ' + PRIVATE }));
    await assert.rejects(h.rpc.call('eth_call', [{ data: PRIVATE }, '0x1000']), error => {
        assert.equal(safeFailure(error).attempts, 3);
        assert.equal(safeFailure(error).block_tag, '0x1000');
        assert.equal(safeFailure(error).category, 'TRANSIENT_PROVIDER_FAILURE');
        assert.ok(!JSON.stringify(safeFailure(error)).includes('SECRET'));
        assert.ok(!String(error).includes(PRIVATE)); return true;
    });
    assert.deepEqual(h.waits, [500, 1500]); assert.equal(h.calls.length, 3);
});

for (const [category, message, code] of [
    ['HISTORICAL_STATE_UNAVAILABLE', 'missing trie node ' + PRIVATE, -32000],
    ['RPC_REJECTED', 'execution reverted ' + PRIVATE, -32000],
    ['RPC_REJECTED', 'invalid params ' + PRIVATE, -32602],
    ['PROVIDER_QUOTA_EXHAUSTED', 'monthly quota exhausted ' + PRIVATE, -32005],
    ['RPC_REJECTED', 'unclassified rejection ' + PRIVATE, -32000]
]) test('no retries on ' + category + ': ' + code, async () => {
    const h = harness(r => response(r, null, { code, message }));
    await assert.rejects(h.rpc.call('eth_call', [{}, 'finalized']), e => safeFailure(e).category === category);
    assert.equal(h.calls.length, 1); assert.deepEqual(h.waits, []);
});

for (const method of ['eth_sendRawTransaction', 'unknown_private_method'])
test('never automatically repeat non-allowlisted operation ' + method, async () => {
    const h = harness(() => { throw new Error(PRIVATE); });
    await assert.rejects(h.rpc.call(method, [PRIVATE]), e => {
        assert.equal(safeFailure(e).read_retryable, false);
        assert.ok(!JSON.stringify(safeFailure(e)).includes(PRIVATE)); return true;
    });
    assert.equal(h.calls.length, 1); assert.equal(h.waits.length, 0);
});

for (const defect of ['wrong_id', 'both_fields', 'neither_field', 'bad_json', 'oversized'])
test('malformed response ' + defect + ' is a hard stop', async () => {
    const h = harness(r => ({ ok: true, status: 200, async text() {
        if (defect === 'bad_json') return PRIVATE;
        if (defect === 'oversized') return 'x'.repeat(4 * 1024 * 1024 + 1);
        return JSON.stringify({ jsonrpc: '2.0', id: defect === 'wrong_id' ? r.id + 1 : r.id,
            ...(defect === 'neither_field' ? {} : { result: '0x1' }),
            ...(defect === 'both_fields' ? { error: { message: PRIVATE } } : {}) });
    } }));
    await assert.rejects(h.rpc.call('eth_getCode', ['0xaddress', '0x1000']),
        e => safeFailure(e).category === 'MALFORMED_RPC_RESPONSE');
    assert.equal(h.calls.length, 1);
});

test('valid null read result is returned without retry', async () => {
    const h = harness(r => response(r, null));
    assert.equal(await h.rpc.call('eth_getTransactionReceipt', ['0xhash']), null);
    assert.equal(h.calls.length, 1);
});

test('unknown local failures and sensitive block tags are redacted', async () => {
    assert.deepEqual(safeFailure(new Error(PRIVATE)), {
        policy: 'SAFE_RPC_READ_RECOVERY_V1', category: 'VERIFICATION_OR_LOCAL_FAILURE',
        check_code: 'UNCLASSIFIED_SAFE_FAILURE' });
    const h = harness(() => { throw new Error(PRIVATE); });
    await assert.rejects(h.rpc.call('eth_call', [{}, PRIVATE]), e => safeFailure(e).block_tag === null);
    assert.equal(safeFailure(new Error('Original officer commitment readback differs')).check_code,
        'OFFICER_COMMITMENT_MISMATCH');
});

test('HTTP authentication failure stops immediately', async () => {
    const h = harness(r => response(r, null, null, 401));
    await assert.rejects(h.rpc.call('eth_getCode', ['0xaddress', 'latest']),
        e => safeFailure(e).category === 'HTTP_REJECTED');
    assert.equal(h.calls.length, 1);
});

test('production Array.map provider index is safe and identifies the failing RPC', async () => {
    const original = globalThis.fetch;
    try {
        globalThis.fetch = async (_, options) => response(JSON.parse(options.body), null, null, 401);
        const rpcs = ['https://one.invalid/SECRET', 'https://two.invalid/SECRET'].map(endpoint);
        for (const [index, rpc] of rpcs.entries())
            await assert.rejects(rpc.call('eth_getCode', ['0xaddress', '0x1000']), error => {
                assert.equal(safeFailure(error).rpc, index + 1); return true;
            });
    } finally { globalThis.fetch = original; }
});

test('caller mutation cannot change retry block or calldata', async () => {
    const params = [{ data: '0x1234' }, '0x1000']; let calls = 0; const recorded = [];
    const rpc = endpoint('https://one.invalid', {
        sleep: async () => { params[1] = 'latest'; params[0].data = '0x5678'; },
        fetchImpl: async (_, options) => {
            const request = JSON.parse(options.body); recorded.push(request.params);
            return ++calls === 1 ? response(request, null, null, 429) : response(request, '0x1');
        }
    });
    assert.equal(await rpc.call('eth_call', params), '0x1');
    assert.deepEqual(recorded, [[{ data: '0x1234' }, '0x1000'], [{ data: '0x1234' }, '0x1000']]);
});

test('guarded CLI prints safe diagnostics without private raw error text', () => {
    const { spawnSync } = require('node:child_process'), path = require('node:path');
    const result = spawnSync(process.execPath, [path.resolve(__dirname, '../publish-research.js')],
        { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Public readback diagnostic:/);
    assert.match(result.stderr, /UNCLASSIFIED_SAFE_FAILURE/);
    assert.ok(!result.stderr.includes('Guarded Python launcher required'));
});

test('full 6596 readback recovers one transient request at position 5101 without writes', async () => {
    const { fake } = require('./public-publisher-support');
    const { readAll } = require('../publication-engine');
    const { Interface } = require('ethers');
    const f = fake(), seal = { block: '0xa7', block_hash: '0x' + 'ab'.repeat(32) };
    f.state.created = true; f.state.sealed = true; f.state.count = 6596;
    for (const chunk of f.plan.chunks)
        chunk.handles.forEach((handle, i) => f.state.records.set(handle, chunk.commitments[i]));
    const iface = new Interface(f.artifact.abi);
    const target = iface.encodeFunctionData('readOfficer', [f.plan.batch, f.plan.chunks[51].handles[0]]);
    let injected = false; const retried = [], waits = [], methods = [];
    const endpoints = f.rpcs.map((rpc, peer) => endpoint('https://fixture.invalid', {
        sleep: async ms => waits.push(ms), fetchImpl: async (_, options) => {
            const request = JSON.parse(options.body); methods.push(request.method);
            if (peer === 0 && request.method === 'eth_call' && request.params[0].data === target) {
                retried.push(request.params);
                if (!injected) { injected = true; return response(request, null, null, 429); }
            }
            if (request.method === 'eth_getBlockByNumber' && request.params[0] === seal.block)
                return response(request, { number: seal.block, hash: seal.block_hash });
            return response(request, await rpc.call(request.method, request.params));
        }
    }));
    // Keep this fixture focused on single-request retry recovery. Batch transport
    // and complete batch coverage are exercised in public-batch-read.test.js.
    const rpcs = endpoints.map(rpc => ({ call: (method, params) => rpc.call(method, params) }));
    let count = 0;
    const result = await readAll(rpcs, f.plan, f.artifact,
        { contract: f.deployment.contract_address, writer: f.wallet.address }, seal, n => { count = n; });
    assert.equal(count, 6596); assert.equal(result.block, '0x1000'); assert.equal(injected, true);
    assert.equal(retried.length, 2); assert.deepEqual(retried[0], retried[1]);
    assert.deepEqual(waits, [500]); assert.equal(f.state.broadcasts.length, 0);
    assert.ok(methods.every(m => !['eth_sendRawTransaction', 'eth_estimateGas'].includes(m)));
});
