'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { endpoint, safeFailure } = require('../rpc-read-recovery');
const { BATCH_LIMIT } = require('../rpc-read-batch');
const PRIVATE = 'https://SECRET.invalid/private-personnel-value';
const requests = () => [0, 1, 2].map(n => ({ method: 'eth_call', params: [{ data: '0x' + n }, '0x1000'] }));
function response(body, status = 200) {
    return { ok: status === 200, status, body: { async cancel() {} },
        async text() { return typeof body === 'string' ? body : JSON.stringify(body); } };
}
function success(messages) { return messages.map(m => ({ jsonrpc: '2.0', id: m.id, result: m.params[0].data })); }
function fixture(transform) {
    const sent = [], waits = [];
    const rpc = endpoint(PRIVATE, { sleep: async ms => waits.push(ms), fetchImpl: async (_, options) => {
        const messages = JSON.parse(options.body); sent.push(messages);
        return transform(messages, sent.length);
    } });
    return { rpc, sent, waits };
}

test('unordered batch replies map to exact requested positions', async () => {
    const f = fixture(messages => response(success(messages).reverse()));
    assert.deepEqual(await f.rpc.batch(requests()), ['0x0', '0x1', '0x2']);
    assert.equal(f.sent.length, 1); assert.equal(new Set(f.sent[0].map(m => m.id)).size, 3);
});

for (const mode of ['missing', 'extra', 'duplicate_id', 'unknown_id', 'string_id', 'both_fields',
    'neither_field', 'wrong_version', 'null_item', 'bad_json', 'oversized', 'global_error'])
test('hard stop for batch ' + mode, async () => {
    const f = fixture(messages => {
        const body = success(messages);
        if (mode === 'missing') body.pop();
        if (mode === 'extra') body.push({ jsonrpc: '2.0', id: 999, result: '0x1' });
        if (mode === 'duplicate_id') body[1].id = body[0].id;
        if (mode === 'unknown_id') body[1].id = 999;
        if (mode === 'string_id') body[1].id = String(body[1].id);
        if (mode === 'both_fields') body[1].error = { code: -32000, message: PRIVATE };
        if (mode === 'neither_field') delete body[1].result;
        if (mode === 'wrong_version') body[1].jsonrpc = '1.0';
        if (mode === 'null_item') body[1] = null;
        if (mode === 'bad_json') return response(PRIVATE);
        if (mode === 'oversized') return response('X'.repeat(4 * 1024 * 1024 + 1));
        if (mode === 'global_error') return response({ jsonrpc: '2.0', id: null, error: { code: -32600, message: PRIVATE } });
        return response(body);
    });
    await assert.rejects(f.rpc.batch(requests()), e => {
        assert.ok(['INCOMPLETE_RPC_BATCH', 'MALFORMED_RPC_BATCH', 'RPC_BATCH_REJECTED'].includes(safeFailure(e).category));
        assert.ok(!JSON.stringify(safeFailure(e)).includes(PRIVATE)); return true;
    });
    assert.equal(f.sent.length, 1); assert.deepEqual(f.waits, []);
});

for (const input of [[], Array.from({ length: BATCH_LIMIT + 1 }, () => requests()[0]),
    [{ method: 'eth_sendRawTransaction', params: [PRIVATE] }],
    [{ method: 'eth_call', params: [], id: 1 }], [{ method: 'eth_call', params: PRIVATE }]])
test('invalid, oversized or write batch refused before network access', async () => {
    const f = fixture(() => { throw new Error('Unexpected fetch'); });
    await assert.rejects(f.rpc.batch(input), e => safeFailure(e).category === 'INVALID_READ_BATCH');
    assert.equal(f.sent.length, 0);
});

for (const mode of ['http', 'transport', 'mixed_rate'])
test('transient batch ' + mode + ' retries same block and content', async () => {
    const f = fixture((messages, attempt) => {
        if (attempt === 1) {
            if (mode === 'http') return response(null, 429);
            if (mode === 'transport') throw new Error(PRIVATE);
            const body = success(messages); body[1] = { jsonrpc: '2.0', id: messages[1].id,
                error: { code: -32005, message: 'rate limit exceeded ' + PRIVATE } };
            return response(body);
        }
        return response(success(messages).reverse());
    });
    assert.deepEqual(await f.rpc.batch(requests()), ['0x0', '0x1', '0x2']);
    assert.equal(f.sent.length, 2); assert.deepEqual(f.waits, [500]);
    assert.deepEqual(f.sent[0].map(m => m.params), f.sent[1].map(m => m.params));
    assert.ok(f.sent[1].every(m => !f.sent[0].some(first => first.id === m.id)));
});

test('permanent historical error wins over another transient batch member', async () => {
    const f = fixture(messages => response(messages.map((m, i) => ({ jsonrpc: '2.0', id: m.id,
        ...(i === 0 ? { error: { code: -32005, message: 'rate limit exceeded' } } :
            i === 1 ? { error: { code: -32000, message: 'historical state unavailable ' + PRIVATE } } :
                { result: '0x1' }) }))));
    await assert.rejects(f.rpc.batch(requests()), e => safeFailure(e).category === 'HISTORICAL_STATE_UNAVAILABLE');
    assert.equal(f.sent.length, 1); assert.equal(f.waits.length, 0);
});

test('exhausted batch transport retries stop at three with no partial result', async () => {
    const f = fixture(() => { throw new Error(PRIVATE); });
    await assert.rejects(f.rpc.batch(requests()), e => safeFailure(e).attempts === 3);
    assert.equal(f.sent.length, 3); assert.deepEqual(f.waits, [500, 1500]);
});

test('caller mutation does not change captured batch on retry', async () => {
    const input = requests(), sent = [];
    const rpc = endpoint(PRIVATE, { sleep: async () => { input[0].params[1] = 'latest'; },
        fetchImpl: async (_, options) => {
            const messages = JSON.parse(options.body); sent.push(messages);
            return sent.length === 1 ? response(null, 503) : response(success(messages));
        } });
    await rpc.batch(input); assert.ok(sent.flat().every(m => m.params[1] === '0x1000'));
});

function captured(fault) {
    const { fake } = require('./public-publisher-support'), { readAll } = require('../publication-engine');
    const f = fake(), seal = { block: '0xa7', block_hash: '0x' + 'ab'.repeat(32) };
    f.state.created = true; f.state.sealed = true; f.state.count = 6596;
    for (const chunk of f.plan.chunks) chunk.handles.forEach((h, i) => f.state.records.set(h, chunk.commitments[i]));
    const batches = [], singles = [], covered = [new Set(), new Set()], waits = [];
    let injected = false;
    const rpcs = f.rpcs.map((rpc, peer) => endpoint('https://fixture.invalid', {
        sleep: async ms => waits.push(ms), fetchImpl: async (_, options) => {
            const request = JSON.parse(options.body);
            const base = async message => {
                if (message.method === 'eth_getBlockByNumber' && message.params[0] === seal.block)
                    return { number: seal.block, hash: seal.block_hash };
                return rpc.call(message.method, message.params);
            };
            if (Array.isArray(request)) {
                batches.push({ peer, request });
                assert.ok(request.length <= 10 && request.every(m => m.method === 'eth_call' && m.params[1] === '0x1000'));
                const values = await Promise.all(request.map(async m => {
                    covered[peer].add(m.params[0].data);
                    return { jsonrpc: '2.0', id: m.id, result: await base(m) };
                }));
                if (fault === 'rate' && peer === 0 && covered[peer].size >= 5100 && !injected) {
                    injected = true; return response(null, 429);
                }
                if (fault === 'mismatch' && peer === 1 && covered[peer].size >= 5100)
                    values[0].result = '0x' + 'dd'.repeat(32);
                if (fault === 'missing' && peer === 1 && covered[peer].size >= 5100) values.pop();
                return response(values.reverse());
            }
            singles.push({ peer, request });
            return response({ jsonrpc: '2.0', id: request.id, result: await base(request) });
        }
    }));
    return { f, batches, singles, covered, waits,
        read: progress => readAll(rpcs, f.plan, f.artifact,
            { contract: f.deployment.contract_address, writer: f.wallet.address }, seal, progress) };
}

test('both providers batch all 6596 exact commitments at one fixed block', async () => {
    const c = captured(); let progress = 0;
    assert.equal((await c.read(n => { progress = n; })).block, '0x1000');
    assert.equal(progress, 6596); assert.equal(c.batches.length, 1320);
    assert.deepEqual(c.covered.map(set => set.size), [6596, 6596]);
    assert.equal(c.f.state.broadcasts.length, 0);
    assert.ok(c.batches.slice(-2).every(b => b.request.length === 6));
});

test('batched full readback survives bounded transient failure near 5100', async () => {
    const c = captured('rate'); let progress = 0;
    await c.read(n => { progress = n; });
    assert.equal(progress, 6596); assert.equal(c.batches.length, 1321);
    assert.deepEqual(c.waits, [500]); assert.deepEqual(c.covered.map(s => s.size), [6596, 6596]);
    assert.equal(c.f.state.broadcasts.length, 0);
});

for (const fault of ['mismatch', 'missing']) test('changed or missing commitment stops batched readback: ' + fault, async () => {
    const c = captured(fault); let progress = 0;
    await assert.rejects(c.read(n => { progress = n; }));
    assert.ok(progress < 6596); assert.equal(c.f.state.broadcasts.length, 0);
});
