'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { readPacing } = require('../rpc-read-pacing');
const { endpoint, safeFailure } = require('../rpc-read-recovery');
function virtual() {
    let now = 0; const waits = [];
    return { clock: () => now, sleep: async ms => { waits.push(ms); now += ms; }, waits };
}
function response(body, status = 200) {
    return { ok: status === 200, status, body: { async cancel() {} }, async text() { return JSON.stringify(body); } };
}
test('queued batch weight reserves logical reads and serializes HTTP dispatch', async () => {
    const v = virtual(), p = readPacing(v), starts = [];
    await Promise.all([10, 10, 1].map(weight => p.run(weight, async () => starts.push(v.clock()))));
    assert.deepEqual(starts, [0, 1000, 2000]);
});
test('provider cooldown applies to already queued reads and clears after elapsed time', async () => {
    const v = virtual(), p = readPacing(v), starts = [];
    await Promise.all([p.run(1, async () => { starts.push(v.clock()); p.cooldown(); }),
        p.run(1, async () => starts.push(v.clock())), p.run(1, async () => starts.push(v.clock()))]);
    assert.deepEqual(starts, [0, 5000, 5100]);
});
test('failed read does not poison the queue or hide original failure', async () => {
    const v = virtual(), p = readPacing(v);
    await assert.rejects(p.run(1, async () => { throw new Error('original'); }), /original/);
    assert.equal(await p.run(1, async () => 42), 42); assert.equal(v.clock(), 100);
});
test('invalid pacing bounds and weights cannot dispatch', async () => {
    assert.throws(() => readPacing({ intervalMs: 0 })); assert.throws(() => readPacing({ cooldownMs: 31000 }));
    await assert.rejects(readPacing().run(11, () => { throw new Error('must not run'); }));
});
for (const mode of ['http', 'numeric', 'global']) test('paced retry keeps original block after ' + mode + ' 429', async () => {
    const v = virtual(), starts = [], sent = [];
    const rpc = endpoint('https://fixture.invalid', { pacing: true, pacingDependencies: v, sleep: v.sleep,
        fetchImpl: async (_, options) => {
            const messages = JSON.parse(options.body); sent.push(messages); starts.push(v.clock());
            const replies = messages.map(m => ({ jsonrpc: '2.0', id: m.id, result: '0x1' }));
            if (sent.length === 1) {
                if (mode === 'http') return response(null, 429);
                const error = { code: 429, message: 'Too many requests' };
                if (mode === 'global') return response({ jsonrpc: '2.0', id: null, error });
                replies[0] = { jsonrpc: '2.0', id: messages[0].id, error };
            }
            return response(replies);
        } });
    const requests = Array.from({ length: 10 }, () => ({ method: 'eth_call', params: [{}, '0xb54408'] }));
    assert.equal((await rpc.batch(requests)).length, 10);
    assert.deepEqual(starts, [0, 5000]);
    assert.ok(sent.flat().every(m => m.params[1] === '0xb54408'));
});
test('sustained throttling stops at three paced attempts', async () => {
    const v = virtual(), starts = [];
    const rpc = endpoint('https://fixture.invalid', { pacing: true, pacingDependencies: v, sleep: v.sleep,
        fetchImpl: async () => { starts.push(v.clock()); return response(null, 429); } });
    await assert.rejects(rpc.call('eth_call', [{}, '0xb54408']), e => safeFailure(e).attempts === 3);
    assert.deepEqual(starts, [0, 5000, 10000]);
});
test('two providers maintain independent pacing queues', async () => {
    const a = virtual(), b = virtual(), p = readPacing(a), q = readPacing(b);
    p.cooldown(); await q.run(10, async () => {}); assert.equal(b.clock(), 0);
    await p.run(1, async () => {}); assert.equal(a.clock(), 5000);
});
test('production endpoint enables pacing without caller configuration', async () => {
    const original = globalThis.fetch, starts = [];
    try {
        globalThis.fetch = async (_, options) => {
            starts.push(performance.now()); const r = JSON.parse(options.body);
            return response({ jsonrpc: '2.0', id: r.id, result: '0x1' });
        };
        const rpc = endpoint('https://fixture.invalid', 1);
        await Promise.all([rpc.call('eth_chainId', []), rpc.call('eth_chainId', [])]);
        assert.ok(starts[1] - starts[0] >= 95);
    } finally { globalThis.fetch = original; }
});
test('paced endpoint never retries signed broadcasts', async () => {
    const v = virtual(); let calls = 0;
    const rpc = endpoint('https://fixture.invalid', { pacing: true, pacingDependencies: v,
        fetchImpl: async () => { calls++; return response(null, 429); } });
    await assert.rejects(rpc.call('eth_sendRawTransaction', ['signed-original']), e => !safeFailure(e).read_retryable);
    assert.equal(calls, 1); assert.deepEqual(v.waits, []);
});
test('all 6596 commitments use paced independent providers at the same finalized block', async () => {
    const { fake } = require('./public-publisher-support'), { readAll } = require('../publication-engine');
    const f = fake(), seal = { block: '0xa7', block_hash: '0x' + 'ab'.repeat(32) };
    f.state.created = true; f.state.sealed = true; f.state.count = 6596;
    for (const c of f.plan.chunks) c.handles.forEach((h, i) => f.state.records.set(h, c.commitments[i]));
    const clocks = [virtual(), virtual()], batches = [0, 0], covered = [new Set(), new Set()];
    const rpcs = f.rpcs.map((base, peer) => endpoint('https://fixture.invalid', {
        pacing: true, pacingDependencies: clocks[peer], sleep: clocks[peer].sleep,
        fetchImpl: async (_, options) => {
            const input = JSON.parse(options.body), entries = Array.isArray(input) ? input : [input];
            if (Array.isArray(input)) batches[peer]++;
            const replies = await Promise.all(entries.map(async m => {
                if (Array.isArray(input)) { assert.equal(m.params[1], '0x1000'); covered[peer].add(m.params[0].data); }
                const result = m.method === 'eth_getBlockByNumber' && m.params[0] === seal.block ?
                    { number: seal.block, hash: seal.block_hash } : await base.call(m.method, m.params);
                return { jsonrpc: '2.0', id: m.id, result };
            }));
            return response(Array.isArray(input) ? replies.reverse() : replies[0]);
        }
    }));
    const result = await readAll(rpcs, f.plan, f.artifact,
        { contract: f.deployment.contract_address, writer: f.wallet.address }, seal);
    assert.equal(result.block, '0x1000'); assert.deepEqual(batches, [660, 660]);
    assert.deepEqual(covered.map(s => s.size), [6596, 6596]);
    assert.ok(clocks.every(v => v.clock() >= 659000)); assert.equal(f.state.broadcasts.length, 0);
});
