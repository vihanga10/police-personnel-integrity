'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { readAll } = require('../publication-engine');
const { fake } = require('./public-publisher-support');
const R = require('../sepolia-rpc');

function captured() {
    const f = fake(), seal = { block: '0xa7', block_hash: '0x' + 'ab'.repeat(32) };
    f.state.created = true; f.state.sealed = true; f.state.count = 6596;
    for (const ch of f.plan.chunks) ch.handles.forEach((h, i) => f.state.records.set(h, ch.commitments[i]));
    const calls = [], stateHash = '0x' + 'ff'.repeat(32);
    const rpcs = f.rpcs.map((rpc, peer) => ({ async call(method, params) {
        calls.push({ method, params, peer });
        if (method === 'eth_getBlockByNumber' && params[0] === seal.block)
            return { number: seal.block, hash: seal.block_hash };
        if ((method === 'eth_call' && params[1] === seal.block) ||
            (method === 'eth_getCode' && params[1] === seal.block)) throw new Error('Archive state unavailable');
        return rpc.call(method, params);
    } }));
    return { f, seal, calls, stateHash, rpcs, async read(progress) {
        return readAll(this.rpcs, f.plan, f.artifact, { contract: f.deployment.contract_address, writer: f.wallet.address }, seal, progress);
    } };
}

test('all 6596 commitments verify with pruned seal state and no broadcast', async () => {
    const c = captured(), progress = [], result = await c.read(n => progress.push(n));
    assert.deepEqual(result, { policy: 'COMMON_FINALIZED_PUBLICATION_STATE_V1', block: '0x1000', block_hash: c.stateHash });
    assert.equal(progress.at(-1), 6596); assert.equal(c.f.state.broadcasts.length, 0);
    const reads = c.calls.filter(x => ['eth_call', 'eth_getCode'].includes(x.method));
    assert.ok(reads.length > 13192); assert.ok(reads.every(x => x.params[1] === '0x1000'));
    assert.ok(!c.calls.some(x => ['eth_sendRawTransaction','eth_estimateGas'].includes(x.method)));
});

test('different finalized heads use the lower agreed height for every state read', async () => {
    const c = captured(), base = c.rpcs;
    c.rpcs = base.map((rpc, peer) => ({ async call(m, p) {
        if (m === 'eth_getBlockByNumber' && p[0] === 'finalized') return { number: peer ? '0x1001' : '0x1000' };
        return rpc.call(m, p);
    } }));
    assert.equal((await c.read()).block, '0x1000');
});

const faults = {
    missing_head: (m,p,v) => m === 'eth_getBlockByNumber' && p[0] === 'finalized' ? null : v,
    before_seal: (m,p,v) => m === 'eth_getBlockByNumber' && p[0] === 'finalized' ? { number: '0x1' } : v,
    hash_disagreement: (m,p,v,peer) => m === 'eth_getBlockByNumber' && p[0] === '0x1000' && peer ? { ...v, hash: '0x' + 'cc'.repeat(32) } : v,
    wrong_height: (m,p,v) => m === 'eth_getBlockByNumber' && p[0] === '0x1000' ? { ...v, number: '0xfff' } : v,
    malformed_hash: (m,p,v) => m === 'eth_getBlockByNumber' && p[0] === '0x1000' ? { ...v, hash: '0x1' } : v,
    seal_changed: (m,p,v) => m === 'eth_getBlockByNumber' && p[0] === '0xa7' ? { ...v, hash: '0x' + 'cc'.repeat(32) } : v,
    runtime_changed: (m,p,v) => m === 'eth_getCode' ? '0x00' : v,
    rejected_state: (m,p,v) => { if (m === 'eth_getCode') throw new Error('RPC rejected request'); return v; }
};
for (const [name, mutate] of Object.entries(faults)) test('hard stop on ' + name + ' without writes', async () => {
    const c = captured(); c.rpcs = c.rpcs.map((rpc, peer) => ({ async call(m,p) { return mutate(m,p,await rpc.call(m,p),peer); } }));
    await assert.rejects(c.read()); assert.equal(c.f.state.broadcasts.length, 0);
});

test('state block changing after officer reads stops verification', async () => {
    const c = captured(); let changed = false;
    c.rpcs = c.rpcs.map(rpc => ({ async call(m,p) {
        const v = await rpc.call(m,p);
        if (m === 'eth_call' && p[0].data.length > 138) changed = true;
        if (changed && m === 'eth_getBlockByNumber' && p[0] === '0x1000') return { ...v, hash: '0x' + 'cc'.repeat(32) };
        return v;
    } }));
    // Trigger at the first completed chunk, without altering returned commitments.
    await assert.rejects(c.read(() => { changed = true; }), /state block changed/);
});

test('changed individual commitment cannot pass full readback', async () => {
    const c = captured(); c.f.state.records.set(c.f.plan.chunks[32].handles[0], '0x' + 'dd'.repeat(32));
    await assert.rejects(c.read(), /commitment readback differs/);
});
