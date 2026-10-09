'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { endpoint, safeFailure } = require('../rpc-read-recovery');
const SECRET = 'private endpoint and personnel values';
const requests = () => [0, 1].map(n => ({ method: 'eth_call', params: [{ data: '0x' + n }, '0xb5436a'] }));
function fixture(mode, message = 'Too many requests', code = 429, exhausted = false) {
    const sent = [], waits = [];
    const rpc = endpoint('https://fixture.invalid', {
        sleep: async ms => waits.push(ms),
        fetchImpl: async (_, options) => {
            const input = JSON.parse(options.body); sent.push(input);
            const entries = Array.isArray(input) ? input : [input];
            const error = { code, message };
            const failed = exhausted || sent.length === 1;
            const replies = entries.map((m, i) => ({ jsonrpc: '2.0', id: m.id,
                ...(failed && (mode !== 'member' || i === 0) ? { error } : { result: '0x' + i }) }));
            const body = failed && mode === 'global' ? { jsonrpc: '2.0', id: null, error } :
                Array.isArray(input) ? replies.reverse() : replies[0];
            return { ok: true, status: 200, async text() { return JSON.stringify(body); } };
        }
    });
    return { rpc, sent, waits };
}
async function invoke(f, mode) {
    return mode === 'single' ? f.rpc.call('eth_call', requests()[0].params) : f.rpc.batch(requests());
}
for (const mode of ['single', 'member', 'global']) {
    test('numeric RPC 429 recovers exact original read: ' + mode, async () => {
        const f = fixture(mode, 'Unclassified provider text ' + SECRET);
        const result = await invoke(f, mode);
        assert.deepEqual(result, mode === 'single' ? '0x0' : ['0x0', '0x1']);
        assert.equal(f.sent.length, 2); assert.deepEqual(f.waits, [500]);
        const strip = input => (Array.isArray(input) ? input : [input]).map(({ method, params }) => ({ method, params }));
        assert.deepEqual(strip(f.sent[0]), strip(f.sent[1]));
    });
    test('persistent numeric RPC 429 stops after three attempts: ' + mode, async () => {
        const f = fixture(mode, SECRET, 429, true);
        await assert.rejects(invoke(f, mode), e => {
            const d = safeFailure(e);
            assert.equal(d.category, 'TRANSIENT_PROVIDER_FAILURE'); assert.equal(d.attempts, 3);
            assert.equal(d.rpc_error_code, 429); assert.equal(d.block_tag, '0xb5436a');
            assert.ok(!JSON.stringify(d).includes(SECRET)); return true;
        });
        assert.equal(f.sent.length, 3); assert.deepEqual(f.waits, [500, 1500]);
    });
    for (const [message, category] of [
        ['historical state unavailable', 'HISTORICAL_STATE_UNAVAILABLE'],
        ['monthly quota exhausted', 'PROVIDER_QUOTA_EXHAUSTED'],
        ['unauthorized', 'RPC_REJECTED']
    ]) test('permanent error wins over numeric 429: ' + mode + ' ' + category, async () => {
        const f = fixture(mode, message, 429, true);
        await assert.rejects(invoke(f, mode), e => safeFailure(e).category === category);
        assert.equal(f.sent.length, 1); assert.deepEqual(f.waits, []);
    });
}
test('numeric RPC 429 never repeats a signed broadcast', async () => {
    const f = fixture('single', 'Too many requests', 429, true);
    await assert.rejects(f.rpc.call('eth_sendRawTransaction', [SECRET]), e => !safeFailure(e).read_retryable);
    assert.equal(f.sent.length, 1); assert.deepEqual(f.waits, []);
});
test('string 429 is not accepted as a numeric provider throttle', async () => {
    const f = fixture('single', 'Too many requests', '429', true);
    await assert.rejects(invoke(f, 'single'), e => !safeFailure(e).read_retryable);
    assert.equal(f.sent.length, 1);
});
