'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { probe } = require('../check-rpc-pacing');
const R = require('../sepolia-rpc');
function fixtures(wrong = false) {
    const calls = [], hash = '0x' + 'ab'.repeat(32);
    const rpcs = [0, 1].map(peer => ({
        async call(method, params) {
            calls.push({ peer, method, params });
            if (method === 'eth_chainId') return '0xaa36a7';
            if (params[0] === '0x0') return { number: '0x0', hash: R.GENESIS };
            return { number: params[0] === 'finalized' || params[0] === 'latest' ? '0x1000' : params[0], hash,
                timestamp: '0x' + Math.floor(Date.now() / 1000).toString(16), gasLimit: '0x1000000' };
        },
        async batch(requests) {
            calls.push({ peer, requests });
            return requests.map(() => wrong && peer === 1 ? '0x00' :
                '0x' + '0'.repeat(24) + '88208cc4bf8118072c909a8fef25740126f66ae1');
        }
    })); return { rpcs, calls };
}
test('limited probe checks 50 fixed-block reads per provider and never submits', async () => {
    const f = fixtures(), reports = []; await probe(f.rpcs, r => reports.push(r));
    assert.equal(reports.length, 2); assert.ok(reports.every(r => r.read_calls === 50));
    const batches = f.calls.filter(c => c.requests);
    assert.equal(batches.length, 10); assert.ok(batches.flatMap(c => c.requests).every(r => r.params[1] === '0x1000'));
    assert.ok(f.calls.every(c => c.method !== 'eth_sendRawTransaction'));
});
test('probe cannot pass changed writer values', async () => {
    await assert.rejects(probe(fixtures(true).rpcs), /Probe writer differs/);
});
