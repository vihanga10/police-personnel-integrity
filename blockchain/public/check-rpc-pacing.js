'use strict';
const path = require('node:path');
const { id } = require('ethers');
const F = require('./deployment-files'), R = require('./sepolia-rpc');
const CONTRACT = '0x4Ae794040d9794cd3b50BB06Fd41eE540c2435a6';
const WRITER = '0x88208CC4Bf8118072C909A8Fef25740126f66AE1';
async function probe(rpcs, report = () => {}) {
    await R.network(rpcs);
    const heads = await Promise.all(rpcs.map(r => r.call('eth_getBlockByNumber', ['finalized', false])));
    const height = R.quantity(heads[0]?.number) < R.quantity(heads[1]?.number) ? heads[0].number : heads[1].number;
    const blocks = await Promise.all(rpcs.map(r => r.call('eth_getBlockByNumber', [height, false])));
    if (blocks.some(b => b.number !== height) || R.hash(blocks[0].hash) !== R.hash(blocks[1].hash))
        throw new Error('Finalized probe block differs');
    const expected = '0x' + '0'.repeat(24) + WRITER.slice(2).toLowerCase();
    await Promise.all(rpcs.map(async (rpc, peer) => {
        for (let n = 0; n < 5; n++) {
            const requests = Array.from({ length: 10 }, () => ({ method: 'eth_call',
                params: [{ to: CONTRACT, data: id('writer()').slice(0, 10) }, height] }));
            const values = await rpc.batch(requests);
            if (values.length !== 10 || values.some(v => typeof v !== 'string' || v.toLowerCase() !== expected))
                throw new Error('Probe writer differs');
        }
        report({ rpc: peer + 1, fixed_block: height, read_calls: 50, status: 'PASSED' });
    }));
    const after = await Promise.all(rpcs.map(r => r.call('eth_getBlockByNumber', [height, false])));
    if (after.some(b => b.number !== height || R.hash(b.hash) !== blocks[0].hash))
        throw new Error('Probe block changed');
}
async function main(argv) {
    if (argv.length !== 2 || argv[0] !== '--wallet-root') throw new Error('Wallet root required');
    // Read only private network configuration. No wallet keystore or unlock file.
    const config = R.configuration(F.read(path.join(argv[1], 'network.json')));
    config.urls.forEach((url, peer) => console.log(JSON.stringify({ rpc: peer + 1,
        service: new URL(url).hostname.endsWith('.alchemy.com') ? 'ALCHEMY' : 'OTHER_PROVIDER',
        account_limits: 'CHECK_PROVIDER_DASHBOARD_PRIVATELY' })));
    await probe(config.urls.map(R.endpoint), result => console.log(JSON.stringify(result)));
    console.log('Limited paced RPC probe: PASSED. Full evidence readiness remains unverified. No transactions submitted.');
}
if (require.main === module) main(process.argv.slice(2)).catch(error => {
    console.error('Limited paced RPC probe stopped:', JSON.stringify(R.safeFailure(error)));
    process.exitCode = 1;
});
module.exports = { probe, main };
