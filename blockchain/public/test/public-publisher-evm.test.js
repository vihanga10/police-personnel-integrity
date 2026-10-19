'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const ganache = require('ganache'), { Wallet, ContractFactory, BrowserProvider, Contract, Interface } = require('ethers');
const { artifact } = require('../deployment-artifact'), { run } = require('../publication-engine');
const R = require('../sepolia-rpc'), { temp } = require('./sepolia-test-support');
const { fixture } = require('./fixture'), { plan } = require('../publication');
test('real compiled EVM accepts journaled create and 100 officer writes with exact readback', { timeout: 900000 }, async () => {
    const wallet = Wallet.createRandom(), a = artifact(wallet.address);
    const evm = ganache.provider({ chain: { chainId: 11155111, hardfork: 'shanghai' }, miner: { blockGasLimit: 30000000 },
        wallet: { accounts: [{ secretKey: wallet.privateKey, balance: '0x3635c9adc5dea00000' }] }, logging: { quiet: true } });
    const provider = new BrowserProvider(evm); provider.pollingInterval = 10;
    try {
        const contract = await new ContractFactory(a.abi, a.bytecode, await provider.getSigner()).deploy(wallet.address);
        const deployed = await contract.deploymentTransaction().wait(), address = await contract.getAddress();
        const rpc = { async call(method, params) {
            // Fixture-only Sepolia genesis/finality and bounded gas-estimate adapter.
            // Execution, receipts, runtime and 100 stored values come from the actual compiled EVM.
            if (method === 'eth_estimateGas' && params[0].data.startsWith(new Interface(a.abi).getFunction('appendOfficers').selector)) return R.hex(8000000n);
            if (method === 'eth_getBlockByNumber' && params[0] === '0x0') return { number: '0x0', hash: R.GENESIS };
            if (method === 'eth_getBlockByNumber' && params[0] === 'finalized') return evm.request({ method, params: ['latest', false] });
            return evm.request({ method, params });
        } };
        const config = R.configuration({ policy: 'SEPOLIA_DEPLOYMENT_NETWORK_V1', rpc_urls: ['https://one.example.invalid', 'https://two.example.invalid'],
            max_fee_gwei: '2', priority_fee_gwei: '1', max_total_fee_eth: '0.025', confirmations: 12 });
        const f = fixture(), p = plan(f.publicPayload, f.digest), directory = temp();
        const deployment = { status: 'PASSED', finalized: true, two_rpc_readback: true, chain_id: 11155111,
            contract_address: address, transaction_hash: deployed.hash, artifact: { runtime_sha256: a.runtime_sha256 } };
        const options = { wallet, artifact: a, rpcs: [rpc, rpc], config, directory, deployment,
            plan: p, digest: f.digest, publicationBudget: '0.02', guard: () => {} };
        await assert.rejects(run({ ...options, mode: 'EXECUTE', interrupt: (point, index) => {
            if (point === 'AFTER_READBACK' && index === 1) throw new Error('compiled fixture stop');
        } }), /compiled fixture stop/);
        const reader = new Contract(address, a.abi, provider), batch = await reader.readBatch(p.batch);
        assert.equal(batch[1], 100n); assert.equal(batch[2], false);
        for (let i = 0; i < 100; i++) assert.equal(await reader.readOfficer(p.batch, p.chunks[0].handles[i]), p.chunks[0].commitments[i]);
        const nonce = await rpc.call('eth_getTransactionCount', [wallet.address, 'latest']);
        await assert.rejects(run({ ...options, mode: 'VALIDATE', interrupt: (point, index) => {
            if (point === 'AFTER_READBACK' && index === 1) throw new Error('compiled fixture stop');
        } }), /compiled fixture stop/);
        assert.equal(await rpc.call('eth_getTransactionCount', [wallet.address, 'latest']), nonce);
    } finally { provider.destroy(); await evm.disconnect(); }
});
