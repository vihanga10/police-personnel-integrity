'use strict';
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { Wallet, Transaction, Interface } = require('ethers');
const F = require('../deployment-files'), R = require('../sepolia-rpc');
const { artifact } = require('../deployment-artifact'), { fixture } = require('./fixture'), { plan } = require('../publication');
const wallet = Wallet.createRandom(), a = artifact(wallet.address), iface = new Interface(a.abi);
const selectors = Object.fromEntries(['writer','CHAIN_ID','OFFICERS','readBatch','readOfficer'].map(n => [n, iface.getFunction(n).selector]));
function fake() {
    const f = fixture(), p = plan(f.publicPayload, f.digest);
    const directory = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'public-publisher-'));
    fs.chmodSync(directory, 0o700);
    const config = R.configuration({ policy: 'SEPOLIA_DEPLOYMENT_NETWORK_V1', rpc_urls: ['https://one.example.invalid', 'https://two.example.invalid'],
        max_fee_gwei: '2', priority_fee_gwei: '1', max_total_fee_eth: '0.025', confirmations: 12 });
    const address = '0x' + '45'.repeat(20), deployment = { status: 'PASSED', finalized: true, two_rpc_readback: true,
        chain_id: 11155111, contract_address: address, transaction_hash: '0x' + 'ab'.repeat(32), artifact: { runtime_sha256: a.runtime_sha256 } };
    const state = { txs: new Map(), records: new Map(), count: 0, sealed: false, created: false,
        broadcasts: [], receipts: true, finality: true, tamper: null, failBroadcast: false, nonce: 1, balance: 10n ** 18n };
    function rpc(peer) { return { async call(m, params) {
        let v; const known = state.txs.get(params[0]);
        switch (m) {
        case 'eth_chainId': v = '0xaa36a7'; break;
        case 'eth_getBlockByNumber':
            if (params[0] === '0x0') v = { number: '0x0', hash: R.GENESIS };
            else if (params[0] === 'latest') v = { number: '0x1000', timestamp: R.hex(Math.floor(Date.now() / 1000)), hash: '0x' + 'ff'.repeat(32), gasLimit: R.hex(30000000n), baseFeePerGas: R.hex(10n) };
            else if (params[0] === 'finalized') v = { number: state.finality ? '0x1000' : '0x1' };
            else { const t = [...state.txs.values()].find(t => t.block.number === params[0]); v = t ? t.block : null; }
            break;
        case 'eth_getCode': v = a.runtime; break;
        case 'eth_getBalance': v = R.hex(state.balance); break;
        case 'eth_getTransactionCount': v = R.hex(state.nonce); break;
        case 'eth_estimateGas': v = R.hex(2000000n); break;
        case 'eth_getTransactionReceipt': v = known && state.receipts ? known.receipt : null; break;
        case 'eth_getTransactionByHash': v = known ? known.view : null; break;
        case 'eth_sendRawTransaction': {
            const tx = Transaction.from(params[0]); state.broadcasts.push(params[0]);
            if (!state.txs.has(tx.hash)) {
                const parsed = iface.parseTransaction({ data: tx.data }), args = parsed.args;
                let event, values;
                if (parsed.name === 'createBatch') { state.created = true; event = 'Created'; values = [p.batch, p.metadata[0], p.metadata[1]]; }
                else if (parsed.name === 'appendOfficers') { for (let i = 0; i < args[2].length; i++) state.records.set(args[2][i], args[3][i]); state.count += args[2].length; event = 'Appended'; values = [p.batch, args[1], BigInt(args[2].length)]; }
                else { state.sealed = true; event = 'Sealed'; values = [p.batch, p.metadata[1]]; }
                const number = R.hex(100 + state.txs.size), blockHash = '0x' + F.digest('block-' + number), log = iface.encodeEventLog(iface.getEvent(event), values);
                const receipt = { transactionHash: tx.hash, blockHash, blockNumber: number, transactionIndex: '0x0', from: wallet.address, to: address,
                    contractAddress: null, status: '0x1', gasUsed: R.hex(2000000n), effectiveGasPrice: R.hex(1000000010n),
                    logs: [{ ...log, address, transactionHash: tx.hash, blockHash, blockNumber: number, transactionIndex: '0x0', logIndex: '0x0', removed: false }] };
                const view = { hash: tx.hash, blockHash, blockNumber: number, transactionIndex: '0x0', from: wallet.address, to: address,
                    input: tx.data, nonce: R.hex(tx.nonce), chainId: R.hex(tx.chainId), type: '0x2', value: '0x0', gas: R.hex(tx.gasLimit),
                    maxFeePerGas: R.hex(tx.maxFeePerGas), maxPriorityFeePerGas: R.hex(tx.maxPriorityFeePerGas), accessList: [] };
                state.txs.set(tx.hash, { receipt, view, block: { number, hash: blockHash, transactions: [tx.hash] } }); state.nonce = tx.nonce + 1;
            }
            if (state.failBroadcast) throw new Error('Ambiguous fixture response'); v = tx.hash; break;
        }
        case 'eth_call': {
            const name = Object.keys(selectors).find(n => params[0].data.startsWith(selectors[n]));
            if (name === 'writer') v = iface.encodeFunctionResult(name, [wallet.address]);
            else if (name === 'CHAIN_ID') v = iface.encodeFunctionResult(name, [11155111n]);
            else if (name === 'OFFICERS') v = iface.encodeFunctionResult(name, [6596n]);
            else if (name === 'readBatch') { if (!state.created) throw new Error('absent fixture'); v = iface.encodeFunctionResult(name, [p.metadata, state.count, state.sealed]); }
            else if (name === 'readOfficer') v = state.records.get('0x' + params[0].data.slice(-64));
            else throw new Error('Unexpected fixture call');
            break;
        }
        default: throw new Error('Unexpected fixture method');
        }
        return state.tamper ? state.tamper(m, params, v, peer) : v;
    } }; }
    return { wallet, artifact: a, deployment, config, plan: p, digest: f.digest, directory, publicationBudget: '1',
        rpcs: [rpc(0), rpc(1)], state, guard: () => {} };
}
module.exports = { fake };
