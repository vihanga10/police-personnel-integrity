'use strict';
const fs = require('node:fs'), path = require('node:path');
const { Interface, Transaction, getAddress, parseEther, formatEther } = require('ethers');
const F = require('./deployment-files'), R = require('./sepolia-rpc');
const POLICY = 'SEPOLIA_PUBLICATION_TRANSACTION_V1';
const MAX_GAS = 16777216n;
const check = (v, m) => { if (!v) throw new Error(m); };
const lower = v => typeof v === 'string' ? v.toLowerCase() : v;
function budget(value) {
    check(typeof value === 'string' && /^\d+(\.\d{1,9})?$/.test(value), 'Publication budget differs');
    const result = parseEther(value);
    check(result > 0n && result <= parseEther('5'), 'Publication budget outside test policy');
    return result;
}
function operations(p, abi) {
    const iface = new Interface(abi);
    const make = (index, name, args, event, eventArgs) => ({ index, name,
        data: iface.encodeFunctionData(name, args), event, eventArgs });
    return [make(0, 'createBatch', [p.batch, p.metadata, p.batch_proof], 'Created', [p.batch, p.metadata[0], p.metadata[1]]),
        ...p.chunks.map((ch, i) => make(i + 1, 'appendOfficers',
            [p.batch, ch.start, ch.handles, ch.commitments, ch.proofs], 'Appended', [p.batch, BigInt(ch.start), BigInt(ch.handles.length)])),
        make(67, 'sealBatch', [p.batch], 'Sealed', [p.batch, p.metadata[1]])];
}
function identity(a, config, deployment, p, digest) {
    return { policy: POLICY, chain_id: 11155111, genesis: R.GENESIS,
        contract: getAddress(deployment.contract_address), deployment_transaction: deployment.transaction_hash,
        writer: a.writer, runtime_sha256: a.runtime_sha256, config_sha256: config.sha256,
        batch: p.batch, public_payload_sha256: digest, merkle_root: p.metadata[1] };
}
function verifyPrepared(prepared, id, op, config, expectedNonce) {
    check(Object.keys(prepared).sort().join(',') === 'identity,index,raw_transaction,transaction_hash', 'Prepared shape differs');
    check(F.stable(prepared.identity) === F.stable(id) && prepared.index === op.index, 'Original transaction binding differs');
    const t = Transaction.from(prepared.raw_transaction);
    check(t.isSigned() && t.hash === prepared.transaction_hash && t.type === 2 && t.chainId === 11155111n &&
        getAddress(t.from) === id.writer && getAddress(t.to) === id.contract && t.value === 0n && t.data === op.data &&
        t.maxFeePerGas === config.maxFee && t.maxPriorityFeePerGas === config.tip && t.accessList?.length === 0 &&
        t.gasLimit > 0n && t.gasLimit <= MAX_GAS && (expectedNonce === null || t.nonce === expectedNonce), 'Original signed publication transaction differs');
    return t;
}
function normalizedReceipt(r) {
    return { hash: r.transactionHash, block_hash: r.blockHash, block: r.blockNumber,
        index: r.transactionIndex, status: r.status, from: lower(r.from), to: lower(r.to),
        gas: r.gasUsed, price: r.effectiveGasPrice, logs: Array.isArray(r.logs) ? r.logs.map(log => ({
            address: lower(log.address), topics: log.topics, data: log.data, transactionHash: log.transactionHash,
            transactionIndex: log.transactionIndex, logIndex: log.logIndex, blockHash: log.blockHash,
            blockNumber: log.blockNumber, removed: log.removed === true })) : r.logs };
}
async function observe(rpcs, prepared, id, op, config, tx, abi) {
    const receipts = await Promise.all(rpcs.map(r => r.call('eth_getTransactionReceipt', [tx.hash])));
    if (receipts.some(r => !r)) return { status: 'PENDING', reason: 'BOTH_ORIGINAL_RECEIPTS_REQUIRED' };
    check(F.stable(normalizedReceipt(receipts[0])) === F.stable(normalizedReceipt(receipts[1])), 'Original receipts disagree');
    const r = receipts[0], number = R.quantity(r.blockNumber), iface = new Interface(abi);
    R.hash(r.blockHash); R.quantity(r.transactionIndex);
    check(r.transactionHash === tx.hash && R.quantity(r.status) === 1n && lower(r.from) === lower(id.writer) &&
        lower(r.to) === lower(id.contract) && r.contractAddress === null && R.quantity(r.gasUsed) <= tx.gasLimit &&
        R.quantity(r.effectiveGasPrice) <= config.maxFee && Array.isArray(r.logs) && r.logs.length === 1, 'Original publication receipt invalid');
    const log = r.logs[0], expected = iface.encodeEventLog(iface.getEvent(op.event), op.eventArgs);
    R.quantity(log.logIndex);
    check(lower(log.address) === lower(id.contract) && log.transactionHash === tx.hash && log.blockHash === r.blockHash &&
        log.blockNumber === r.blockNumber && R.quantity(log.transactionIndex) === R.quantity(r.transactionIndex) &&
        log.removed !== true && log.data === expected.data &&
        F.stable(log.topics) === F.stable(expected.topics), 'Original publication event differs');
    const finalities = await Promise.all(rpcs.map(async rpc => {
        const [block, view, head, final] = await Promise.all([
            rpc.call('eth_getBlockByNumber', [r.blockNumber, false]), rpc.call('eth_getTransactionByHash', [tx.hash]),
            rpc.call('eth_getBlockByNumber', ['latest', false]), rpc.call('eth_getBlockByNumber', ['finalized', false])]);
        check(block && block.hash === r.blockHash && R.quantity(block.number) === number && block.transactions?.includes(tx.hash), 'Publication inclusion differs');
        check(view && view.hash === tx.hash && view.blockHash === r.blockHash && R.quantity(view.blockNumber) === number &&
            R.quantity(view.transactionIndex) === R.quantity(r.transactionIndex) && lower(view.from) === lower(id.writer) &&
            lower(view.to) === lower(id.contract) && view.input === tx.data && R.quantity(view.nonce) === BigInt(tx.nonce) &&
            R.quantity(view.chainId) === 11155111n && R.quantity(view.type) === 2n && R.quantity(view.value) === 0n &&
            R.quantity(view.gas) === tx.gasLimit && R.quantity(view.maxFeePerGas) === config.maxFee &&
            R.quantity(view.maxPriorityFeePerGas) === config.tip && Array.isArray(view.accessList) && view.accessList.length === 0,
            'Original publication transaction readback differs');
        const again = await rpc.call('eth_getBlockByNumber', [r.blockNumber, false]);
        check(again?.hash === r.blockHash, 'Publication reorg detected');
        return R.quantity(head.number) >= number + BigInt(config.confirmations) - 1n && final && R.quantity(final.number) >= number;
    }));
    return { status: 'MINED', receipt: normalizedReceipt(r), finalized: finalities.every(Boolean) };
}
async function runtimeCheck(rpcs, a, id, tag = 'latest') {
    const iface = new Interface(a.abi);
    for (const rpc of rpcs) {
        const [code, writer, chain, count] = await Promise.all([
            rpc.call('eth_getCode', [id.contract, tag]),
            rpc.call('eth_call', [{ to: id.contract, data: iface.encodeFunctionData('writer') }, tag]),
            rpc.call('eth_call', [{ to: id.contract, data: iface.encodeFunctionData('CHAIN_ID') }, tag]),
            rpc.call('eth_call', [{ to: id.contract, data: iface.encodeFunctionData('OFFICERS') }, tag])]);
        check(code === a.runtime && getAddress(iface.decodeFunctionResult('writer', writer)[0]) === id.writer &&
            iface.decodeFunctionResult('CHAIN_ID', chain)[0] === 11155111n &&
            iface.decodeFunctionResult('OFFICERS', count)[0] === 6596n, 'Publication runtime or writer differs');
    }
}
async function checkState(rpcs, p, a, id, completed, tag = 'latest') {
    if (!completed) return; // Absence is checked by createBatch estimation; an external existing batch cannot produce the required Created event.
    const iface = new Interface(a.abi), expectedCount = completed === 68 ? 6596 : Math.min((completed - 1) * 100, 6596);
    for (const rpc of rpcs) {
        const value = await rpc.call('eth_call', [{ to: id.contract, data: iface.encodeFunctionData('readBatch', [p.batch]) }, tag]);
        const state = iface.decodeFunctionResult('readBatch', value);
        check(F.stable(Array.from(state[0])) === F.stable(p.metadata) && state[1] === BigInt(expectedCount) &&
            state[2] === (completed === 68), 'Public batch metadata, count or seal differs');
    }
}
async function readAll(rpcs, p, a, id, sealReceipt, progress = () => {}) {
    const tag = sealReceipt.block, iface = new Interface(a.abi);
    await runtimeCheck(rpcs, a, id, tag); await checkState(rpcs, p, a, id, 68, tag);
    // Bound concurrency to four calls. Read every value at the exact sealed inclusion block.
    for (const ch of p.chunks) {
        for (let offset = 0; offset < ch.handles.length; offset += 2) {
            await Promise.all(ch.handles.slice(offset, offset + 2).flatMap((handle, j) => rpcs.map(async rpc => {
                const bytes = await rpc.call('eth_call', [{ to: id.contract, data: iface.encodeFunctionData('readOfficer', [p.batch, handle]) }, tag]);
                check(iface.decodeFunctionResult('readOfficer', bytes)[0] === ch.commitments[offset + j], 'Original officer commitment readback differs');
            })));
        }
        progress(ch.start + ch.handles.length);
    }
    for (const rpc of rpcs) {
        const block = await rpc.call('eth_getBlockByNumber', [tag, false]);
        check(block?.hash === sealReceipt.block_hash, 'Sealed readback block reorg detected');
    }
}
async function quote(rpcs, a, id, op, config) {
    const heads = await R.network(rpcs);
    const views = await Promise.all(rpcs.map(async (rpc, i) => {
        const [estimate, balance, latest, pending] = await Promise.all([
            rpc.call('eth_estimateGas', [{ from: id.writer, to: id.contract, data: op.data, value: '0x0',
                maxFeePerGas: R.hex(config.maxFee), maxPriorityFeePerGas: R.hex(config.tip) }]),
            rpc.call('eth_getBalance', [id.writer, 'latest']), rpc.call('eth_getTransactionCount', [id.writer, 'latest']),
            rpc.call('eth_getTransactionCount', [id.writer, 'pending'])]);
        check(R.quantity(heads[i].baseFeePerGas) + config.tip <= config.maxFee, 'Publication fee cap too low');
        return { estimate: R.quantity(estimate), balance: R.quantity(balance), latest: R.quantity(latest),
            pending: R.quantity(pending), blockCap: R.quantity(heads[i].gasLimit) };
    }));
    check(views[0].latest === views[1].latest && views.every(v => v.latest === v.pending) &&
        views[0].latest <= BigInt(Number.MAX_SAFE_INTEGER), 'Publication nonce not idle');
    const estimate = views.reduce((n, v) => v.estimate > n ? v.estimate : n, 0n);
    const cap = views.reduce((n, v) => v.blockCap < n ? v.blockCap : n, MAX_GAS);
    const preferred = (estimate * 120n + 99n) / 100n;
    // Preserve at least 5% headroom; never exceed either block cap or EIP-7825.
    const minimum = (estimate * 105n + 99n) / 100n;
    check(estimate > 0n && minimum <= cap, 'Publication operation exceeds gas cap');
    const gas = preferred <= cap ? preferred : cap;
    return { gas, estimate, gasCap: cap, cost: gas * config.maxFee, nonce: Number(views[0].latest),
        funded: views.every(v => v.balance >= gas * config.maxFee), minBalance: views.reduce((n, v) => v.balance < n ? v.balance : n, views[0].balance) };
}
// Bounded read-only polling never signs, broadcasts or suppresses verification errors.
async function pollUntil(read, initial, ready, { waitMs = 0, intervalMs = 3000, now = Date.now,
    sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) } = {}) {
    check(Number.isInteger(waitMs) && waitMs >= 0 && waitMs <= 60000 &&
        Number.isInteger(intervalMs) && intervalMs >= 1000 && intervalMs <= 5000, 'Polling bounds differ');
    let value = initial;
    const end = now() + waitMs, rounds = Math.ceil(waitMs / intervalMs);
    for (let n = 0; n < rounds && !ready(value); n++) {
        const left = end - now();
        if (left <= 0) break;
        await sleep(Math.min(intervalMs, left));
        if (now() >= end) break;
        value = await read();
    }
    return value;
}
async function run({ mode, wallet, rpcs, config, artifact: a, deployment, plan: p, digest, directory,
    publicationBudget, guard = () => { throw new Error('Fresh authorization required'); }, interrupt = () => {}, progress = () => {}, readProgress = () => {},
    receiptWaitMs = 0, finalityWaitMs = 0, pollIntervalMs = 3000, pollingSleep, pollingNow, waitProgress = () => {} }) {
    check(['VALIDATE', 'EXECUTE', 'RECONCILE'].includes(mode), 'Publication mode differs');
    const limit = budget(publicationBudget), id = identity(a, config, deployment, p, digest), ops = operations(p, a.abi);
    check(wallet.address === id.writer && deployment.status === 'PASSED' && deployment.finalized === true &&
        deployment.two_rpc_readback === true && deployment.chain_id === 11155111 && deployment.artifact.runtime_sha256 === a.runtime_sha256,
        'Verified deployment required');
    const completionFile = path.join(directory, 'PASSED.json');
    const observations = []; let reserved = 0n, priorNonce = null, submitted = 0;
    const pending = reason => ({ status: 'PENDING', reason, completed_operations: observations.length,
        original_transactions_prepared: observations.length + (fs.existsSync(path.join(directory, `${observations.length.toString().padStart(2, '0')}-PREPARED.json`)) ? 1 : 0),
        submitted_transactions_this_run: submitted, research_publication_complete: false });
    const polling = waitMs => ({ waitMs, intervalMs: pollIntervalMs,
        ...(pollingSleep ? { sleep: pollingSleep } : {}), ...(pollingNow ? { now: pollingNow } : {}) });
    // Validate both wait policies even when the chain is immediately available.
    await pollUntil(async () => null, null, () => true, polling(receiptWaitMs));
    await pollUntil(async () => null, null, () => true, polling(finalityWaitMs));
    try {
    guard(); await R.network(rpcs); await runtimeCheck(rpcs, a, id);
    for (const op of ops) {
        let newlyPrepared = false;
        const file = path.join(directory, `${op.index.toString().padStart(2, '0')}-PREPARED.json`);
        if (!fs.existsSync(file)) {
            if (mode === 'RECONCILE') return pending('ORIGINAL_TRANSACTION_NOT_PREPARED');
            guard(); await checkState(rpcs, p, a, id, observations.length);
            const q = await quote(rpcs, a, id, op, config);
            check(priorNonce === null || q.nonce === priorNonce + 1, 'Unrelated wallet transaction detected');
            const report = { status: q.funded && reserved + q.cost <= limit ? 'READY' : 'FUNDING_OR_BUDGET_REQUIRED', mode,
                next_operation: op.index, next_method: op.name, estimated_gas_limit: q.gas.toString(),
                raw_gas_estimate: q.estimate.toString(), gas_headroom: (q.gas - q.estimate).toString(), effective_gas_cap: q.gasCap.toString(),
                maximum_next_fee_test_eth: formatEther(q.cost), reserved_publication_fees_test_eth: formatEther(reserved),
                publication_fee_budget_test_eth: formatEther(limit), wallet_balance_test_eth: formatEther(q.minBalance),
                remaining_operations: 68 - op.index, remaining_maximum_policy_exposure_test_eth: formatEther(BigInt(68 - op.index) * MAX_GAS * config.maxFee),
                submitted_transactions_this_run: submitted, research_publication_complete: false };
            if (mode === 'VALIDATE' || !q.funded || reserved + q.cost > limit) return report;
            guard();
            const raw = await wallet.signTransaction({ type: 2, chainId: 11155111, to: id.contract, nonce: q.nonce,
                data: op.data, value: 0n, gasLimit: q.gas, maxFeePerGas: config.maxFee, maxPriorityFeePerGas: config.tip, accessList: [] });
            F.write(file, { identity: id, index: op.index, raw_transaction: raw, transaction_hash: Transaction.from(raw).hash });
            newlyPrepared = true;
            await interrupt('AFTER_PREPARE', op.index);
        }
        const prepared = F.read(file), tx = verifyPrepared(prepared, id, op, config, priorNonce === null ? null : priorNonce + 1);
        reserved += tx.gasLimit * config.maxFee;
        check(reserved <= limit, 'Previously prepared fees exceed publication budget');
        let observation = await observe(rpcs, prepared, id, op, config, tx, a.abi);
        const waitReceipt = async initial => {
            if (initial.status !== 'PENDING' || !receiptWaitMs || mode !== 'EXECUTE') return initial;
            waitProgress('RECEIPTS', op.index);
            return pollUntil(() => observe(rpcs, prepared, id, op, config, tx, a.abi), initial,
                v => v.status !== 'PENDING', polling(receiptWaitMs));
        };
        if (!newlyPrepared) observation = await waitReceipt(observation);
        if (observation.status === 'PENDING' && mode === 'EXECUTE') {
            guard(); await R.network(rpcs);
            const nonceViews = await Promise.all(rpcs.map(async rpc => {
                const [latest, pendingNonce, known] = await Promise.all([rpc.call('eth_getTransactionCount', [id.writer, 'latest']),
                    rpc.call('eth_getTransactionCount', [id.writer, 'pending']), rpc.call('eth_getTransactionByHash', [tx.hash])]);
                return { latest: R.quantity(latest), pending: R.quantity(pendingNonce), known };
            }));
            // If one provider already sees mining, wait for the other; never compete with a consumed nonce.
            if (nonceViews.some(v => v.latest > BigInt(tx.nonce))) return pending('ORIGINAL_RECEIPTS_CATCHING_UP');
            check(nonceViews.every(v => v.latest === BigInt(tx.nonce) && v.pending <= BigInt(tx.nonce) + 1n &&
                (v.pending === BigInt(tx.nonce) || v.known?.hash === tx.hash)), 'Unrelated pending publication nonce');
            // Both receipts must be absent before retrying a broadcast.
            const receipts = await Promise.all(rpcs.map(r => r.call('eth_getTransactionReceipt', [tx.hash])));
            if (receipts.some(Boolean)) return pending('ORIGINAL_RECEIPTS_CATCHING_UP');
            guard(); let acknowledged = false;
            for (const rpc of rpcs) {
                try { guard(); submitted++; const hash = await rpc.call('eth_sendRawTransaction', [prepared.raw_transaction]);
                    check(hash === tx.hash, 'Publication broadcast hash differs'); acknowledged = true; break;
                } catch (error) { if (['Publication broadcast hash differs', 'Fresh live gate required'].includes(error.message)) throw error; }
            }
            await interrupt('AFTER_BROADCAST', op.index);
            observation = await waitReceipt(await observe(rpcs, prepared, id, op, config, tx, a.abi));
            if (!acknowledged && observation.status === 'PENDING') return pending('AMBIGUOUS_ORIGINAL_BROADCAST');
        }
        if (observation.status === 'PENDING') return pending(observation.reason);
        const minedFile = path.join(directory, `${op.index.toString().padStart(2, '0')}-MINED.json`);
        const mined = { identity: id, index: op.index, transaction_hash: tx.hash, receipt: observation.receipt };
        if (fs.existsSync(minedFile)) check(F.stable(F.read(minedFile)) === F.stable(mined), 'Saved mined receipt differs');
        else if (mode !== 'VALIDATE') { F.write(minedFile, mined); await interrupt('AFTER_RECEIPT', op.index); }
        observations.push({ tx: tx.hash, ...observation }); priorNonce = tx.nonce;
        await interrupt('AFTER_READBACK', op.index); progress(observations.length);
    }
    if (observations.some(o => !o.finalized) && finalityWaitMs && mode !== 'VALIDATE') {
        waitProgress('FINALITY', 67);
        const refreshed = await pollUntil(async () => {
            const next = [];
            for (const op of ops) {
                const prepared = F.read(path.join(directory, `${op.index.toString().padStart(2, '0')}-PREPARED.json`));
                const tx = verifyPrepared(prepared, id, op, config, null);
                const value = await observe(rpcs, prepared, id, op, config, tx, a.abi);
                check(value.status === 'MINED' && F.stable(value.receipt) === F.stable(observations[op.index].receipt), 'Final publication inclusion changed');
                next.push({ tx: tx.hash, ...value });
            }
            return next;
        }, observations, values => values.every(v => v.finalized), polling(finalityWaitMs));
        observations.splice(0, observations.length, ...refreshed);
    }
    if (observations.some(o => !o.finalized)) return pending('ALL_ORIGINAL_TRANSACTIONS_REQUIRE_FINALITY');
    const seal = observations.at(-1).receipt;
    await readAll(rpcs, p, a, id, seal, readProgress);
    // Recheck every original receipt/inclusion after the bounded full-record readback.
    for (const op of ops) {
        const prepared = F.read(path.join(directory, `${op.index.toString().padStart(2, '0')}-PREPARED.json`));
        const tx = verifyPrepared(prepared, id, op, config, null);
        const again = await observe(rpcs, prepared, id, op, config, tx, a.abi);
        check(again.status === 'MINED' && again.finalized && F.stable(again.receipt) === F.stable(observations[op.index].receipt), 'Final publication inclusion changed');
    }
    // The gate is required at entry and before every signing/broadcast. Final readback is
    // against an immutable, finalized sealed block and may legitimately take over ten minutes.
    const result = { policy: 'SEPOLIA_RESEARCH_PUBLICATION_V1', status: 'PASSED', identity: id, officers: 6596,
        original_valid_transactions: 68, two_rpc_readback: true, finalized: true, sealed_block: seal.block,
        sealed_block_hash: seal.block_hash, transaction_hashes: observations.map(o => o.tx), classification: 'UNASSESSED' };
    if (fs.existsSync(completionFile)) check(F.stable(F.read(completionFile)) === F.stable(result), 'Saved publication completion differs');
    else if (mode !== 'VALIDATE') F.write(completionFile, result);
    return { ...result, mode, submitted_transactions_this_run: submitted, research_publication_complete: true };
    } catch (error) {
        if (error.message === 'Fresh live gate required') return pending('FRESH_AUTHORIZATION_REQUIRED');
        throw error;
    }
}
module.exports = { run, operations, verifyPrepared, observe, quote, budget, readAll, identity, pollUntil };
