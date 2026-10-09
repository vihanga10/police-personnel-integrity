'use strict';
// Only idempotent reads may retry. Signed transaction broadcasts stay single-attempt.
const READS = new Set(['eth_chainId', 'eth_getBlockByNumber', 'eth_blockNumber',
    'eth_getBalance', 'eth_getTransactionCount', 'eth_getTransactionReceipt',
    'eth_getTransactionByHash', 'eth_getCode', 'eth_call', 'eth_estimateGas',
    'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_feeHistory']);
const METHODS = new Set([...READS, 'eth_sendRawTransaction']);
const HTTP_TRANSIENT = new Set([408, 429, 500, 502, 503, 504]);
const CHECKS = new Map([
    ['Original officer commitment readback differs', 'OFFICER_COMMITMENT_MISMATCH'],
    ['Finalized publication state blocks disagree', 'FINALIZED_BLOCK_DISAGREEMENT'],
    ['Finalized publication state block changed', 'FINALIZED_BLOCK_CHANGED'],
    ['Original sealed inclusion block changed', 'ORIGINAL_SEAL_BLOCK_CHANGED'],
    ['Publication finality regressed', 'FINALITY_REGRESSED'],
    ['Deployed contract runtime differs', 'CONTRACT_RUNTIME_MISMATCH'],
    ['Publication runtime or writer differs', 'CONTRACT_RUNTIME_OR_WRITER_MISMATCH'],
    ['Public batch metadata, count or seal differs', 'BATCH_STATE_MISMATCH'],
    ['Finalized publication head unavailable', 'FINALIZED_HEAD_UNAVAILABLE'],
    ['Finalized publication head precedes seal', 'FINALIZED_HEAD_BEFORE_SEAL'],
    ['Finalized publication state block malformed', 'FINALIZED_STATE_BLOCK_MALFORMED'],
    ['Original receipts disagree', 'ORIGINAL_RECEIPT_DISAGREEMENT'],
    ['Publication reorg detected', 'REORG_DETECTED'],
    ['Sepolia identity differs', 'SEPOLIA_IDENTITY_MISMATCH'],
    ['RPC head stale', 'RPC_HEAD_STALE'],
    ['Fresh live gate required', 'EVIDENCE_AUTHORIZATION_EXPIRED'],
    ['Final publication inclusion changed', 'ORIGINAL_RECEIPT_CHANGED']
]);

class RpcFailure extends Error {
    constructor(category, method, params, attempt, status = null, code = null, transient = false, provider = null) {
        super('RPC diagnostic: ' + category);
        this.name = 'RpcFailure';
        const tag = method === 'eth_getBlockByNumber' ? params[0] :
            ['eth_call', 'eth_getCode', 'eth_getBalance', 'eth_getTransactionCount'].includes(method) ? params[1] : null;
        this.diagnostic = Object.freeze({ policy: 'SAFE_RPC_READ_RECOVERY_V1', category,
            rpc: provider, method: METHODS.has(method) ? method : 'UNLISTED_METHOD',
            block_tag: typeof tag === 'string' && /^(latest|finalized|pending|safe|earliest|0x[0-9a-f]+)$/.test(tag) ? tag : null,
            attempts: attempt, http_status: status,
            rpc_error_code: Number.isSafeInteger(code) ? code : null,
            read_retryable: READS.has(method) && transient });
    }
}

function safeFailure(error) {
    if (error instanceof RpcFailure) return error.diagnostic;
    return { policy: 'SAFE_RPC_READ_RECOVERY_V1', category: 'VERIFICATION_OR_LOCAL_FAILURE',
        check_code: CHECKS.get(error?.message) || 'UNCLASSIFIED_SAFE_FAILURE' };
}

function classify(message, code) {
    // Historical-state loss, reverts and invalid requests are not transient retries.
    if (/historical|prun|missing trie|state unavailable|archive|state is not available|no state available/i.test(message))
        return ['HISTORICAL_STATE_UNAVAILABLE', false];
    if (/revert|invalid (argument|param|request)|unauthorized|forbidden|method not found/i.test(message))
        return ['RPC_REJECTED', false];
    if (/daily|monthly|billing|credits exhausted|quota exhausted/i.test(message))
        return ['PROVIDER_QUOTA_EXHAUSTED', false];
    if ([-32005, -32016, -32000, -32603].includes(code) &&
        /rate.?limit|too many requests|requests per|temporarily unavailable|server busy|overload|try again/i.test(message))
        return ['TRANSIENT_PROVIDER_FAILURE', true];
    return ['RPC_REJECTED', false];
}

function endpoint(url, options = {}) {
    // Array.map passes the provider index; test dependencies are explicit objects.
    const provider = Number.isInteger(options) && options >= 0 && options < 2 ? options + 1 : null;
    const { fetchImpl = globalThis.fetch, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) } =
        typeof options === 'object' && options !== null ? options : {};
    const fail = (...args) => { while (args.length < 7) args.push(undefined); return new RpcFailure(...args, provider); };
    let id = 0;
    return { async call(method, params) {
        // Capture exact parameters once; retries cannot select a different state block.
        const captured = JSON.parse(JSON.stringify(params));
        const limit = READS.has(method) ? 3 : 1;
        for (let attempt = 1; attempt <= limit; attempt++) {
            let failure;
            const requestId = ++id;
            let response;
            try {
                response = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json' },
                    body: JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params: captured }),
                    signal: AbortSignal.timeout(20000) });
            } catch {
                failure = fail('TRANSPORT_UNAVAILABLE', method, captured, attempt, null, null, true);
            }
            if (response) {
                if (!response.ok) {
                    const transient = HTTP_TRANSIENT.has(response.status);
                    failure = fail(transient ? 'TRANSIENT_HTTP_FAILURE' : 'HTTP_REJECTED',
                        method, captured, attempt, response.status, null, transient);
                    // Release failed response bodies; never retain or print provider text.
                    try { await response.body?.cancel(); } catch {}
                } else {
                    let body;
                    try {
                        const text = await response.text();
                        if (text.length > 4 * 1024 * 1024) throw new Error('Size bound');
                        body = JSON.parse(text);
                    } catch {
                        throw fail('MALFORMED_RPC_RESPONSE', method, captured, attempt, response.status);
                    }
                    if (!body || body.jsonrpc !== '2.0' || body.id !== requestId ||
                        (Object.hasOwn(body, 'error') === Object.hasOwn(body, 'result')))
                        throw fail('MALFORMED_RPC_RESPONSE', method, captured, attempt, response.status);
                    if (Object.hasOwn(body, 'error')) {
                        const [category, transient] = classify(String(body.error?.message || ''), body.error?.code);
                        failure = fail(category, method, captured, attempt, response.status,
                            body.error?.code, transient);
                    } else return body.result;
                }
            }
            if (!failure.diagnostic.read_retryable || attempt === limit) throw failure;
            await sleep(attempt === 1 ? 500 : 1500);
        }
    } };
}
module.exports = { endpoint, safeFailure, RpcFailure };
