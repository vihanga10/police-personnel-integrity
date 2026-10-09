'use strict';
const BATCH_LIMIT = 10;
const HTTP_TRANSIENT = new Set([408, 429, 500, 502, 503, 504]);

function batchReader({ url, fetchImpl, sleep, nextId, fail, isRead, classify }) {
    return async function batch(requests) {
        // Entire batches are idempotent reads; no notifications or writes allowed.
        if (!Array.isArray(requests) || requests.length < 1 || requests.length > BATCH_LIMIT ||
            !requests.every(r => r && Object.keys(r).sort().join(',') === 'method,params' &&
                typeof r.method === 'string' && isRead(r.method) && Array.isArray(r.params)))
            throw fail('INVALID_READ_BATCH', 'eth_call', [], 0);
        const captured = JSON.parse(JSON.stringify(requests));
        const representative = captured[0];
        const errorFor = (category, attempt, status = null, code = null, transient = false, entry = representative) =>
            fail(category, entry.method, entry.params, attempt, status, code, transient);
        for (let attempt = 1; attempt <= 3; attempt++) {
            const messages = captured.map(r => ({ jsonrpc: '2.0', id: nextId(), method: r.method, params: r.params }));
            const expected = new Map(messages.map((m, i) => [m.id, i]));
            let response, failure;
            try {
                response = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json' },
                    body: JSON.stringify(messages), signal: AbortSignal.timeout(20000) });
            } catch { failure = errorFor('TRANSPORT_UNAVAILABLE', attempt, null, null, true); }
            if (response) {
                if (!response.ok) {
                    const transient = HTTP_TRANSIENT.has(response.status);
                    failure = errorFor(transient ? 'TRANSIENT_HTTP_FAILURE' : 'HTTP_REJECTED',
                        attempt, response.status, null, transient);
                    try { await response.body?.cancel(); } catch {}
                } else {
                    let body;
                    try {
                        const text = await response.text();
                        if (text.length > 4 * 1024 * 1024) throw new Error('Batch size bound');
                        body = JSON.parse(text);
                    } catch { throw errorFor('MALFORMED_RPC_BATCH', attempt, response.status); }
                    // A valid batch can arrive out of order; it must still cover every
                    // requested ID exactly once, with no extra/missing/duplicate IDs.
                    // A provider may throttle the entire batch with one valid
                    // id:null error. Only numeric 429 enters bounded recovery.
                    if (!Array.isArray(body) && body?.jsonrpc === '2.0' && body.id === null &&
                        Object.hasOwn(body, 'error') && !Object.hasOwn(body, 'result') &&
                        body.error?.code === 429 && typeof body.error.message === 'string')
                        body = messages.map(m => ({ jsonrpc: '2.0', id: m.id, error: body.error }));
                    if (!Array.isArray(body))
                        throw errorFor('RPC_BATCH_REJECTED', attempt, response.status,
                            Number.isSafeInteger(body?.error?.code) ? body.error.code : null);
                    if (body.length !== messages.length)
                        throw errorFor('INCOMPLETE_RPC_BATCH', attempt, response.status);
                    const seen = new Set(), values = new Array(messages.length), errors = [];
                    for (const item of body) {
                        if (!item || item.jsonrpc !== '2.0' || !expected.has(item.id) || seen.has(item.id) ||
                            (Object.hasOwn(item, 'error') === Object.hasOwn(item, 'result')))
                            throw errorFor('MALFORMED_RPC_BATCH', attempt, response.status);
                        seen.add(item.id);
                        const index = expected.get(item.id);
                        if (Object.hasOwn(item, 'error')) {
                            const [category, transient] = classify(String(item.error?.message || ''), item.error?.code);
                            errors.push(errorFor(category, attempt, response.status, item.error?.code,
                                transient, captured[index]));
                        } else values[index] = item.result;
                    }
                    if (seen.size !== expected.size) throw errorFor('INCOMPLETE_RPC_BATCH', attempt, response.status);
                    // Any permanent error wins over transient errors elsewhere in the
                    // batch. No successful subset is returned or counted as coverage.
                    failure = errors.find(e => !e.diagnostic.read_retryable) || errors[0];
                    if (!failure) return values;
                }
            }
            if (!failure || !failure.diagnostic.read_retryable || attempt === 3) throw failure ||
                errorFor('MALFORMED_RPC_BATCH', attempt);
            await sleep(attempt === 1 ? 500 : 1500);
        }
    };
}
module.exports = { batchReader, BATCH_LIMIT };
