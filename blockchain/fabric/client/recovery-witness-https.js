'use strict';
// No automatic enrollment, redirect, retry, proxy or deployment.
const https = require('node:https');
const tls = require('node:tls');
const crypto = require('node:crypto');
const {canonical} = require('../findings-chaincode/lib/findings');
const transports = new WeakSet();
const POLICY = 'FINDINGS_RECOVERY_WITNESS_MTLS_V1';
const LIMIT = 32768;
const ROUTE = '/v1/recovery/checkpoint';
const check = (v, m) => { if (!v) throw new Error(m); };
function exact(value, keys) {
    check(value && Object.getPrototypeOf(value) === Object.prototype &&
        Reflect.ownKeys(value).length === keys.length && keys.every(k =>
        Object.hasOwn(Object.getOwnPropertyDescriptor(value, k) || {}, 'value')), 'Exact HTTPS configuration required');
}
function digest(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function certificate(value) { return new crypto.X509Certificate(value); }
function pin(value) { check(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value), 'TLS certificate SHA-256 pin required'); }
function timeout(value) { check(Number.isSafeInteger(value) && value >= 100 && value <= 30000, 'Bounded HTTPS timeout required'); }
function material(cert, key) {
    const c = certificate(cert), k = crypto.createPrivateKey(key);
    check(c.checkPrivateKey(k), 'TLS certificate/private key mismatch');
    check(Date.parse(c.validFrom) <= Date.now() && Date.now() < Date.parse(c.validTo), 'Current TLS certificate required');
    // Preserve supplied intermediates while pinning/validating the leaf.
    return {cert: Buffer.from(cert).toString('utf8'), key: k.export({type:'pkcs8', format:'pem'})};
}
function encode(value) {
    const bytes = Buffer.from(canonical(value));
    check(bytes.length > 0 && bytes.length <= LIMIT, 'Bounded witness message required');
    return bytes;
}
function decode(bytes) {
    check(bytes.length > 0 && bytes.length <= LIMIT, 'Bounded witness message required');
    const text = bytes.toString('utf8');
    check(Buffer.from(text).equals(bytes), 'Witness UTF-8 differs');
    const value = JSON.parse(text);
    check(canonical(value) === text, 'Canonical witness message required');
    return value;
}
function media(headers) {
    check(headers['content-type'] === 'application/json' && !headers['content-encoding'] && !headers['transfer-encoding'], 'Witness HTTP encoding differs');
    const length = headers['content-length'];
    check(typeof length === 'string' && /^[1-9][0-9]{0,4}$/.test(length) && Number(length) <= LIMIT, 'Bounded Content-Length required');
    return Number(length);
}
function createHttpsTransport(options) {
    exact(options, ['endpoint','ca','cert','key','server_certificate_sha256','timeout_ms']);
    pin(options.server_certificate_sha256); timeout(options.timeout_ms);
    const endpoint = new URL(options.endpoint);
    check(endpoint.protocol === 'https:' && !endpoint.username && !endpoint.password && !endpoint.search && !endpoint.hash && endpoint.pathname === ROUTE && endpoint.href === options.endpoint, 'Exact HTTPS checkpoint endpoint required');
    const keys = material(options.cert, options.key), ca = Buffer.from(options.ca);
    // Parse at least one CA now; TLS independently validates the actual chain.
    certificate(ca);
    const expected = options.server_certificate_sha256, deadline = options.timeout_ms;
    const target = endpoint.href;
    const transport = Object.freeze({secure_transport:true, policy:POLICY, endpoint:target,
        async call(envelope) {
            const body = encode(envelope);
            return new Promise((resolve, reject) => {
                let timer, done = false;
                const finish = (error, value) => {
                    if (done) return;
                    done = true; clearTimeout(timer);
                    if (error) { request.destroy(); reject(error); } else resolve(value);
                };
                const request = https.request(target, {
                    method:'POST', agent:false, ...keys, ca,
                    minVersion:'TLSv1.3', maxVersion:'TLSv1.3', rejectUnauthorized:true,
                    checkServerIdentity(host, peer) {
                        return tls.checkServerIdentity(host, peer) ||
                            (digest(peer.raw) !== expected ? new Error('Witness TLS certificate pin differs') : undefined);
                    },
                    headers:{'content-type':'application/json','content-length':body.length,'connection':'close'}
                }, response => {
                    try {
                        check(response.statusCode === 200, 'Witness HTTP request refused; update may be uncertain');
                        const expectedLength = media(response.headers); let size = 0; const chunks = [];
                        response.on('data', chunk => {
                            size += chunk.length;
                            if (size > expectedLength || size > LIMIT) finish(new Error('Witness response too large'));
                            else chunks.push(chunk);
                        });
                        response.on('end', () => {
                            try { check(size === expectedLength, 'Witness response truncated'); finish(null, decode(Buffer.concat(chunks))); }
                            catch (error) { finish(error); }
                        });
                        response.on('error', finish);
                        response.on('aborted', () => finish(new Error('Witness response interrupted; update may be uncertain')));
                    } catch (error) { response.destroy(); finish(error); }
                });
                request.on('error', finish);
                timer = setTimeout(() => finish(new Error('Witness HTTPS deadline; update may be uncertain')), deadline);
                request.end(body);
            });
        }
    });
    transports.add(transport); return transport;
}
function createHttpsServer(options) {
    exact(options, ['ca','cert','key','client_certificate_sha256','timeout_ms','service']);
    pin(options.client_certificate_sha256); timeout(options.timeout_ms);
    check(options.service?.policy === POLICY && typeof options.service.transport?.call === 'function', 'Secure witness service required');
    const keys = material(options.cert, options.key), ca = Buffer.from(options.ca); certificate(ca);
    const expected = options.client_certificate_sha256, deadline = options.timeout_ms;
    const call = options.service.transport.call.bind(options.service.transport);
    const server = https.createServer({...keys,ca,requestCert:true,rejectUnauthorized:true,
        minVersion:'TLSv1.3',maxVersion:'TLSv1.3',handshakeTimeout:deadline,
        maxHeaderSize:8192}, (request, response) => {
        let timer;
        const refuse = () => {
            clearTimeout(timer);
            if (!response.destroyed && !response.headersSent) {
                const body = Buffer.from('{"error":"WITNESS_REQUEST_REFUSED"}');
                response.writeHead(503, {'content-type':'application/json','content-length':body.length,'connection':'close','cache-control':'no-store'});
                response.end(body);
            }
        };
        try {
            check(request.socket.authorized && digest(request.socket.getPeerCertificate().raw) === expected, 'Witness TLS client not authorized');
            check(request.method === 'POST' && request.url === ROUTE, 'Witness HTTP route differs');
            const expectedLength = media(request.headers); let size = 0; const chunks = [];
            timer = setTimeout(() => { request.destroy(); refuse(); }, deadline);
            request.on('error', refuse);
            request.on('data', chunk => {
                size += chunk.length;
                if (size > expectedLength || size > LIMIT) { request.destroy(); refuse(); }
                else chunks.push(chunk);
            });
            request.on('end', async () => {
                try {
                    check(size === expectedLength, 'Witness request truncated');
                    const result = await call(decode(Buffer.concat(chunks)));
                    const body = encode(result); clearTimeout(timer);
                    if (!response.destroyed) {
                        response.writeHead(200, {'content-type':'application/json','content-length':body.length,'connection':'close','cache-control':'no-store'});
                        response.end(body);
                    }
                } catch { refuse(); }
            });
        } catch { request.resume(); refuse(); }
    });
    server.requestTimeout = deadline; server.headersTimeout = deadline;
    server.timeout = deadline; server.keepAliveTimeout = 1; server.maxHeadersCount = 32;
    return server; // Explicit caller must bind/listen; construction starts nothing.
}
module.exports = {POLICY, ROUTE, LIMIT, createHttpsTransport, createHttpsServer,
    isHttpsTransport: value => transports.has(value)};
