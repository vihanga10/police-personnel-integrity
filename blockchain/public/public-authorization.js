'use strict';
const crypto = require('node:crypto');
const F = require('./deployment-files');
const { plan } = require('./publication');
const { bindCapturedReceipt } = require('./fabric-binding');
const check = (v, m) => { if (!v) throw new Error(m); };
function recent(payload, now = Date.now()) {
    const time = Date.parse(payload.checked_at);
    check(Number.isFinite(time) && now >= time && now - time <= 600000, 'Fresh live gate required');
}
function authorize(envelope, secret, mode, now = Date.now()) {
    check(Buffer.isBuffer(secret) && secret.length === 32, 'Private session required');
    check(envelope && Object.keys(envelope).sort().join(',') === 'mac,payload', 'Authorization shape differs');
    const p = envelope.payload;
    const mac = crypto.createHmac('sha256', secret).update(F.stable(p)).digest('hex');
    check(typeof envelope.mac === 'string' && /^[0-9a-f]{64}$/.test(envelope.mac) &&
        crypto.timingSafeEqual(Buffer.from(mac, 'hex'), Buffer.from(envelope.mac, 'hex')), 'Session MAC differs');
    check(Object.keys(p).sort().join(',') === 'checked_at,deployment_transaction,mode,policy,public_payload_sha256,publication,publication_fee_budget_eth,reconciliation', 'Ticket fields differ');
    check(p.policy === 'SEPOLIA_RESEARCH_SUBMISSION_V1' && p.mode === mode &&
        ['VALIDATE', 'EXECUTE', 'RECONCILE'].includes(mode), 'Ticket mode differs');
    recent(p, now);
    check(p.public_payload_sha256 === 'fa0a2820a3732739d719cdead513f0929f1b458ae69a2cbc7766b62ae449ad1b', 'Original research publication required');
    // Production pin is checked here; test fixtures exercise the generic engine separately.
    check(p.deployment_transaction === '0x9240ee602582b02fc0e363610bbbaf462215aca366771891a9e6508c42be1dbd', 'Original deployment required');
    bindCapturedReceipt(p.reconciliation, p.publication, p.public_payload_sha256);
    return { payload: p, plan: plan(p.publication, p.public_payload_sha256) };
}
module.exports = { authorize, recent };
