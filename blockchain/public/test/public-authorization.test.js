'use strict';
const test = require('node:test'), assert = require('node:assert/strict'), crypto = require('node:crypto');
const F = require('../deployment-files'), { authorize } = require('../public-authorization');
const { fixture } = require('./fixture');
function ticket() {
    const f = fixture(), secret = Buffer.alloc(32, 83), payload = {
        policy: 'SEPOLIA_RESEARCH_SUBMISSION_V1', mode: 'EXECUTE', checked_at: new Date().toISOString(),
        publication: f.publicPayload, public_payload_sha256: f.digest, publication_fee_budget_eth: '0.025',
        deployment_transaction: '0x9240ee602582b02fc0e363610bbbaf462215aca366771891a9e6508c42be1dbd', reconciliation: {} };
    return { payload, secret };
}
function seal(payload, secret) { return { payload, mac: crypto.createHmac('sha256', secret).update(F.stable(payload)).digest('hex') }; }
test('unrelated fixture publication cannot authorize this original research batch', () => {
    const t = ticket(); assert.throws(() => authorize(seal(t.payload, t.secret), t.secret, 'EXECUTE'), /Original research publication required/);
});
for (const kind of ['mac', 'mode', 'expired', 'future', 'fields', 'session']) test('authorization rejects ' + kind, () => {
    const t = ticket();
    if (kind === 'mode') t.payload.mode = 'RECONCILE';
    if (kind === 'expired') t.payload.checked_at = new Date(Date.now() - 601000).toISOString();
    if (kind === 'future') t.payload.checked_at = new Date(Date.now() + 10000).toISOString();
    if (kind === 'fields') t.payload.personal_data = 'forbidden fixture';
    const envelope = seal(t.payload, t.secret);
    if (kind === 'mac') envelope.mac = '0'.repeat(64);
    assert.throws(() => authorize(envelope, kind === 'session' ? Buffer.alloc(1) : t.secret, 'EXECUTE'));
});
