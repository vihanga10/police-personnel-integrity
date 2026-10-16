'use strict';
// Deterministic contract rules; identity and transactional state are supplied by Fabric.
const crypto = require('node:crypto');
const POLICY = 'PROMOTIONS_FABRIC_ANCHOR_V1';
const RECORD_POLICY = 'PROMOTIONS_FABRIC_RECORD_V1';
const NAMESPACE = 'promotions-anchor-v1';
const HEX = /^[0-9a-f]{64}$/;
const FIELDS = ['policy','namespace','publication_id','public_sha256','merkle_root','publication_commitment'];
function check(value,message) { if (!value) throw new Error(message); }
function exact(value,fields) {
    check(value !== null && typeof value === 'object' && !Array.isArray(value) &&
        Object.keys(value).sort().join(',') === [...fields].sort().join(','), 'Unexpected promotions fields');
}
function canonical(value) {
    if (Array.isArray(value)) return '['+value.map(canonical).join(',')+']';
    if (value !== null && typeof value === 'object') return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
    check(value === null || typeof value === 'string' || typeof value === 'boolean' || Number.isSafeInteger(value), 'Unsupported JSON type');
    return JSON.stringify(value);
}
function sha(value) { return crypto.createHash('sha256').update(canonical(value),'utf8').digest('hex'); }
function handle(id) { check(typeof id === 'string' && HEX.test(id), 'Invalid promotions handle'); return id; }
function key(id) { return NAMESPACE+':publication:'+handle(id); }
function validate(payload) {
    exact(payload,FIELDS);
    check(payload.policy === POLICY && payload.namespace === NAMESPACE, 'Dedicated promotions policy required');
    for (const name of ['publication_id','public_sha256','merkle_root','publication_commitment']) handle(payload[name]);
    return payload;
}
function writer(ctx) {
    check(ctx.clientIdentity.getMSPID() === 'Org1MSP' &&
        ctx.clientIdentity.assertAttributeValue('promotions.anchor','true') === true, 'Promotions writer not authorized');
}
function reader(ctx) { check(['Org1MSP','Org2MSP'].includes(ctx.clientIdentity.getMSPID()), 'Promotions reader not authorized'); }
async function read(ctx,id) {
    const bytes = await ctx.stub.getState(key(id));
    if (!bytes.length) return null;
    const record = JSON.parse(bytes.toString('utf8'));
    exact(record,['policy','payload','transaction_id']);
    check(record.policy === RECORD_POLICY && handle(record.transaction_id) && validate(record.payload).publication_id === id,
        'Stored promotions binding differs');
    check(bytes.toString('utf8') === canonical(record), 'Stored promotions encoding differs');
    return record;
}
class PromotionsRules {
    async AnchorPromotions(ctx,json) {
        writer(ctx);
        check(typeof json === 'string' && Buffer.byteLength(json,'utf8') <= 4096, 'Promotions input too large or not text');
        const payload = validate(JSON.parse(json));
        // Reject duplicate JSON keys, alternate encodings and extraneous input before reads/writes.
        check(json === canonical(payload), 'Canonical promotions payload required');
        const prior = await read(ctx,payload.publication_id);
        if (prior !== null) {
            check(canonical(prior.payload) === canonical(payload), 'Conflicting immutable promotions publication');
            return prior; // Return the ORIGINAL committed transaction, never a new retry identity.
        }
        const tx = handle(ctx.stub.getTxID());
        const record = {policy:RECORD_POLICY,payload,transaction_id:tx};
        // The preceding absent-key read is the MVCC dependency; concurrent inserts cannot both commit.
        await ctx.stub.putState(key(payload.publication_id),Buffer.from(canonical(record),'utf8'));
        return record;
    }
    async ReadPromotions(ctx,id) {
        reader(ctx);handle(id);
        const record = await read(ctx,id);check(record !== null,'Promotions publication absent');return record;
    }
}
module.exports = {PromotionsRules,POLICY,RECORD_POLICY,NAMESPACE,FIELDS,canonical,sha,key,validate};
