'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {argumentsFor,POLICY,NAMESPACE,METADATA,FIELDS}=require('../payload');
const vector=require('./public-vector.json');
const canonical=x=>x===null||typeof x!=='object'?JSON.stringify(x):Array.isArray(x)?'['+x.map(canonical).join(',')+']':'{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
const digest=x=>crypto.createHash('sha256').update(canonical(x)).digest('hex');
test('Python coordinator vector has exact public, Fabric destination and receipt digests',()=>{
    const p=vector.payload;
    assert.equal(p.public_sha256,vector.fabric_payload.public_sha256);assert.equal(p.fabric_destination_sha256,digest(vector.fabric_destination));
    assert.equal(p.fabric_receipt_sha256,digest(vector.fabric_receipt));assert.equal(p.fabric_transaction_id,vector.fabric_receipt.transaction_id);
    assert.equal(p.merkle_root,vector.fabric_payload.merkle_root);assert.equal(p.publication_id,vector.fabric_payload.publication_id);
    assert.equal(p.policy,POLICY);assert.equal(p.namespace,NAMESPACE);
    assert.deepEqual(argumentsFor(p),['0x'+p.publication_id,METADATA.map(k=>'0x'+p[k])]);
});
test('schema preparation returns independent arrays and leaves input unchanged',()=>{
    const p=structuredClone(vector.payload),before=structuredClone(p),a=argumentsFor(p);a[1][0]='changed';assert.deepEqual(p,before);
});
for(const k of FIELDS)test('missing field '+k+' is rejected',()=>{const p={...vector.payload};delete p[k];assert.throws(()=>argumentsFor(p));});
for(const k of ['publication_id',...METADATA])for(const value of [null,42,'', '0'.repeat(64),'A'.repeat(64),'a'.repeat(63),'0x'+'a'.repeat(64), 'g'.repeat(64)])
    test('reject malformed '+k+' '+JSON.stringify(value),()=>assert.throws(()=>argumentsFor({...vector.payload,[k]:value})));
for(const k of ['nic','name','officer_uid','explanation','effective_at','recorded_at','publication_commitment'])
    test('reject unexpected public field '+k,()=>assert.throws(()=>argumentsFor({...vector.payload,[k]:'private'})));
test('wrong policy and namespace are rejected',()=>{
    assert.throws(()=>argumentsFor({...vector.payload,policy:'PROMOTIONS_FABRIC_ANCHOR_V1'}));
    assert.throws(()=>argumentsFor({...vector.payload,namespace:'officer-evidence-v1'}));
});
test('reject non-plain, inherited, accessor and symbol-bearing objects without invoking getters',()=>{
    for(const v of [null,[],new Date(),Object.create(vector.payload),Object.assign(Object.create(null),vector.payload)])assert.throws(()=>argumentsFor(v));
    const p={...vector.payload};Object.defineProperty(p,'public_sha256',{get(){assert.fail('getter executed');}});assert.throws(()=>argumentsFor(p),/Plain fields/);
    assert.throws(()=>argumentsFor({...vector.payload,[Symbol('private')]:1}));
});
test('changing any opaque value changes exactly the corresponding ABI value',()=>{
    const original=argumentsFor(vector.payload);
    for(const k of ['publication_id',...METADATA]){
        const changed=argumentsFor({...vector.payload,[k]:'ab'.repeat(32)});assert.notDeepEqual(changed,original);
        if(k==='publication_id')assert.deepEqual(changed[1],original[1]);else assert.equal(changed[0],original[0]);
    }
});
