'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EvidenceRules, canonical, sha, tree, key, POLICY } = require('../lib/evidence');
const hex = n => BigInt(n).toString(16).padStart(64, '0');
function data() {
    const rows = Array.from({length:6596}, (_,i) => ({ publication_id:hex(i+1), commitment_version:1, commitment:hex(i+10000) }));
    const publicPayload = { policy:POLICY, commitment_version:1, key_version:'commit-v1', batch_publication_id:hex(80000),
        officers:rows, shared_commitment:hex(80001), coverage_commitment:hex(80002), batch_commitment:hex(80003) };
    publicPayload.merkle_root = tree([...rows.map(r => ({kind:'OFFICER', ...r})), {kind:'BATCH', publication_id:publicPayload.batch_publication_id, commitment:publicPayload.batch_commitment}]);
    const {officers, ...metadata} = publicPayload;
    Object.assign(metadata,{officer_count:6596,public_payload_sha256:sha(publicPayload)});
    return {rows, metadata, publicPayload};
}
function fixture() {
    const state = new Map(); let number = 100000;
    const ctx = {clientIdentity:{getMSPID:()=> 'Org1MSP', assertAttributeValue:(name,value)=>name==='evidence.anchor'&&value==='true'},
        stub:{getState:async k=>state.get(k)||Buffer.alloc(0), putState:async(k,v)=>state.set(k,v), getTxID:()=>hex(number)}};
    return {ctx,state, rules:new EvidenceRules(), advance:()=>number++};
}
async function ingest(f, d) {
    await f.rules.CreateBatch(f.ctx,canonical(d.metadata));
    for(let i=0;i<66;i++) {f.advance();await f.rules.AppendOfficers(f.ctx,d.metadata.batch_publication_id,String(i),canonical(d.rows.slice(i*100,(i+1)*100)));}
}
test('all 6596 commitments seal with exact payload and append-only replay',async()=>{
    const f=fixture(),d=data(); await ingest(f,d); f.advance();
    const seal=await f.rules.SealBatch(f.ctx,d.metadata.batch_publication_id);
    assert.equal(seal.officer_count,6596);assert.equal(seal.public_payload_sha256,sha(d.publicPayload));
    const before=[...f.state.entries()].map(([k,v])=>[k,v.toString()]);
    f.advance();await f.rules.CreateBatch(f.ctx,canonical(d.metadata));
    await f.rules.AppendOfficers(f.ctx,d.metadata.batch_publication_id,'0',canonical(d.rows.slice(0,100)));
    assert.deepEqual(await f.rules.SealBatch(f.ctx,d.metadata.batch_publication_id),seal);
    assert.deepEqual([...f.state.entries()].map(([k,v])=>[k,v.toString()]),before);
    assert.equal(f.state.size,1+6596+66+1);
    const observed=await f.rules.ReadOfficer(f.ctx,d.metadata.batch_publication_id,d.rows[50].publication_id);
    assert.equal(observed.commitment,d.rows[50].commitment);assert.equal(observed.commitment_version,1);
});
test('writer MSP and anchoring attribute required for every write',async()=>{
    for(const kind of ['wrong_msp','missing_attribute']) {
        const f=fixture(),d=data();
        if(kind==='wrong_msp') f.ctx.clientIdentity.getMSPID=()=> 'Org2MSP';
        else f.ctx.clientIdentity.assertAttributeValue=()=> false;
        await assert.rejects(f.rules.CreateBatch(f.ctx,canonical(d.metadata)),/not authorized/);
        await assert.rejects(f.rules.AppendOfficers(f.ctx,d.metadata.batch_publication_id,'0',canonical(d.rows.slice(0,100))),/not authorized/);
        await assert.rejects(f.rules.SealBatch(f.ctx,d.metadata.batch_publication_id),/not authorized/);
        assert.equal(f.state.size,0);
    }
});
test('unauthorized readers cannot query',async()=>{
    const f=fixture(),d=data();f.ctx.clientIdentity.getMSPID=()=> 'UnknownMSP';
    await assert.rejects(f.rules.ReadBatch(f.ctx,d.metadata.batch_publication_id),/not authorized/);
    await assert.rejects(f.rules.ReadOfficer(f.ctx,d.metadata.batch_publication_id,d.rows[0].publication_id),/not authorized/);
});
for(const kind of ['personal_field','bad_digest','wrong_version','wrong_count','wrong_policy']) {
    test(`reject malformed batch ${kind}`,async()=>{
        const f=fixture(),d=data();
        if(kind==='personal_field')d.metadata.nic='123456789V';
        if(kind==='bad_digest')d.metadata.batch_commitment='bad';
        if(kind==='wrong_version')d.metadata.commitment_version=2;
        if(kind==='wrong_count')d.metadata.officer_count=5861;
        if(kind==='wrong_policy')d.metadata.policy='OTHER';
        await assert.rejects(f.rules.CreateBatch(f.ctx,canonical(d.metadata)));assert.equal(f.state.size,0);
    });
}
test('conflicting batch cannot replace its original',async()=>{
    const f=fixture(),d=data();await f.rules.CreateBatch(f.ctx,canonical(d.metadata));
    d.metadata.batch_commitment=hex(99);await assert.rejects(f.rules.CreateBatch(f.ctx,canonical(d.metadata)),/Conflicting/);
    assert.equal(f.state.size,1);
});
for(const kind of ['missing','duplicate','unsorted','extra_field','wrong_version','invalid_index','out_of_order']) {
    test(`reject malformed chunk ${kind}`,async()=>{
        const f=fixture(),d=data();await f.rules.CreateBatch(f.ctx,canonical(d.metadata));
        const rows=d.rows.slice(0,100).map(r=>({...r}));let index='0';
        if(kind==='missing')rows.pop();
        if(kind==='duplicate')rows[1]={...rows[0]};
        if(kind==='unsorted')rows.reverse();
        if(kind==='extra_field')rows[0].officer_uid='identity';
        if(kind==='wrong_version')rows[0].commitment_version=2;
        if(kind==='invalid_index')index='00';
        if(kind==='out_of_order')index='1';
        await assert.rejects(f.rules.AppendOfficers(f.ctx,d.metadata.batch_publication_id,index,canonical(rows)));
        assert.equal(f.state.size,1);
    });
}
test('a changed officer in a retry cannot replace a committed chunk',async()=>{
    const f=fixture(),d=data();await f.rules.CreateBatch(f.ctx,canonical(d.metadata));
    const rows=d.rows.slice(0,100).map(r=>({...r}));await f.rules.AppendOfficers(f.ctx,d.metadata.batch_publication_id,'0',canonical(rows));
    rows[50].commitment=hex(999999);await assert.rejects(f.rules.AppendOfficers(f.ctx,d.metadata.batch_publication_id,'0',canonical(rows)),/Conflicting/);
    assert.equal((await f.rules.ReadOfficer(f.ctx,d.metadata.batch_publication_id,rows[50].publication_id)).commitment,d.rows[50].commitment);
});
test('cannot seal missing chunks',async()=>{
    const f=fixture(),d=data();await f.rules.CreateBatch(f.ctx,canonical(d.metadata));
    await assert.rejects(f.rules.SealBatch(f.ctx,d.metadata.batch_publication_id),/incomplete/);
    assert.equal(f.state.size,1);
});
for(const kind of ['altered_content','wrong_root','missing_record','wrong_tx']) {
    test(`seal fails for ${kind}`,async()=>{
        const f=fixture(),d=data();
        if(kind==='altered_content')d.rows[0].commitment=hex(999999);
        if(kind==='wrong_root')d.metadata.merkle_root=hex(999999);
        await ingest(f,d);
        if(kind==='missing_record')f.state.delete(key('officer',d.metadata.batch_publication_id,d.rows[0].publication_id));
        if(kind==='wrong_tx') {
            const stateKey=key('officer',d.metadata.batch_publication_id,d.rows[0].publication_id);
            const row=JSON.parse(f.state.get(stateKey));row.transaction_id=hex(999999);f.state.set(stateKey,Buffer.from(canonical(row)));
        }
        await assert.rejects(f.rules.SealBatch(f.ctx,d.metadata.batch_publication_id));
        assert.equal(f.state.has(key('seal',d.metadata.batch_publication_id)),false);
    });
}
test('wire canonicalization is fixed and typed',()=>{
    assert.equal(canonical({b:[true,null],a:1}),'\x7b"a":1,"b":[true,null]\x7d');
    assert.throws(()=>canonical({a:NaN}));assert.throws(()=>canonical({a:undefined}));
    assert.notEqual(sha({a:1}),sha({a:'1'}));
});
