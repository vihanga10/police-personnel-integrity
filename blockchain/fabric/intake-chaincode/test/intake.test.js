'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {IntakeRules,RECORD_POLICY,POLICY,NAMESPACE,DATASETS,canonical,key} = require('../lib/intake');
const hex = n => BigInt(n).toString(16).padStart(64,'0');
const payload = (changes={}) => ({policy:POLICY,namespace:NAMESPACE,dataset:'TRANSFER_HISTORY',
    publication_id:'a'.repeat(64),public_sha256:'b'.repeat(64),merkle_root:'c'.repeat(64),publication_commitment:'d'.repeat(64),...changes});

// Explicit transaction simulator: reads track versions, writes apply only on valid commit.
function ledger() {
    const state = new Map(), versions = new Map(); let txNumber = 1000;
    function transaction(msp='Org1MSP',attribute=true) {
        const reads = new Map(), writes = new Map(), txID = hex(txNumber++);
        const ctx = {clientIdentity:{getMSPID:()=>msp,assertAttributeValue:(name,value)=>name==='intake.anchor'&&value==='true'&&attribute},
            stub:{getTxID:()=>txID,getState:async k=>{reads.set(k,versions.get(k)||0);return state.get(k)||Buffer.alloc(0);},
                putState:async(k,v)=>{writes.set(k,Buffer.from(v));}}};
        return {ctx,reads,writes,txID,commit:()=>{
            for(const [k,v] of reads)if((versions.get(k)||0)!==v)throw new Error('MVCC_READ_CONFLICT');
            for(const [k,v] of writes){state.set(k,v);versions.set(k,(versions.get(k)||0)+1);}
        }};
    }
    return {state,transaction,rules:new IntakeRules()};
}
async function anchor(l,p=payload(),t=l.transaction()){const r=await l.rules.AnchorIntake(t.ctx,canonical(p));t.commit();return r;}

test('registered dataset code and opaque commitments are recorded with the original transaction ID',async()=>{
    const l=ledger(),t=l.transaction(),r=await anchor(l,payload(),t);
    assert.deepEqual(r,{policy:RECORD_POLICY,payload:payload(),transaction_id:t.txID});
    assert.deepEqual([...t.reads.keys()],[key('a'.repeat(64))]);
    for(const msp of ['Org1MSP','Org2MSP'])assert.deepEqual(await l.rules.ReadIntake(l.transaction(msp).ctx,'a'.repeat(64)),r);
    assert.equal(DATASETS.length,18);
});

test('exact retry returns the original identity; a changed payload under the same handle is refused',async()=>{
    const l=ledger(),first=await anchor(l),retry=await anchor(l);
    assert.deepEqual(retry,first);
    await assert.rejects(anchor(l,payload({merkle_root:'e'.repeat(64)})),/Conflicting immutable intake publication/);
    await assert.rejects(anchor(l,payload({dataset:'EDUCATION'})),/Conflicting immutable intake publication/);
});

test('only the Org1 intake writer attribute may anchor; both organizations may read',async()=>{
    const l=ledger();
    await assert.rejects(l.rules.AnchorIntake(l.transaction('Org2MSP').ctx,canonical(payload())),/writer not authorized/);
    await assert.rejects(l.rules.AnchorIntake(l.transaction('Org1MSP',false).ctx,canonical(payload())),/writer not authorized/);
    await assert.rejects(l.rules.ReadIntake(l.transaction('Org3MSP').ctx,'a'.repeat(64)),/reader not authorized/);
});

test('unregistered datasets, promotions policy, personal fields and non-canonical input are refused',async()=>{
    const l=ledger();
    for(const bad of [payload({dataset:'PROMOTION_HISTORY'}),payload({dataset:'transfer_history'}),payload({policy:'PROMOTIONS_FABRIC_ANCHOR_V1'}),
        {...payload(),officer_nic_no:'000000001V'},payload({merkle_root:'X'.repeat(64)})])
        await assert.rejects(anchor(l,bad));
    await assert.rejects(l.rules.AnchorIntake(l.transaction().ctx,JSON.stringify(payload(),null,1)),/Canonical intake payload required/);
    assert.equal(l.state.size,0);
});
