'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const {FindingsRules,POLICY,RECORD_POLICY,NAMESPACE,canonical,sha,key} = require('../lib/findings');
const vector = require('./commitment-vector.json');
const hex = n => BigInt(n).toString(16).padStart(64,'0');
const payload = () => structuredClone(vector.payload);

// Explicit transaction simulator: reads track versions, writes apply only on valid commit.
// This is a test of dependencies, not a real Fabric peer or consensus implementation.
function ledger() {
    const state = new Map(); const versions = new Map(); let txNumber = 1000;
    function transaction(msp='Org1MSP',attribute=true) {
        const reads = new Map(), writes = new Map(); const txID = hex(txNumber++);
        const ctx = {clientIdentity:{getMSPID:()=>msp,assertAttributeValue:(name,value)=>
            name==='findings.anchor' && value==='true' && attribute},stub:{
            getTxID:()=>txID,
            getState:async k=>{reads.set(k,versions.get(k)||0);return state.get(k)||Buffer.alloc(0);},
            putState:async(k,v)=>{writes.set(k,Buffer.from(v));}
        }};
        return {ctx,reads,writes,txID,commit:()=>{
            for(const [k,v] of reads)if((versions.get(k)||0)!==v)throw new Error('MVCC_READ_CONFLICT');
            for(const [k,v] of writes){state.set(k,v);versions.set(k,(versions.get(k)||0)+1);}
        }};
    }
    return {state,versions,transaction,rules:new FindingsRules()};
}
async function anchor(l,p=payload(),t=l.transaction()) {
    const r=await l.rules.AnchorFindings(t.ctx,canonical(p));t.commit();return r;
}
function inventory(l) {return [...l.state].map(([k,v])=>[k,v.toString()]);}

test('Python-produced commitment has exact canonical digest and SHA-256 Merkle encoding',()=>{
    const p=vector.public;
    assert.equal(sha(p),vector.payload.public_sha256);
    let leaves=p.entries.map(e=>({kind:'FINDINGS_ENTRY',...e}));
    leaves.push({kind:'FINDINGS_HISTORY',policy:p.policy,commitment_version:1,key_version:p.key_version,
        publication_id:p.publication_id,history_commitment:p.history_commitment,entry_count:p.entries.length,
        commitment:p.publication_commitment});
    let nodes=leaves.map(x=>crypto.createHash('sha256').update(Buffer.from([0])).update(canonical(x)).digest());
    while(nodes.length>1){
        if(nodes.length%2)nodes.push(nodes[nodes.length-1]);
        const next=[];for(let i=0;i<nodes.length;i+=2)next.push(crypto.createHash('sha256').update(Buffer.from([1])).update(nodes[i]).update(nodes[i+1]).digest());nodes=next;
    }
    assert.equal(nodes[0].toString('hex'),p.merkle_root);
});

test('publication records only exact opaque metadata with original transaction ID',async()=>{
    const l=ledger(),p=payload(),t=l.transaction();const r=await anchor(l,p,t);
    assert.deepEqual(r,{policy:RECORD_POLICY,payload:p,transaction_id:t.txID});
    assert.equal(l.state.size,1);assert.deepEqual([...t.reads.keys()],[key(p.publication_id)]);
    for(const msp of ['Org1MSP','Org2MSP'])assert.deepEqual(await l.rules.ReadFindings(l.transaction(msp).ctx,p.publication_id),r);
    for(const word of ['officer_uid','nic','reason','recorded_at','reviewed_at','source_context'])assert.ok(!JSON.stringify(r).includes(word));
});

test('exact retry returns original committed identity and adds no state writes',async()=>{
    const l=ledger(),first=await anchor(l),before=inventory(l),t=l.transaction();
    const retry=await l.rules.AnchorFindings(t.ctx,canonical(payload()));t.commit();
    assert.deepEqual(retry,first);assert.notEqual(retry.transaction_id,t.txID);
    assert.equal(t.writes.size,0);assert.deepEqual(inventory(l),before);
});

for(const field of ['public_sha256','merkle_root','publication_commitment']) {
    test('conflicting '+field+' cannot replace an immutable publication',async()=>{
        const l=ledger();await anchor(l);const before=inventory(l),p=payload(),t=l.transaction();p[field]=hex(9999);
        await assert.rejects(l.rules.AnchorFindings(t.ctx,canonical(p)),/Conflicting/);
        assert.equal(t.writes.size,0);assert.deepEqual(inventory(l),before);
    });
}

test('later opaque publication appends without deleting or changing prior findings or evidence',async()=>{
    const l=ledger();l.state.set('evidence-v1:batch:'+hex(4),Buffer.from('original evidence'));
    const first=await anchor(l),old=inventory(l),p=payload();p.publication_id=hex(8888);p.merkle_root=hex(8889);
    await anchor(l,p);assert.equal(l.state.size,3);
    for(const [k,v] of old)assert.equal(l.state.get(k).toString(),v);
    assert.deepEqual(await l.rules.ReadFindings(l.transaction().ctx,first.payload.publication_id),first);
});

for(const kind of ['wrong-msp','missing-attribute','evidence-only','truthy-not-boolean']) {
    test('writer authorization rejects '+kind+' including retries',async()=>{
        const l=ledger();await anchor(l);const before=inventory(l);
        const t=l.transaction(kind==='wrong-msp'?'Org2MSP':'Org1MSP',kind!=='missing-attribute');
        if(kind==='evidence-only')t.ctx.clientIdentity.assertAttributeValue=(name,value)=>name==='evidence.anchor'&&value==='true';
        if(kind==='truthy-not-boolean')t.ctx.clientIdentity.assertAttributeValue=()=> 'true';
        await assert.rejects(l.rules.AnchorFindings(t.ctx,canonical(payload())),/not authorized/);
        assert.equal(t.reads.size,0);assert.equal(t.writes.size,0);assert.deepEqual(inventory(l),before);
    });
}

test('unauthorized reader and absent publication fail without writes',async()=>{
    const l=ledger();await anchor(l);const t=l.transaction('UnknownMSP');
    await assert.rejects(l.rules.ReadFindings(t.ctx,payload().publication_id),/not authorized/);
    assert.equal(t.reads.size,0);assert.equal(t.writes.size,0);
    await assert.rejects(l.rules.ReadFindings(l.transaction().ctx,hex(9999)),/absent/);
});

for(const kind of ['extra-nic','missing','wrong-policy','wrong-namespace','uppercase','short','number','array','null','proto','malformed','duplicate','pretty','oversize']) {
    test('reject input '+kind+' before ledger writes',async()=>{
        const l=ledger(),t=l.transaction();let p=payload(),text;
        if(kind==='extra-nic')p.nic='fixture-private';
        else if(kind==='missing')delete p.merkle_root;
        else if(kind==='wrong-policy')p.policy='OFFICER_PROTECTED_COMMITMENT_V1';
        else if(kind==='wrong-namespace')p.namespace='evidence-v1';
        else if(kind==='uppercase')p.merkle_root='A'.repeat(64);
        else if(kind==='short')p.public_sha256='ab';
        else if(kind==='number')p.publication_id=123;
        else if(kind==='array')p=[];
        else if(kind==='null')p=null;
        text=canonical(p);
        if(kind==='proto')text=text.slice(0,-1)+',"__proto__":{"nic":"secret"}}';
        else if(kind==='malformed')text='{';
        else if(kind==='duplicate')text=text.slice(0,-1)+',"policy":"'+POLICY+'"}';
        else if(kind==='pretty')text=JSON.stringify(p,null,2);
        else if(kind==='oversize')text=' '.repeat(4097);
        await assert.rejects(l.rules.AnchorFindings(t.ctx,text));
        assert.equal(t.writes.size,0);assert.equal(l.state.size,0);
    });
}

for(const value of ['../x','',hex(1)+':other','ABC',null,10]) {
    test('reject invalid read handle '+JSON.stringify(value),async()=>{
        const l=ledger(),t=l.transaction();await assert.rejects(l.rules.ReadFindings(t.ctx,value));
        assert.equal(t.reads.size,0);
    });
}

test('transaction ID must be a valid Fabric hex ID before any staged write',async()=>{
    const l=ledger(),t=l.transaction();t.ctx.stub.getTxID=()=> 'invalid';
    await assert.rejects(l.rules.AnchorFindings(t.ctx,canonical(payload())));assert.equal(t.writes.size,0);
});

for(const kind of ['same','conflicting']) {
    test('simulated concurrent absent-key insert has one valid commit: '+kind,async()=>{
        const l=ledger(),a=l.transaction(),b=l.transaction(),p=payload(),other=payload();
        if(kind==='conflicting')other.merkle_root=hex(44);
        const first=await l.rules.AnchorFindings(a.ctx,canonical(p));
        await l.rules.AnchorFindings(b.ctx,canonical(other));
        assert.equal(l.state.size,0);a.commit();assert.throws(()=>b.commit(),/MVCC_READ_CONFLICT/);
        assert.deepEqual(await l.rules.ReadFindings(l.transaction().ctx,p.publication_id),first);
        assert.equal(l.state.size,1);
        if(kind==='same')assert.deepEqual(await anchor(l),first);
        else await assert.rejects(anchor(l,other),/Conflicting/);
    });
}

test('read failures and state write failures never return a success record',async()=>{
    const l=ledger(),a=l.transaction();a.ctx.stub.getState=async()=>{throw new Error('read outage');};
    await assert.rejects(l.rules.AnchorFindings(a.ctx,canonical(payload())),/read outage/);assert.equal(a.writes.size,0);
    const b=l.transaction();b.ctx.stub.putState=async()=>{throw new Error('write outage');};
    await assert.rejects(l.rules.AnchorFindings(b.ctx,canonical(payload())),/write outage/);assert.equal(l.state.size,0);
});

for(const kind of ['json','policy','extra','handle','transaction','encoding']) {
    test('corrupt stored state is detected: '+kind,async()=>{
        const l=ledger();const r=await anchor(l);let record=structuredClone(r),text;
        if(kind==='policy')record.policy='OTHER';
        else if(kind==='extra')record.nic='private';
        else if(kind==='handle')record.payload.publication_id=hex(99);
        else if(kind==='transaction')record.transaction_id='bad';
        text=kind==='json'?'broken':kind==='encoding'?JSON.stringify(record,null,2):canonical(record);
        l.state.set(key(r.payload.publication_id),Buffer.from(text));
        await assert.rejects(l.rules.ReadFindings(l.transaction().ctx,r.payload.publication_id));
        await assert.rejects(l.rules.AnchorFindings(l.transaction().ctx,canonical(payload())));
    });
}

test('Fabric wrapper exposes exactly two explicit transactions in separate contract',async()=>{
    class Contract {constructor(name){this.name=name;}}
    const box={module:{exports:{}},require:name=>{
        if(name==='fabric-contract-api')return {Contract};
        if(name==='./lib/findings')return {FindingsRules};
        throw new Error('Unexpected wrapper dependency');
    }};
    vm.runInNewContext(fs.readFileSync(require.resolve('../index.js'),'utf8'),box);
    const [Type]=box.module.exports.contracts,contract=new Type();
    assert.equal(contract.name,'FindingsAnchor');
    assert.deepEqual(Object.getOwnPropertyNames(Type.prototype).sort(),['AnchorFindings','ReadFindings','constructor']);
    const l=ledger(),t=l.transaction();const r=await contract.AnchorFindings(t.ctx,canonical(payload()));t.commit();
    assert.deepEqual(await contract.ReadFindings(l.transaction('Org2MSP').ctx,payload().publication_id),r);
});
