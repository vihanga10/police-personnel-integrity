'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {makeData}=require('../check-network');const {canonical,sha,EvidenceRules}=require('../../chaincode/lib/evidence');
const {authorize,recent}=require('../research-authorization');const {run}=require('../anchor-research');
const secret=Buffer.alloc(32,83);
function payload(mode='EXECUTE') {
 const {publication,metadata}=makeData();return {policy:'FABRIC_RESEARCH_SUBMISSION_V1',mode,checked_at:new Date().toISOString(),publication,public_payload_sha256:sha(publication),
 network:{channel:'personnel',chaincode:'officer-evidence-v1',genesis_sha256:'a'.repeat(64)},
 plan:{policy:'LIVE_EVIDENCE_ANCHOR_GATE_V1',metadata,officer_count:6596,chunk_count:66,transaction_count:68,chunks:Array.from({length:66},(_,i)=>{const records=publication.officers.slice(i*100,(i+1)*100);return {index:i,records,records_sha256:sha(records)};})}};
}
function ticket(p){return {payload:p,mac:crypto.createHmac('sha256',secret).update(canonical(p)).digest('hex')};}
test('authorized exact original 6596 publication accepted',()=>{const p=payload();assert.deepEqual(authorize(ticket(p),secret,'EXECUTE'),p);});
for(const kind of ['mac','expired','future','mode','digest','plan','merkle','count','personal','namespace'])test('reject '+kind,()=>{
 const p=payload();if(kind==='expired')p.checked_at=new Date(Date.now()-600001).toISOString();if(kind==='future')p.checked_at=new Date(Date.now()+60000).toISOString();
 if(kind==='mode')p.mode='RECONCILE';if(kind==='digest')p.public_payload_sha256='f'.repeat(64);
 if(kind==='plan')p.plan.chunks[0].records_sha256='f'.repeat(64);if(kind==='merkle')p.publication.merkle_root='f'.repeat(64);
 if(kind==='count')p.publication.officers.pop();if(kind==='personal')p.publication.officers[0].nic='fixture';if(kind==='namespace')p.network.chaincode='officer-evidence-test-v1';
 const t=ticket(p);if(kind==='mac')t.mac='0'.repeat(64);assert.throws(()=>authorize(t,secret,'EXECUTE'));
});
function connection(p){let ledger=new Map(),pending=new Map(),counter=0,submits=0;const rules=new EvidenceRules();
 function context(map,id){return {clientIdentity:{getMSPID:()=> 'Org1MSP',assertAttributeValue:()=>true},stub:{getTxID:()=>id,getState:async k=>map.get(k)||Buffer.alloc(0),putState:async(k,v)=>map.set(k,v)}};}
 const driver={endorse:async(method,args)=>{const id=(++counter).toString(16).padStart(64,'0'),copy=new Map(ledger);const expected=await rules[method](context(copy,id),...args);pending.set(id,{copy,expected});return {id,bytes:id,expected};},
 submit:async id=>{submits++;ledger=pending.get(id).copy;return {id,commit_bytes:id};},status:async id=>({transactionId:id,successful:true,code:0,blockNumber:1n}),
 observe:async(method,args)=>{const value=await rules[method](context(ledger,'read'),...args);return {Org1MSP:value,Org2MSP:value};}};
 return {network:p.network,verifyNetwork:async()=>{},driver,counts:()=>({endorse:counter,submit:submits})};
}
async function quiet(fn){const previous=console.log;console.log=()=>{};try{return await fn();}finally{console.log=previous;}}
test('all actual research values persist and reconcile without another write',async()=>{
 const p=payload(),c=connection(p),directory=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'research-anchor-'));fs.chmodSync(directory,0o700);
 try{const result=await quiet(()=>run(c,p,directory));assert.equal(result.original_valid_transactions,68);assert.equal(c.counts().submit,68);
 const reconciled=await quiet(()=>run(c,{...p,mode:'RECONCILE'},directory));assert.equal(reconciled.officers,6596);assert.deepEqual(c.counts(),{endorse:68,submit:68});}
 finally{fs.rmSync(directory,{recursive:true,force:true});}
});
test('expiry between endorsement and submit preserves prepared original for a fresh gate',async()=>{
 const p=payload(),c=connection(p),directory=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'research-anchor-'));fs.chmodSync(directory,0o700);const endorse=c.driver.endorse;
 c.driver.endorse=async(...args)=>{const result=await endorse(...args);p.checked_at=new Date(0).toISOString();return result;};
 try{await assert.rejects(quiet(()=>run(c,p,directory)),/expired/);assert.equal(c.counts().submit,0);assert.equal(fs.existsSync(path.join(directory,'batch.prepared.json')),true);
 c.driver.endorse=endorse;p.checked_at=new Date().toISOString();await quiet(()=>run(c,p,directory));assert.equal(c.counts().endorse,68);assert.equal(c.counts().submit,68);}
 finally{fs.rmSync(directory,{recursive:true,force:true});}
});
test('read-only reconciliation cannot create missing transactions',async()=>{
 const p=payload('RECONCILE'),c=connection(p),directory=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'research-anchor-'));fs.chmodSync(directory,0o700);
 try{await assert.rejects(run(c,p,directory),/receipt missing/);assert.deepEqual(c.counts(),{endorse:0,submit:0});}finally{fs.rmSync(directory,{recursive:true,force:true});}
});
