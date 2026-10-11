'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {checks,publicPayload}=require('../integration/witnessed-dual-check'),P=require('../protected-public-runner'),N=require('../network');
const vector=require('./public-vector.json');
// Fabric is a double in this local suite. The Docker launcher replaces it with
// authenticated genuine SDK/peer runs; both suites use actual local EVM execution.
test('16 witnessed composed recovery scenarios on actual local EVM with Fabric receipt doubles',async()=>{
    const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'ppi-dual-local-'));fs.chmodSync(root,0o700);
    const repo=path.join(root,'repo');fs.mkdirSync(repo,{mode:0o700});const recorded=new Map();let executions=0;
    const fabric={scope:p=>({private_sha256:'a'.repeat(64),public_sha256:p.public_sha256,history_sha256:'b'.repeat(64),code_revision:'1'.repeat(40),payload:p}),eventually:fn=>fn(),async run({selection:s,mode,directory,lost}){
        if(mode==='EXECUTE'){assert.ok(!recorded.has(directory),'No repeated Fabric execute');executions++;if(lost==='before')throw new Error('INJECTED_BEFORE_DELIVERY');const r=structuredClone(vector.fabric_receipt);r.payload=s.payload;r.transaction_id=crypto.randomBytes(32).toString('hex');recorded.set(directory,r);if(lost)throw new Error('INJECTED_ACK_LOSS');}
        assert.ok(recorded.has(directory));return {status:'FABRIC_COMMIT_VERIFIED',receipt:structuredClone(recorded.get(directory))};
    }};
    try{const result=await checks({root,repo,fabric});assert.equal(result.checks,16);assert.equal(executions,16);assert.equal(result.public_finality_simulated,true);assert.equal(result.public_provider_independence,false);assert.equal(result.live_research_ready,false);assert.equal(result.research_records_used,0);}finally{fs.rmSync(root,{recursive:true,force:true});}
});
test('Fabric public binding rejects each changed commitment, destination and original transaction',()=>{
    const receipt=structuredClone(vector.fabric_receipt),payload=publicPayload(receipt);
    assert.deepEqual(payload,vector.payload);
    const selection={private_sha256:'a'.repeat(64),public_sha256:payload.public_sha256,history_sha256:'b'.repeat(64),code_revision:'1'.repeat(40),network_config_sha256:'c'.repeat(64),destination:{chain_id:11155111,contract:'0x'+'11'.repeat(20),writer:'0x'+'22'.repeat(20),runtime_sha256:'d'.repeat(64),namespace:'findings-anchor-v1',finality:'FINALIZED'},payload,fabric_receipt:receipt};
    P.selection(selection);
    for(const field of ['publication_id','public_sha256','merkle_root','fabric_destination_sha256','fabric_transaction_id','fabric_receipt_sha256']){const s=structuredClone(selection);s.payload[field]='f'.repeat(64);assert.throws(()=>P.selection(s));}
    const s=structuredClone(selection);s.fabric_receipt.transaction_id='0x'+s.fabric_receipt.transaction_id;assert.throws(()=>P.selection(s));
    assert.equal(N.sha(receipt),payload.fabric_receipt_sha256);
});
