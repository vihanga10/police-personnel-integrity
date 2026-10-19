'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {fixture}=require('./fixture'),{bindCapturedReceipt}=require('../fabric-binding'),{readPrivate}=require('../check-plan');
function receipt(f){return {status:'PASSED',mode:'RECONCILE',public_payload_sha256:f.digest,fabric_result:{status:'PASSED',mode:'RECONCILE',public_payload_sha256:f.digest,officers:6596,original_valid_transactions:68,two_organization_readback:true,batch_publication_id:f.publicPayload.batch_publication_id,merkle_root:f.publicPayload.merkle_root,classification:'UNASSESSED',network:{channel:'personnel',chaincode:'officer-evidence-v1',genesis_sha256:'7e496158e847bd1ed07232f4790331f9ec9a6639e3419e2e98ea55a89948016e',genesis_identity:{policy:'FABRIC_GENESIS_HEADER_DATA_V1',header_sha256:'b9ed551d2ce23b9ac765e6e9e9966ce498e7b09e85450fb98103e38354588cb6',data_sha256:'2d4a456cfa91b90cbbd152d47ee960f07a42be2eba401d4a0bedddf42064d434'}}}};}
test('saved reconciliation comparison binds exact original public version and network',()=>{const f=fixture();assert.equal(bindCapturedReceipt(receipt(f),f.publicPayload,f.digest),true);});
for(const key of ['mode','officers','original_valid_transactions','two_organization_readback','batch_publication_id','merkle_root','public_payload_sha256','classification']){
    test('saved comparison rejects '+key,()=>{const f=fixture(),r=receipt(f);r.fabric_result[key]='wrong';assert.throws(()=>bindCapturedReceipt(r,f.publicPayload,f.digest));});
}
test('test chaincode and different network capture cannot pass saved comparison',()=>{
    const f=fixture(),r=receipt(f);r.fabric_result.network.chaincode='officer-evidence-test-v1';assert.throws(()=>bindCapturedReceipt(r,f.publicPayload,f.digest));
    const s=receipt(f);s.fabric_result.network.genesis_identity.data_sha256='0'.repeat(64);assert.throws(()=>bindCapturedReceipt(s,f.publicPayload,f.digest));
});
test('private input reader rejects symlinks and permissive files',()=>{
    const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'public-plan-test-'));
    try{const file=path.join(root,'receipt.json');fs.writeFileSync(file,'{}',{mode:0o600});assert.deepEqual(readPrivate(file),{});
        const link=path.join(root,'link.json');fs.symlinkSync(file,link);assert.throws(()=>readPrivate(link));
        fs.chmodSync(file,0o644);assert.throws(()=>readPrivate(file));
    }finally{fs.rmSync(root,{recursive:true,force:true});}
});
