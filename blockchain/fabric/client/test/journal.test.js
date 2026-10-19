'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const os=require('node:os');const path=require('node:path');
const {execute,save,read}=require('../journal');
const txid='a'.repeat(64);const expected={transaction_id:txid,commitment:'b'.repeat(64)};
function fixture() {
    const directory=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'fabric-journal-test-'));fs.chmodSync(directory,0o700);
    const counts={endorse:0,submit:0,status:0,observe:0};
    const driver={endorse:async()=>{counts.endorse++;return {id:txid,bytes:'endorsed',expected};},
        submit:async bytes=>{assert.equal(bytes,'endorsed');counts.submit++;return {id:txid,commit_bytes:'commit-status'};},
        status:async bytes=>{assert.equal(bytes,'commit-status');counts.status++;return {transactionId:txid,successful:true,code:0,blockNumber:9n};},
        observe:async()=>{counts.observe++;return {Org1MSP:expected,Org2MSP:expected};}};
    const network={genesis_sha256:'c'.repeat(64),channel:'personnel',chaincode:'test'};
    const job={name:'test',method:'CreateBatch',args:['data'],read_method:'ReadBatch',read_args:['batch']};
    return {directory,driver,network,job,counts};
}
for(const stage of ['AFTER_PREPARE','AFTER_SUBMIT','AFTER_STATUS','AFTER_RECEIPT']) {
    test('durable replay at '+stage,async()=>{const f=fixture();try{
        await assert.rejects(execute({...f,interrupt:stage}),new RegExp('INJECTED_'+stage));
        const result=await execute(f);assert.equal(result.transaction_id,txid);assert.equal(result.validation_code,0);
        assert.equal(f.counts.endorse,1);assert.equal(f.counts.submit,1);
        const previous={...f.counts};await execute(f);
        assert.equal(f.counts.endorse,previous.endorse);assert.equal(f.counts.submit,previous.submit);
        assert.equal(fs.statSync(path.join(f.directory,'test.prepared.json')).mode&0o077,0);
    }finally{fs.rmSync(f.directory,{recursive:true,force:true});}});
}
for(const kind of ['invalid_status','wrong_tx','one_peer','readback_mismatch','network','operation','receipt_tamper','unsafe_name']) {
    test('stop on '+kind,async()=>{const f=fixture();try{
        if(kind==='invalid_status')f.driver.status=async()=>({transactionId:txid,successful:false,code:11,blockNumber:9n});
        if(kind==='wrong_tx')f.driver.status=async()=>({transactionId:'f'.repeat(64),successful:true,code:0,blockNumber:9n});
        if(kind==='one_peer')f.driver.observe=async()=>({Org1MSP:expected});
        if(kind==='readback_mismatch')f.driver.observe=async()=>({Org1MSP:expected,Org2MSP:{...expected,commitment:'f'.repeat(64)}});
        if(kind==='unsafe_name')f.job.name='../outside';
        if(['network','operation','receipt_tamper'].includes(kind)) {
            await execute(f);
            if(kind==='network')f.network.channel='other';
            if(kind==='operation')f.job.args=['changed'];
            if(kind==='receipt_tamper') {
                const receipt=path.join(f.directory,'test.valid.json');fs.writeFileSync(receipt,JSON.stringify({...read(receipt),validation_code:11}));
            }
        }
        await assert.rejects(execute(f));
    }finally{fs.rmSync(f.directory,{recursive:true,force:true});}});
}
test('ambiguous submit preserves same endorsed transaction; no invented receipt',async()=>{
    const f=fixture();try{f.driver.submit=async()=>{throw new Error('network timeout');};
        await assert.rejects(execute(f),/network timeout/);
        assert.equal(fs.existsSync(path.join(f.directory,'test.prepared.json')),true);
        assert.equal(fs.existsSync(path.join(f.directory,'test.valid.json')),false);
        assert.equal(f.counts.endorse,1);
    }finally{fs.rmSync(f.directory,{recursive:true,force:true});}
});
test('atomic files refuse overwrite and permissive directories',()=>{
    const f=fixture();try{const file=path.join(f.directory,'one.json');save(file,{x:1});assert.throws(()=>save(file,{x:2}));assert.deepEqual(read(file),{x:1});
        fs.chmodSync(f.directory,0o755);assert.throws(()=>save(path.join(f.directory,'two.json'),{x:1}));
    }finally{fs.rmSync(f.directory,{recursive:true,force:true});}
});
test('test fixture covers 6596 distinct random commitments and has no research input',()=>{
    const {makeData}=require('../check-network');const first=makeData(),second=makeData();
    assert.equal(first.publication.officers.length,6596);assert.notEqual(first.publication.batch_publication_id,second.publication.batch_publication_id);
    assert.equal(new Set(first.publication.officers.map(r=>r.publication_id)).size,6596);
    assert.equal(first.metadata.public_payload_sha256,require('../../chaincode/lib/evidence').sha(first.publication));
});
