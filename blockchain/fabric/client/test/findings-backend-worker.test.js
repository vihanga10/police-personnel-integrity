'use strict';
// No SDK connection, credentials, ledger or witness provisioning in these tests.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {runJob}=require('../findings-backend-worker');
const {canonical}=require('../../findings-chaincode/lib/findings');
const R=require('../witnessed-findings-gateway');
const vector=require('../../findings-chaincode/test/commitment-vector.json');
function setup(){
    const key=crypto.generateKeyPairSync('ed25519');
    const selection={private_sha256:'1'.repeat(64),public_sha256:vector.payload.public_sha256,
        history_sha256:'2'.repeat(64),code_revision:'3'.repeat(40),gateway_config_sha256:'4'.repeat(64),
        destination:{genesis_sha256:'5'.repeat(64),channel:'personnel',chaincode:'findings-anchor-v1',
            namespace:'findings-anchor-v1',organizations:['Org1MSP','Org2MSP']},payload:structuredClone(vector.payload)};
    const body={policy:R.POLICY,key_id:'backend',mode:'RECONCILE',issued_at:new Date(Date.now()-1000).toISOString(),
        expires_at:new Date(Date.now()+60000).toISOString(),selection};
    return {selection,mode:'RECONCILE',approval:{body,signature:crypto.sign(null,Buffer.from(canonical(body)),key.privateKey).toString('base64')},
        trustedKeys:{backend:key.publicKey.export({type:'spki',format:'pem'})},repo:'/nonexistent-repo',
        gatewayConfigFile:'/nonexistent-gateway',witnessConfigFile:'/nonexistent-witness',witnessConfigSha256:'6'.repeat(64),
        directory:'/nonexistent-recovery',recoveryKeyFile:'/nonexistent-key'};
}
test('bad signature stops before backend callback or credential reads',async()=>{
    const job=setup();job.approval.signature=Buffer.alloc(64).toString('base64');let calls=0;
    await assert.rejects(runJob(job,async()=>{calls++;}),/signature invalid/);assert.equal(calls,0);
});
test('backend denial stops before any credential read or SDK load',async()=>{
    let calls=0;await assert.rejects(runJob(setup(),async()=>{calls++;throw new Error('SOURCE_REPLAY_DENIED');}),/SOURCE_REPLAY_DENIED/);
    assert.equal(calls,1);
});
test('backend selection mismatch cannot pass the entry boundary',async()=>{
    await assert.rejects(runJob(setup(),async()=>({})),/entry verification differs/);
});
test('only exact worker schema and known modes accepted',async()=>{
    await assert.rejects(runJob({...setup(),fixture_transport:true},async()=>{}),/schema differs/);
    const job=setup();job.mode='PUBLIC_EXECUTE';await assert.rejects(runJob(job,async()=>{}),/mode differs/);
});
test('successful source check still requires configured private key file',async()=>{
    const job=setup();let calls=0;
    await assert.rejects(runJob(job,async()=>{calls++;return job.selection;}));assert.equal(calls,1);
});
test('worker composes confirmed mTLS retention and preserves read-only recovery (SDK adapter double)',async t=>{
    const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),Module=require('node:module');
    const {sha}=require('../../findings-chaincode/lib/findings');
    const {POLICY:RETENTION}=require('../findings-retention');
    const {httpsAuthority}=require('../../integration/recovery-witness-https-fixture');
    const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'backend-worker-'));fs.chmodSync(root,0o700);
    const job=setup();job.repo=path.join(root,'repo');fs.mkdirSync(job.repo,{mode:0o700});
    job.directory=path.join(root,'retention');fs.mkdirSync(job.directory,{mode:0o700});
    job.recoveryKeyFile=path.join(root,'retention.key');fs.writeFileSync(job.recoveryKeyFile,crypto.randomBytes(32),{mode:0o600});
    job.mode='EXECUTE';job.approval.body.mode='EXECUTE';
    const signer=crypto.generateKeyPairSync('ed25519');job.trustedKeys={backend:signer.publicKey.export({type:'spki',format:'pem'})};
    const sign=mode=>{const body={...job.approval.body,mode};return {body,signature:crypto.sign(null,Buffer.from(canonical(body)),signer.privateKey).toString('base64')};};
    job.approval=sign('EXECUTE');
    const authority=await httpsAuthority(root,'fabric-https-witness',job.repo);
    t.after(async()=>{await authority.close();fs.rmSync(root,{recursive:true,force:true});});
    const binding={policy:RETENTION,operation:sha({policy:R.POLICY,selection:job.selection}),selection_sha256:sha(job.selection)};
    const witness=authority(binding);
    job.witnessConfigFile=path.join(root,'fabric-https-witness/backend/config.json');
    job.witnessConfigSha256=crypto.createHash('sha256').update(fs.readFileSync(job.witnessConfigFile)).digest('hex');
    const counts={endorse:0,submit:0},actions=[],transaction='a'.repeat(64);
    const fakeConnect=options=>({
        prepare:async operation=>{counts.endorse++;const plan={operation,transaction_id:transaction};await options.retention.save(operation,plan);return plan;},
        validatePlan:()=>{},submit:async()=>{const tip=await witness.read();assert.equal(tip.snapshot.stages.at(-1).stage,'attempt');counts.submit++;return {transaction_id:transaction};},
        observeCommitted:async()=>({status:'FINAL',destination:job.selection.destination,payload:job.selection.payload,transaction_id:transaction,
            verification:{validation_code:'VALID',organizations:['Org1MSP','Org2MSP'],block_sha256:'b'.repeat(64)}}),close:()=>{}});
    const filename=require.resolve('../findings-backend-worker'),original=Module._load;
    Module._load=function(id,parent,...rest){
        if(parent?.filename===filename){
            if(id==='./findings-gateway')return {...require('../findings-gateway'),connectFindings:fakeConnect};
            if(id.startsWith('../integration/node_modules/'))return {};
        }
        return original.call(this,id,parent,...rest);
    };
    delete require.cache[filename];
    try{
        const worker=require('../findings-backend-worker');
        const guard=async(action,s,mode)=>{actions.push(action);assert.deepEqual(s,job.selection);assert.equal(mode,job.mode);return s;};
        const result=await worker.runJob(job,guard);assert.equal(result.recovery_witness_transport,'MTLS');assert.equal(result.recovery_witness_fixture,false);
        assert.deepEqual(counts,{endorse:1,submit:1});assert.ok(actions.includes('BEFORE_SUBMIT'));
        const before=fs.readdirSync(job.directory).sort().map(n=>[n,fs.readFileSync(path.join(job.directory,n)).toString('hex')]);
        job.mode='RECONCILE';job.approval=sign('RECONCILE');await worker.runJob(job,guard);
        assert.deepEqual(counts,{endorse:1,submit:1});
        assert.deepEqual(fs.readdirSync(job.directory).sort().map(n=>[n,fs.readFileSync(path.join(job.directory,n)).toString('hex')]),before);
    }finally{Module._load=original;delete require.cache[filename];}
});
