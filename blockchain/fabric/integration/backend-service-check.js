'use strict';
// Real Python service + private pipes + real Node worker/SDK; source replay fixture.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {spawn}=require('node:child_process');
const {canonical,sha}=require('../findings-chaincode/lib/findings');
const {createRetention}=require('../client/findings-retention');
const POLICY='PPI_BACKEND_SERVICE_PEERS_V1';
async function checks({root,scope,payload,grant,trustedKeys,configFile,witnessFor,witnessForSelection,evalPeer}){
    const complete=[],fixtures=[];
    function session(){
        const directory=path.join(root,'backend-case-'+fixtures.length);fs.mkdirSync(directory,{mode:0o700});
        const recovery=path.join(directory,'retention');fs.mkdirSync(recovery,{mode:0o700});
        const keyFile=path.join(directory,'retention.key');fs.writeFileSync(keyFile,crypto.randomBytes(32),{mode:0o600});
        const s=scope(payload());witnessForSelection(s);
        const file=path.join(root,'fabric-https-witness/backend/config.json');
        const job={selection:s,approval:grant(s,'EXECUTE'),trustedKeys,mode:'EXECUTE',repo:'/work/fabric',
            gatewayConfigFile:configFile,witnessConfigFile:file,witnessConfigSha256:crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),
            directory:recovery,recoveryKeyFile:keyFile};
        const item={job,directory,recovery,keyFile};fixtures.push(item);return item;
    }
    async function run(item,mode='EXECUTE',deny_action=null,approval=null){
        const job={...item.job,mode,approval:approval||grant(item.job.selection,mode)};
        const file=path.join(item.directory,'request-'+crypto.randomBytes(8).toString('hex')+'.json');
        fs.writeFileSync(file,canonical({policy:'PPI_BACKEND_SERVICE_FIXTURE_V1',job,deny_action}),{mode:0o600});
        try{const response=await new Promise((resolve,reject)=>{
            const child=spawn('python3',['/work/fabric/integration/backend-service-fixture.py',file],
                {env:{PATH:process.env.PATH,PPI_TEST_ROOT:root,LANG:'C.UTF-8'},stdio:['ignore','pipe','pipe']});
            let stdout='',stderr='';const timer=setTimeout(()=>child.kill('SIGKILL'),135000);
            child.stdout.on('data',b=>{stdout+=b;if(stdout.length>1048576)child.kill('SIGKILL');});
            child.stderr.on('data',b=>{stderr+=b;if(stderr.length>8192)stderr=stderr.slice(-8192);});
            child.on('error',e=>{clearTimeout(timer);reject(e);});
            child.on('close',code=>{clearTimeout(timer);if(code!==0)return reject(new Error('Fixture Python driver stopped: '+stderr));
                try{resolve(JSON.parse(stdout));}catch(e){reject(e);}});
        });
            assert.equal(response.full_source_replay_simulated,true);
            if(deny_action){assert.equal(response.ok,false);assert.equal(response.guards.at(-1),deny_action);assert.equal(response.error_type,'ValueError');}
            return response;
        }finally{fs.unlinkSync(file);}
    }
    const inventory=item=>fs.readdirSync(item.recovery).sort().map(n=>[n,fs.readFileSync(path.join(item.recovery,n)).toString('hex')]);
    const ledger=async()=>Promise.all([1,2].map(async n=>Buffer.from(await evalPeer(n,'qscc','GetChainInfo',['personnel'])).toString('hex')));
    function plan(item){const s=item.job.selection,store=createRetention({directory:item.recovery,repo:'/work/fabric',key:fs.readFileSync(item.keyFile),
        binding:{policy:'FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1',operation:sha({policy:'PROTECTED_FINDINGS_GATEWAY_BRIDGE_V1',selection:s}),selection_sha256:sha(s)}});
        try{return store.read('plan');}finally{store.close();}}
    const done=name=>{complete.push(name);console.log('Backend bridge check '+complete.length+'/11:',name);};
    const first=session(),initial=await run(first);assert.equal(initial.ok,true,'Backend diagnostic: '+JSON.stringify(initial));assert.equal(initial.full_source_replay_simulated,true);
    assert.equal(initial.result.receipt.verification.validation_code,'VALID');assert.equal(initial.result.recovery_witness_transport,'MTLS');
    assert.ok(initial.guards.includes('BEFORE_SUBMIT'));assert.equal(plan(first).transaction_id,initial.result.receipt.transaction_id);
    done('actual Python service/private pipe/SDK worker submits and verifies original VALID transaction');
    const before=inventory(first),head=await ledger(),again=await run(first,'RECONCILE');assert.equal(again.ok,true);
    assert.equal(again.result.receipt.transaction_id,initial.result.receipt.transaction_id);assert.deepEqual(inventory(first),before);assert.deepEqual(await ledger(),head);
    done('fresh Python/Node processes reconcile original ID without recovery or ledger writes');
    const bad=session(),wrong=grant(bad.job.selection,'EXECUTE');wrong.signature=Buffer.alloc(64).toString('base64');
    const prior=await ledger();assert.equal((await run(bad,'EXECUTE',null,wrong)).ok,false);assert.deepEqual(inventory(bad),[]);assert.deepEqual(await ledger(),prior);
    done('invalid signed backend approval stops before transaction retention or ledger write');
    const entry=session();assert.equal((await run(entry,'EXECUTE','ENTRY')).ok,false);assert.deepEqual(inventory(entry),[]);
    done('source fixture denial at entry stops actual backend service before worker');
    const prepared=session(),priorPrepare=await ledger();assert.equal((await run(prepared,'EXECUTE','BEFORE_ATTEMPT')).ok,false);
    assert.deepEqual(fs.readdirSync(prepared.recovery).sort(),['intent.encrypted.json','plan.encrypted.json']);assert.deepEqual(await ledger(),priorPrepare);
    const originalPlan=plan(prepared),resumed=await run(prepared);assert.equal(resumed.ok,true);assert.equal(resumed.result.receipt.transaction_id,originalPlan.transaction_id);
    done('interruption before attempt resumes same real endorsed plan under fresh approval');
    const attempted=session(),priorAttempt=await ledger();assert.equal((await run(attempted,'EXECUTE','BEFORE_SUBMIT')).ok,false);
    assert.deepEqual(fs.readdirSync(attempted.recovery).sort(),['attempt.encrypted.json','intent.encrypted.json','plan.encrypted.json']);
    assert.equal((await witnessForSelection(attempted.job.selection).read()).sequence,3);assert.deepEqual(await ledger(),priorAttempt);
    const attemptBytes=inventory(attempted);assert.equal((await run(attempted,'RECONCILE')).ok,false);
    assert.deepEqual(inventory(attempted),attemptBytes);assert.deepEqual(await ledger(),priorAttempt);
    done('confirmed attempt followed by source denial never broadcasts on read-only recovery');
    const final=session();assert.equal((await run(final,'EXECUTE','FINAL')).ok,false);
    assert.deepEqual(fs.readdirSync(final.recovery).sort(),['ack.encrypted.json','attempt.encrypted.json','intent.encrypted.json','plan.encrypted.json']);
    const finalBytes=inventory(final),finalHead=await ledger(),read=await run(final,'RECONCILE');assert.equal(read.ok,true);
    assert.equal(read.result.receipt.transaction_id,plan(final).transaction_id);assert.deepEqual(inventory(final),finalBytes);assert.deepEqual(await ledger(),finalHead);
    done('interruption after actual submission/ack recovers original committed ID without writes');
    const ack=session();assert.equal((await run(ack,'EXECUTE','ACK')).ok,false);
    assert.deepEqual(fs.readdirSync(ack.recovery).sort(),['attempt.encrypted.json','intent.encrypted.json','plan.encrypted.json']);
    const ackBytes=inventory(ack),ackRead=await run(ack,'RECONCILE');assert.equal(ackRead.ok,true);
    assert.equal(ackRead.result.receipt.transaction_id,plan(ack).transaction_id);assert.deepEqual(inventory(ack),ackBytes);
    // Submission acknowledgement precedes ordering/commit. Observe the original
    // VALID transaction first, then compare heads around a second read-only run.
    const ackHead=await ledger();assert.equal((await run(ack,'RECONCILE')).ok,true);
    assert.deepEqual(inventory(ack),ackBytes);assert.deepEqual(await ledger(),ackHead);
    done('lost backend acknowledgement after real submission reconciles original ID without rebroadcast');
    const recoveryHead=await ledger();
    for(const [name]of before)fs.unlinkSync(path.join(first.recovery,name));
    assert.equal((await run(first,'RECONCILE')).ok,false);assert.deepEqual(inventory(first),[]);assert.deepEqual(await ledger(),recoveryHead);
    for(const [name,hex]of before)fs.writeFileSync(path.join(first.recovery,name),Buffer.from(hex,'hex'),{mode:0o600});
    done('whole local recovery rollback rejected against actual HTTPS authoritative tip');
    await witnessFor.stop();try{assert.equal((await run(first,'RECONCILE')).ok,false);assert.deepEqual(inventory(first),before);}finally{await witnessFor.start();}
    assert.equal((await run(first,'RECONCILE')).ok,true);assert.deepEqual(await ledger(),recoveryHead);
    done('HTTPS outage has no fallback and restart preserves original transaction');
    const readonly=session();assert.equal((await run(readonly,'RECONCILE')).ok,false);assert.deepEqual(inventory(readonly),[]);assert.deepEqual(await ledger(),recoveryHead);
    done('read-only missing intent cannot create a new endorsement, attempt or publication');
    return {policy:POLICY,checks:complete.length,checks_completed:complete,actual_python_service:true,actual_node_worker:true,
        actual_fabric_sdk:true,actual_fabric_peers:true,https_witness_transport:true,full_source_replay_simulated:true,
        independent_witness_deployment_verified:false,live_research_ready:false,research_records_used:0};
}
module.exports={checks,POLICY};
