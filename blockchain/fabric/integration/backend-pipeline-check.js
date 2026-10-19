'use strict';
// Real coordinator/services/private pipes/peers/HTTPS/EVM. Source replay is the
// explicitly declared isolated Python substitute, not research readiness.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {spawn}=require('node:child_process');
const N=require('../../public/findings/network'),{setup}=require('./backend-pipeline-runtime');
const POLICY='PPI_ISOLATED_BACKEND_PIPELINE_V1';
async function checks({root,scope,payload,grant,trustedKeys,configFile,witnessFor,witnessForSelection,evalPeer}){
    const cleanup=[];const t={after:fn=>cleanup.push(fn)};const completed=[];
    const runtime=await setup(t,root),authority=runtime.authority;
    const key=crypto.generateKeyPairSync('ed25519'),publicKeys={fixture:key.publicKey.export({type:'spki',format:'pem'})};
    const h=b=>crypto.createHash('sha256').update(b).digest('hex');
    const done=name=>{completed.push(name);console.log('Pipeline check '+completed.length+'/9:',name);};
    function publicGrant(s,mode){const now=Date.now(),body={policy:'PROTECTED_FINDINGS_PUBLIC_FIXTURE_V1',key_id:'fixture',mode,
        issued_at:new Date(now-1000).toISOString(),expires_at:new Date(now+599000).toISOString(),selection:s};
        return {body,signature:crypto.sign(null,Buffer.from(N.canonical(body)),key.privateKey).toString('base64')};}
    let index=0;
    const inventory=dir=>fs.readdirSync(dir).sort().map(n=>[n,h(fs.readFileSync(path.join(dir,n)))]);
    const heads=async()=>Promise.all([1,2].map(async n=>Buffer.from(await evalPeer(n,'qscc','GetChainInfo',['personnel'])).toString('hex')));
    function session(){
        const directory=path.join(root,'pipeline-case-'+(++index));fs.mkdirSync(directory,{mode:0o700});
        const write=(n,b)=>{const f=path.join(directory,n);fs.writeFileSync(f,b,{mode:0o600});return f;};
        const fabricDir=path.join(directory,'fabric'),publicDir=path.join(directory,'public');
        for(const p of [fabricDir,publicDir])fs.mkdirSync(p,{mode:0o700});
        const s=scope(payload());witnessForSelection(s);
        const witnessFile=path.join(root,'fabric-https-witness/backend/config.json');
        const job={repo:'/work/pipeline',mode:'EXECUTE',selection:s,trustedKeys,
            gatewayConfigFile:configFile,witnessConfigFile:witnessFile,witnessConfigSha256:h(fs.readFileSync(witnessFile)),
            directory:fabricDir,recoveryKeyFile:write('fabric.key',crypto.randomBytes(32))};
        const publicOptions={node_binary:'/usr/local/bin/node',network_config_file:runtime.networkFile,
            witness_config_file:path.join(runtime.f.parent,'public-https-witness/backend/config.json'),
            witness_config_sha256:h(fs.readFileSync(path.join(runtime.f.parent,'public-https-witness/backend/config.json'))),
            recovery_directory:publicDir,recovery_key_file:write('public.key',crypto.randomBytes(32)),timeout:300,
            runtime_config_file:runtime.file,runtime_config_sha256:h(fs.readFileSync(runtime.file))};
        return {directory,job,publicOptions,publicDir,fabricDir,selection:null};
    }
    async function run(item,phase,mode='EXECUTE',extra={}){
        const request={policy:'PPI_BACKEND_PIPELINE_FIXTURE_V1',phase,mode,fabric_job:item.job,
            fabric_approval:grant(item.job.selection,mode),fabric_read_approval:grant(item.job.selection,'RECONCILE'),
            public_options:item.publicOptions,public_config:runtime.evm.config,public_destination:runtime.evm.destination,
            public_trusted_keys:publicKeys,public_selection:item.selection,public_approval:item.selection?publicGrant(item.selection,mode):null,...extra};
        const file=path.join(item.directory,'request-'+crypto.randomBytes(8).toString('hex')+'.json');fs.writeFileSync(file,N.canonical(request),{mode:0o600});
        try{return await new Promise((resolve,reject)=>{
            const child=spawn('python3',['/work/fabric/integration/backend-pipeline-fixture.py',file],
                {env:{PATH:process.env.PATH,PPI_TEST_ROOT:root,LANG:'C.UTF-8'},stdio:['ignore','pipe','pipe']});
            let output='',errors='';const timer=setTimeout(()=>child.kill('SIGKILL'),420000);
            child.stdout.on('data',b=>{output+=b;if(output.length>1048576)child.kill('SIGKILL');});
            child.stderr.on('data',b=>errors=(errors+b).slice(-8000));child.on('error',e=>{clearTimeout(timer);reject(e);});
            child.on('close',code=>{clearTimeout(timer);if(code!==0)return reject(new Error('Pipeline test driver stopped: '+errors));
                try{const v=JSON.parse(output);assert.equal(v.full_source_replay_simulated,true);resolve(v);}catch(e){reject(e);}});
        });}finally{fs.unlinkSync(file);}
    }
    async function prepare(item){
        const f=await run(item,'fabric');assert.equal(f.ok,true,f.error_message);
        const p=await run(item,'public-plan');assert.equal(p.ok,true,p.error_message);item.selection=p.result;
        assert.deepEqual(item.selection.fabric_receipt,f.result.receipt);
        authority({policy:'FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1',operation:N.sha({policy:'PROTECTED_FINDINGS_PUBLIC_FIXTURE_V1',selection:item.selection}),selection_sha256:N.sha(item.selection)});
        return f;
    }
    try{
        const first=session(),fabric=await prepare(first),result=await run(first,'public-run');assert.equal(result.ok,true,result.error_message);
        assert.equal(result.result.status,'ISOLATED_PIPELINE_VERIFIED');assert.deepEqual(result.result.fabric_receipt,fabric.result.receipt);
        assert.equal(result.result.public_result.recovery_witness_transport,'MTLS');assert.equal(result.result.live_research_ready,false);
        done('coordinator connects fresh Fabric receipt to actual Python/Node HTTPS public execution');
        const bytes=inventory(first.publicDir),fb=inventory(first.fabricDir),head=await heads(),broadcasts=runtime.evm.state.broadcasts;
        const restart=await run(first,'public-run','RECONCILE');assert.equal(restart.ok,true,restart.error_message);
        assert.deepEqual(restart.result.public_result.receipt,result.result.public_result.receipt);
        assert.deepEqual(inventory(first.publicDir),bytes);assert.deepEqual(inventory(first.fabricDir),fb);
        assert.deepEqual(await heads(),head);assert.equal(runtime.evm.state.broadcasts,broadcasts);
        done('new Python/Node processes reconcile both original transactions without storage or ledger writes');
        const invalid=publicGrant(first.selection,'EXECUTE');invalid.signature=Buffer.alloc(64).toString('base64');
        const rejected=await run(first,'public-run','EXECUTE',{public_approval:invalid});assert.equal(rejected.ok,false);
        assert.deepEqual(inventory(first.publicDir),bytes);assert.equal(runtime.evm.state.broadcasts,broadcasts);
        done('invalid public approval cannot advance verified Fabric receipt to another submission');
        for(const action of ['SIGN','SUBMIT','ACK']){
            const item=session();await prepare(item);const prior=runtime.evm.state.broadcasts;
            const denied=await run(item,'public-run','EXECUTE',{deny_action:action});assert.equal(denied.ok,false,action);
            assert.match(denied.error_message,/FIXTURE_SOURCE_DENIED/);
            assert.equal(runtime.evm.state.broadcasts,prior+(action==='ACK'?1:0));
            if(action!=='SIGN'){
                const old=inventory(item.publicDir),recovered=await run(item,'public-run','RECONCILE');assert.equal(recovered.ok,true,recovered.error_message);
                assert.equal(recovered.result.status,action==='ACK'?'ISOLATED_PIPELINE_VERIFIED':'PENDING');assert.deepEqual(inventory(item.publicDir),old);
                assert.equal(runtime.evm.state.broadcasts,prior+(action==='ACK'?1:0));
            }
            done('cross-service source denial at '+action+' preserves original recovery lineage');
        }
        const lost=session();await prepare(lost);runtime.evm.state.throwAfter=true;
        const count=runtime.evm.state.broadcasts;assert.equal((await run(lost,'public-run')).ok,false);runtime.evm.state.throwAfter=false;
        const original=inventory(lost.publicDir),recovered=await run(lost,'public-run','RECONCILE');assert.equal(recovered.ok,true,recovered.error_message);
        assert.equal(recovered.result.status,'ISOLATED_PIPELINE_VERIFIED');assert.deepEqual(inventory(lost.publicDir),original);assert.equal(runtime.evm.state.broadcasts,count+1);
        done('lost original public acknowledgement recovers through fresh Fabric verification with no retry');
        const prior=runtime.evm.state.broadcasts;await witnessFor.stop();
        try{assert.equal((await run(first,'public-run','RECONCILE')).ok,false);}finally{await witnessFor.start();}
        assert.equal(runtime.evm.state.broadcasts,prior);assert.deepEqual(inventory(first.publicDir),bytes);
        done('Fabric HTTPS witness outage blocks public progression without fallback');
        const old=inventory(first.publicDir);for(const name of fs.readdirSync(first.publicDir))fs.unlinkSync(path.join(first.publicDir,name));
        const rollback=await run(first,'public-run','RECONCILE');assert.equal(rollback.ok,false);assert.deepEqual(inventory(first.publicDir),[]);
        assert.equal(runtime.evm.state.broadcasts,prior);
        done('public recovery directory rollback rejected against HTTPS witness before any replacement');
        assert.equal(completed.length,9);
        return {policy:POLICY,checks:9,checks_completed:completed,actual_python_coordinator:true,actual_python_services:true,
            actual_node_workers:true,actual_fabric_sdk:true,actual_fabric_peers:true,actual_local_evm:true,https_rpc_transport:true,
            https_witness_transport:true,full_source_replay_simulated:true,public_finality_simulated:true,
            provider_independence_verified:false,independent_witness_deployment_verified:false,live_research_ready:false,research_records_used:0};
    }finally{for(const fn of cleanup.reverse())await fn();}
}
module.exports={checks,POLICY};
