'use strict';
// Backend callbacks are explicit source doubles. Local EVM/mTLS are actual;
// public consensus finality and provider independence remain simulated.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {fixture}=require('./public-adapter-fixture'),N=require('../network');
const {runJob}=require('../findings-public-backend-worker');
const {httpsAuthority}=require('../../../fabric/integration/recovery-witness-https-fixture');
function jobFor(f){return {selection:structuredClone(f.selection),mode:'EXECUTE',approval:f.grant('EXECUTE'),trustedKeys:f.trustedKeys,
    repo:f.repo,networkConfigFile:'/unused-network',witnessConfigFile:'/unused-witness',witnessConfigSha256:'f'.repeat(64),
    directory:f.directory,recoveryKeyFile:'/unused-key'};}
for(const kind of ['signature','source','selection','runtime','schema','mode'])test('public backend rejects '+kind+' before credentials or signing',async()=>{
    const f=fixture();try{
        const job=jobFor(f);let loads=0;
        const guard=async(a,s)=>{if(kind==='source')throw new Error('SOURCE_DENIED');if(kind==='selection')return {};return s;};
        let loader=async()=>{loads++;return {fixture_transport:false,rpcs:[]};};
        if(kind==='signature')job.approval.signature=Buffer.alloc(64).toString('base64');
        if(kind==='runtime')loader=undefined;
        if(kind==='schema')job.rpcUrls=['https://live.example'];
        if(kind==='mode')job.mode='LIVE';
        if(kind==='runtime')await assert.rejects(runJob(job,guard),/Public runtime is not provisioned/);
        else await assert.rejects(runJob(job,guard,loader));assert.equal(f.state.signs,0);assert.equal(f.state.broadcasts.length,0);
        if(kind!=='runtime')assert.equal(loads,0);
    }finally{f.close();}
});
async function setup(t,useEvm=false){
    const f=fixture();let evm;
    if(useEvm){evm=await require('../integration/local-evm').localEvm();f.selection.destination=evm.destination;
        f.selection.network_config_sha256=N.sha(evm.config);}
    const authority=await httpsAuthority(f.parent,'public-https-witness',f.repo);
    t.after(async()=>{await authority.close();if(evm)await evm.close();f.close();});
    const binding={policy:'FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1',operation:N.sha({policy:'PROTECTED_FINDINGS_PUBLIC_FIXTURE_V1',selection:f.selection}),selection_sha256:N.sha(f.selection)};
    const witness=authority(binding),job=jobFor(f);
    job.witnessConfigFile=path.join(f.parent,'public-https-witness/backend/config.json');
    job.witnessConfigSha256=crypto.createHash('sha256').update(fs.readFileSync(job.witnessConfigFile)).digest('hex');
    job.networkConfigFile=path.join(f.parent,'network.json');fs.writeFileSync(job.networkConfigFile,N.canonical(evm?evm.config:f.config),{mode:0o600});
    job.recoveryKeyFile=path.join(f.parent,'public.key');fs.writeFileSync(job.recoveryKeyFile,f.key,{mode:0o600});
    const transport={fixture_transport:true,rpcs:evm?evm.rpcs:f.rpcs,wallet:evm?evm.wallet:f.wallet};
    const actions=[];
    const run=(mode='EXECUTE',deny=null)=>{job.mode=mode;job.approval=f.grant(mode);return runJob(job,async(a,s,m)=>{
        actions.push(a);assert.deepEqual(s,f.selection);assert.equal(m,mode);if(a===deny)throw new Error('SOURCE_DENIED');return s;
    },async()=>transport);};
    return {f,evm,authority,witness,job,transport,run,actions};
}
test('real local EVM public backend uses mTLS attempt barrier and preserves read-only history',async t=>{
    const {f,evm,witness,run,actions}=await setup(t,true);
    const original=evm.rpcs[0].call.bind(evm.rpcs[0]);evm.rpcs[0].call=async(m,p)=>{
        if(m==='eth_sendRawTransaction')assert.equal((await witness.read()).snapshot.stages.at(-1).stage,'attempt');return original(m,p);
    };
    const result=await run();assert.equal(result.status,'ISOLATED_PUBLIC_VERIFIED');assert.equal(result.backend_public_runtime,'FIXTURE_ONLY');
    assert.equal(result.public_transport_enabled,false);assert.equal(result.live_chain_verification,false);assert.equal(result.recovery_witness_transport,'MTLS');
    assert.ok(actions.includes('SIGN')&&actions.includes('SUBMIT')&&actions.includes('VERIFIED'));
    const bytes=f.inventory();assert.deepEqual((await run('RECONCILE')).receipt,result.receipt);assert.deepEqual(f.inventory(),bytes);
    assert.equal(evm.state.broadcasts,1);assert.equal(evm.state.signs,1);
});
for(const action of ['SIGN','SUBMIT','ACK'])test('public backend source denial at '+action+' preserves original recovery stages',async t=>{
    const {f,run}=await setup(t);await assert.rejects(run('EXECUTE',action),/SOURCE_DENIED/);
    assert.equal(fs.existsSync(path.join(f.directory,'.gateway-lock')),false);
    if(action==='SIGN'){assert.equal(f.state.signs,0);assert.equal(f.state.broadcasts.length,0);}
    else if(action==='SUBMIT'){
        assert.equal(f.state.signs,1);assert.equal(f.state.broadcasts.length,0);const bytes=f.inventory();
        assert.equal((await run('RECONCILE')).status,'PENDING');assert.deepEqual(f.inventory(),bytes);assert.equal(f.state.broadcasts.length,0);
    }else{
        assert.equal(f.state.broadcasts.length,1);const bytes=f.inventory();
        assert.equal((await run('RECONCILE')).status,'ISOLATED_PUBLIC_VERIFIED');assert.deepEqual(f.inventory(),bytes);assert.equal(f.state.broadcasts.length,1);
    }
});
test('public network file drift stops before signing',async t=>{
    const {f,job,run}=await setup(t);fs.appendFileSync(job.networkConfigFile,'\n');
    await assert.rejects(run(),/canonical public network/);assert.equal(f.state.signs,0);assert.deepEqual(f.inventory(),[]);
});
test('HTTPS witness outage blocks public signing with no fallback',async t=>{
    const {f,authority,run}=await setup(t);await authority.stop();
    await assert.rejects(run());assert.equal(f.state.signs,0);assert.equal(f.state.broadcasts.length,0);assert.deepEqual(f.inventory(),[]);
});

test('request transport dictionaries cannot enable a live runtime',async()=>{
    const f=fixture();try{let signed=false;
        await assert.rejects(runJob(jobFor(f),async(a,s)=>s,async()=>({fixture_transport:false,rpcs:f.rpcs,
            wallet:{signTransaction:async()=>{signed=true;}}})),/Only isolated public runtime/);
        assert.equal(signed,false);assert.deepEqual(f.inventory(),[]);
    }finally{f.close();}
});
for(const kind of ['unprovisioned','denied','wrong-id','eof'])test('actual public worker private pipe fails closed: '+kind,{timeout:10000},async t=>{
    const {spawn}=require('node:child_process'),readline=require('node:readline');
    const f=fixture();t.after(()=>f.close());
    const child=spawn(process.execPath,[require.resolve('../findings-public-backend-worker')],{stdio:['pipe','pipe','pipe']});
    t.after(()=>child.kill('SIGKILL'));let stderr='';child.stderr.on('data',v=>stderr+=v);
    const exit=new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',resolve);});
    const messages=[];readline.createInterface({input:child.stdout}).on('line',line=>{
        const m=JSON.parse(line);messages.push(m);
        if(m.kind!=='guard')return;
        assert.equal(m.action,'ENTRY');
        if(kind==='eof')child.stdin.end();
        else if(kind==='unprovisioned')child.stdin.write(N.canonical({kind:'approved',id:m.id,selection:m.selection})+'\n');
        else child.stdin.write(N.canonical({kind:'denied',id:m.id+(kind==='wrong-id'?1:0)})+'\n');
    });
    child.stdin.write(N.canonical({kind:'start',job:jobFor(f)})+'\n');
    assert.equal(await exit,1);assert.equal(stderr,'');assert.equal(messages[0].kind,'guard');
    assert.ok(messages.every(m=>m.kind!=='result'));assert.deepEqual(f.inventory(),[]);
});
