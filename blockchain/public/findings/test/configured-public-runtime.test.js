'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {loadLocalRuntime}=require('../configured-public-runtime'),{setup}=require('./configured-public-runtime-fixture');
const N=require('../network'),{runJob}=require('../findings-public-backend-worker');
test('configured private wallet signs exact transaction; pinned HTTPS views use actual mTLS',async t=>{
    const x=await setup(t),r=loadLocalRuntime(x.options());t.after(()=>r.close());
    assert.equal(await r.rpcs[0].call('eth_chainId',[]),'0xaa36a7');
    assert.equal(await r.rpcs[1].call('eth_chainId',[]),'0xaa36a7');
    assert.equal(r.wallet.address.toLowerCase(),x.evm.destination.writer);
    assert.equal(x.state.httpRequests,2);assert.equal(r.fixture_transport,true);
    await assert.rejects(async()=>r.rpcs[1].call('eth_sendRawTransaction',['0x00']),/cannot broadcast/);
    await assert.rejects(async()=>r.rpcs[0].call('personal_unlockAccount',[]),/Allowed findings/);
    assert.equal(x.state.httpRequests,2);
});
for(const fault of ['live-url','duplicate-listener','wrong-policy','writer','config-pin','wallet-pin','wallet-reuse','file-mode','symlink','hardlink'])
test('configured runtime refuses '+fault+' before any RPC',async t=>{
    const x=await setup(t);
    if(fault==='live-url')x.change(c=>c.providers[0].connect_url='https://public.example/rpc');
    if(fault==='duplicate-listener')x.change(c=>c.providers[1].connect_url=c.providers[0].connect_url);
    if(fault==='wrong-policy')x.change(c=>c.policy='LIVE');
    if(fault==='writer')x.change(c=>c.writer='0x'+'11'.repeat(20));
    if(fault==='wallet-pin')x.change(c=>c.wallet_sha256='0'.repeat(64));
    if(fault==='wallet-reuse'){fs.copyFileSync(x.c.wallet_file,x.job.recoveryKeyFile);}
    if(fault==='file-mode')fs.chmodSync(x.file,0o644);
    if(fault==='symlink'){fs.renameSync(x.c.wallet_file,x.c.wallet_file+'.old');fs.symlinkSync(x.c.wallet_file+'.old',x.c.wallet_file);}
    if(fault==='hardlink')fs.linkSync(x.c.wallet_file,x.c.wallet_file+'.link');
    const opts=x.options();if(fault==='config-pin')opts.sha256='0'.repeat(64);
    assert.throws(()=>loadLocalRuntime(opts));assert.equal(x.state.httpRequests,0);
});
for(const fault of ['server-pin','ca','client'])test('real HTTPS refuses '+fault+' without delivering RPC',async t=>{
    const x=await setup(t);x.change(c=>{
        if(fault==='server-pin')c.providers[0].server_certificate_sha256='0'.repeat(64);
        if(fault==='ca'){c.providers[0].ca_file=path.join(x.tls.root,'server.pem');c.providers[0].ca_sha256=require('node:crypto').createHash('sha256').update(x.tls.read('server.pem')).digest('hex');}
        if(fault==='client')for(const k of ['certificate','key']){const p=c.providers[0];p['client_'+k+'_file']=path.join(x.tls.root,'other.'+(k==='key'?'key':'pem'));
            p['client_'+k+'_sha256']=require('node:crypto').createHash('sha256').update(fs.readFileSync(p['client_'+k+'_file'])).digest('hex');}
    });
    const r=loadLocalRuntime(x.options());t.after(()=>r.close());await assert.rejects(r.rpcs[0].call('eth_chainId',[]));
    assert.equal(x.state.requests.length,0);
});
for(const fault of ['id','duplicate','json','extra','redirect','encoding','oversize','timeout'])
test('configured HTTPS rejects '+fault+' with one request and no retry',async t=>{
    const x=await setup(t);x.change(c=>c.timeout_ms=300);const r=loadLocalRuntime(x.options());t.after(()=>r.close());
    x.state.fault=fault;const start=Date.now();await assert.rejects(r.rpcs[0].call('eth_chainId',[]));
    assert.equal(x.state.requests.length,1);assert.ok(Date.now()-start<2000);
});
test('runtime file drift and close prevent further calls and signing',async t=>{
    const x=await setup(t),r=loadLocalRuntime(x.options());fs.appendFileSync(x.file,'\n');
    assert.throws(()=>r.rpcs[0].call('eth_chainId',[]),/changed/);await assert.rejects(r.wallet.signTransaction({}),/changed/);
    assert.equal(x.state.httpRequests,0);r.close();assert.throws(()=>r.rpcs[0].call('eth_chainId',[]),/closed/);
});
test('configured runner executes real HTTPS/EVM with witness barrier and reconciles original bytes',async t=>{
    const x=await setup(t);const original=x.evm.rpcs[0].call.bind(x.evm.rpcs[0]);
    x.evm.rpcs[0].call=async(m,p)=>{if(m==='eth_sendRawTransaction')assert.equal((await x.witness.read()).snapshot.stages.at(-1).stage,'attempt');return original(m,p);};
    const actions=[];const run=()=>runJob(x.job,async(a,s)=>{actions.push(a);return s;},job=>loadLocalRuntime({...x.options(),job}));
    const result=await run();assert.equal(result.status,'ISOLATED_PUBLIC_VERIFIED');assert.equal(result.public_transport_enabled,false);
    assert.ok(actions.includes('SIGN')&&actions.includes('SUBMIT'));assert.equal(x.evm.state.broadcasts,1);
    const bytes=x.f.inventory();x.job.mode='RECONCILE';x.job.approval=x.f.grant('RECONCILE');
    assert.deepEqual((await run()).receipt,result.receipt);assert.deepEqual(x.f.inventory(),bytes);assert.equal(x.evm.state.broadcasts,1);
});
// Positive execution uses the actual Python private-pipe transport and the fixed
// configured Node main. The source/Fabric callback below is explicitly a double.
async function pythonBridge(x,deny=null){
    const {spawn}=require('node:child_process');
    const repo=path.resolve(__dirname,'../../../..'),backend=path.join(repo,'backend');
    const python=process.env.PPI_TEST_PYTHON||(process.env.VIRTUAL_ENV?path.join(process.env.VIRTUAL_ENV,'bin/python'):'python3');
    const script=`import json,sys\nfrom app.identity.findings_backend_service import _exchange\nv=json.load(sys.stdin)\nactions=[]\ndef guard(a,s,m):\n actions.append(a)\n if a==v['deny']:raise ValueError('TEST_SOURCE_DENIED')\n return s\ntry:\n r=_exchange(v['command'],v['job'],guard,timeout=60)\n print(json.dumps({'ok':True,'result':r,'actions':actions}))\nexcept Exception as e:print(json.dumps({'ok':False,'error':str(e),'actions':actions}))\n`;
    const command=[process.execPath,require.resolve('../configured-public-backend-worker'),x.file,x.options().sha256];
    const child=spawn(python,['-c',script],{cwd:backend,env:{...process.env,PYTHONPATH:backend},stdio:['pipe','pipe','pipe']});
    let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);
    child.stdin.end(JSON.stringify({command,job:x.job,deny}));
    const code=await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',resolve);});
    assert.equal(code,0,stderr);return JSON.parse(stdout);
}
test('actual Python-to-configured-Node private pipe succeeds and restart remains read-only',async t=>{
    const x=await setup(t),first=await pythonBridge(x);assert.equal(first.ok,true,first.error);
    assert.equal(first.result.status,'ISOLATED_PUBLIC_VERIFIED');assert.ok(first.actions.includes('VERIFIED'));
    assert.equal(x.evm.state.broadcasts,1);const bytes=x.f.inventory();
    x.job.mode='RECONCILE';x.job.approval=x.f.grant('RECONCILE');const second=await pythonBridge(x);
    assert.equal(second.ok,true,second.error);assert.deepEqual(second.result.receipt,first.result.receipt);
    assert.deepEqual(x.f.inventory(),bytes);assert.equal(x.evm.state.broadcasts,1);
});
for(const action of ['SIGN','SUBMIT','ACK'])test('actual Python denial at '+action+' retains recoverable original history',async t=>{
    const x=await setup(t),result=await pythonBridge(x,action);assert.equal(result.ok,false);assert.match(result.error,/TEST_SOURCE_DENIED/);
    assert.equal(fs.existsSync(path.join(x.f.directory,'.gateway-lock')),false);
    assert.equal(x.evm.state.broadcasts,action==='ACK'?1:0);
    if(action!=='SIGN'){
        const bytes=x.f.inventory();x.job.mode='RECONCILE';x.job.approval=x.f.grant('RECONCILE');const recovered=await pythonBridge(x);
        assert.equal(recovered.ok,true,recovered.error);assert.equal(recovered.result.status,action==='ACK'?'ISOLATED_PUBLIC_VERIFIED':'PENDING');
        assert.deepEqual(x.f.inventory(),bytes);assert.equal(x.evm.state.broadcasts,action==='ACK'?1:0);
    }
});
test('lost local HTTPS acknowledgement recovers original transaction without broadcast retry',async t=>{
    const x=await setup(t);x.evm.state.throwAfter=true;const result=await pythonBridge(x);assert.equal(result.ok,false);
    assert.equal(x.evm.state.broadcasts,1);const bytes=x.f.inventory();x.job.mode='RECONCILE';x.job.approval=x.f.grant('RECONCILE');
    const recovered=await pythonBridge(x);assert.equal(recovered.ok,true,recovered.error);assert.equal(recovered.result.status,'ISOLATED_PUBLIC_VERIFIED');
    assert.deepEqual(x.f.inventory(),bytes);assert.equal(x.evm.state.broadcasts,1);
});
