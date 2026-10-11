'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {fixture}=require('./public-adapter-fixture'),{runProtectedLoaded,POLICY}=require('../witnessed-public-runner');
const W=require('../../../fabric/client/recovery-witness'),N=require('../network');
function setup(t,existing=null){
    const f=existing||fixture();t.after(()=>f.close());const authority=path.join(f.parent,'authority');fs.mkdirSync(authority,{mode:0o700});
    const backend=crypto.generateKeyPairSync('ed25519'),serviceKey=crypto.generateKeyPairSync('ed25519'),pem=(k,p=false)=>k.export({type:p?'pkcs8':'spki',format:'pem'});
    const binding={policy:'FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1',operation:N.sha({policy:POLICY,selection:f.selection}),selection_sha256:N.sha(f.selection)};
    const service=W.createWitnessService({directory:authority,privateKey:pem(serviceKey.privateKey,true),writerPublicKey:pem(backend.publicKey)});service.provision(binding);const fault={stage:null,after:false};
    const transport={...service.transport,async call(q){const fail=q.body.action==='ADVANCE'&&q.body.snapshot.stages.at(-1).stage===fault.stage;if(fail&&!fault.after)throw new Error('WITNESS_UNAVAILABLE');const r=await service.transport.call(q);if(q.body.action==='READ'&&fault.delayRead)await new Promise(resolve=>setTimeout(resolve,fault.delayRead));if(fail&&fault.after)throw new Error('WITNESS_ACK_LOST');return r;}};
    const recoveryProtection=W.createWitnessClient({transport,privateKey:pem(backend.privateKey,true),witnessPublicKey:service.publicKey,binding});
    return {f,fault,recoveryProtection,run:(mode='EXECUTE',changes={})=>runProtectedLoaded({...f.options(mode),recoveryProtection,...changes})};
}
test('witnessed public runner confirms attempt before broadcast and preserves read-only bytes',async t=>{
    const {f,run,recoveryProtection}=setup(t),call=f.rpcs[0].call.bind(f.rpcs[0]);f.rpcs[0].call=async(method,args)=>{if(method==='eth_sendRawTransaction')assert.ok((await recoveryProtection.read()).snapshot.stages.some(x=>x.stage==='attempt'));return call(method,args);};
    const r=await run();assert.equal(r.recovery_witness_fixture,true);const before=f.inventory();assert.deepEqual((await run('RECONCILE')).receipt,r.receipt);assert.deepEqual(f.inventory(),before);assert.equal(f.state.broadcasts.length,1);assert.equal(f.state.signs,1);
});
for(const after of [false,true])test('public attempt witness failure '+(after?'after':'before')+' commit prevents transmission',async t=>{
    const {f,run,fault}=setup(t);fault.stage='attempt';fault.after=after;await assert.rejects(run(),/WITNESS_/);assert.equal(f.state.broadcasts.length,0);assert.equal(f.state.signs,1);fault.stage=null;
    if(!after)await assert.rejects(run('RECONCILE'),/unconfirmed/);assert.equal((await run()).status,'PENDING');assert.equal(f.state.broadcasts.length,0);assert.equal(f.state.signs,1);
});
for(const stage of ['intent','plan','attempt'])test('public rollback after '+stage+' stops before further signing or sending',async t=>{
    const {f,run}=setup(t);f.state.interrupt=p=>{if(p==='AFTER_'+stage.toUpperCase())throw new Error('CAPTURE');};await assert.rejects(run(),/CAPTURE/);const before=f.inventory();f.state.interrupt=null;
    if(stage==='attempt'){// Durable attempt prohibits transmission even before rollback.
        assert.equal((await run()).status,'PENDING');assert.equal(f.state.broadcasts.length,0);
        // Delete a known attempt to model restoring the earlier plan-only backup.
        fs.unlinkSync(path.join(f.directory,'attempt.encrypted.json'));
    }else{await run();for(const name of fs.readdirSync(f.directory))fs.unlinkSync(path.join(f.directory,name));for(const [name,hex]of before)fs.writeFileSync(path.join(f.directory,name),Buffer.from(hex,'hex'),{mode:0o600});}
    const count=f.state.signs,sends=f.state.broadcasts.length;await assert.rejects(run(),/rollback/);await assert.rejects(run('RECONCILE'),/rollback/);assert.equal(f.state.signs,count);assert.equal(f.state.broadcasts.length,sends);
});
test('witness required, no fallback to legacy retention',async t=>{const {f}=setup(t);await assert.rejects(runProtectedLoaded(f.options()),/Mandatory/);assert.equal(f.state.signs,0);assert.deepEqual(f.inventory(),[]);});
test('mandatory witnessed runner verifies a real local EVM publication and detects later whole-directory rollback',async t=>{
    const {localEvm}=require('../integration/local-evm'),evm=await localEvm();t.after(()=>evm.close());const f=fixture();
    f.selection.destination=evm.destination;f.selection.network_config_sha256=N.sha(evm.config);
    const {run,recoveryProtection}=setup(t,f),options={config:evm.config,rpcs:evm.rpcs,wallet:evm.wallet};
    const result=await run('EXECUTE',options);assert.equal(result.status,'ISOLATED_PUBLIC_VERIFIED');assert.equal(result.recovery_witness_fixture,true);assert.equal((await recoveryProtection.read()).sequence,5);
    const before=f.inventory();assert.deepEqual((await run('RECONCILE',options)).receipt,result.receipt);assert.deepEqual(f.inventory(),before);
    for(const name of fs.readdirSync(f.directory))fs.unlinkSync(path.join(f.directory,name));await assert.rejects(run('EXECUTE',options),/rollback/);assert.equal(evm.state.broadcasts,1);assert.equal(evm.state.signs,1);
});
test('expired approval cannot repair an interrupted local checkpoint after an asynchronous witness read',async t=>{
    const {f,run,fault,recoveryProtection}=setup(t);fault.stage='plan';await assert.rejects(run(),/WITNESS_/);fault.stage=null;assert.equal((await recoveryProtection.read()).sequence,1);
    const now=Date.now(),approval=f.grant('EXECUTE',{issued_at:new Date(now-1).toISOString(),expires_at:new Date(now+20).toISOString()});fault.delayRead=50;
    await assert.rejects(run('EXECUTE',{approval}),/Fresh public approval/);fault.delayRead=0;assert.equal((await recoveryProtection.read()).sequence,1);assert.equal(f.state.broadcasts.length,0);assert.equal(f.state.signs,1);
});
