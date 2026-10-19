'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {fixture}=require('./public-adapter-fixture'),{fixture:tlsFixture}=require('../../../fabric/client/test/recovery-witness-tls-fixture');
const {runProtectedLoaded,POLICY}=require('../witnessed-public-runner'),N=require('../network'),H=require('../../../fabric/client/recovery-witness-https');
async function setup(t,existing=null,fault=null){
 const f=existing||fixture();t.after(()=>f.close());const tls=tlsFixture(t);
 const binding={policy:'FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1',operation:N.sha({policy:POLICY,selection:f.selection}),selection_sha256:N.sha(f.selection)};
 tls.service.provision(binding);let server=tls.server;
 if(fault){const real=tls.service.transport.call;server=H.createHttpsServer({...tls.serverOptions,service:{policy:H.POLICY,transport:{async call(q){
 const stop=q.body.action==='ADVANCE'&&q.body.snapshot.stages.at(-1).stage==='attempt'&&fault.enabled;
 if(stop&&!fault.after)throw new Error('BEFORE_COMMIT');const r=await real(q);if(stop&&fault.after)throw new Error('AFTER_COMMIT');return r;
 }}}});}
 const endpoint=await tls.listen(server),recoveryProtection=tls.client(endpoint,{binding});
 return {f,tls,server,recoveryProtection,run:(mode='EXECUTE',changes={})=>runProtectedLoaded({...f.options(mode),recoveryProtection,...changes})};
}
test('public protected runner confirms a real HTTPS witness attempt before broadcasting to local EVM',async t=>{
 const {localEvm}=require('../integration/local-evm'),evm=await localEvm();t.after(()=>evm.close());
 const f=fixture();f.selection.destination=evm.destination;f.selection.network_config_sha256=N.sha(evm.config);
 const {run,recoveryProtection}=await setup(t,f),options={config:evm.config,rpcs:evm.rpcs,wallet:evm.wallet};
 const call=evm.rpcs[0].call.bind(evm.rpcs[0]);evm.rpcs[0].call=async(method,args)=>{if(method==='eth_sendRawTransaction')assert.ok((await recoveryProtection.read()).snapshot.stages.some(x=>x.stage==='attempt'));return call(method,args);};
 const result=await run('EXECUTE',options);assert.equal(result.status,'ISOLATED_PUBLIC_VERIFIED');assert.equal(result.recovery_witness_transport,'MTLS');assert.equal(result.recovery_witness_fixture,false);assert.equal(result.live_chain_verification,false);
 const before=f.inventory();assert.deepEqual((await run('RECONCILE',options)).receipt,result.receipt);assert.deepEqual(f.inventory(),before);
 for(const name of fs.readdirSync(f.directory))fs.unlinkSync(path.join(f.directory,name));await assert.rejects(run('EXECUTE',options),/rollback/);assert.equal(evm.state.broadcasts,1);assert.equal(evm.state.signs,1);
});
for(const after of [false,true])test('HTTPS attempt failure '+(after?'after':'before')+' commit blocks public broadcast and replacement',async t=>{
 const fault={enabled:true,after},{f,run,recoveryProtection}=await setup(t,null,fault);
 await assert.rejects(run());assert.equal(f.state.broadcasts.length,0);assert.equal(f.state.signs,1);
 fault.enabled=false;if(!after)await assert.rejects(run('RECONCILE'),/unconfirmed/);
 assert.equal((await run()).status,'PENDING');assert.equal(f.state.broadcasts.length,0);assert.equal(f.state.signs,1);assert.equal((await recoveryProtection.read()).sequence,3);
});
test('HTTPS witness unavailable stops public runner before transaction signing',async t=>{
 const {f,run,server}=await setup(t);server.closeAllConnections();await new Promise(r=>server.close(r));
 await assert.rejects(run());assert.equal(f.state.signs,0);assert.equal(f.state.broadcasts.length,0);assert.deepEqual(f.inventory(),[]);
});
