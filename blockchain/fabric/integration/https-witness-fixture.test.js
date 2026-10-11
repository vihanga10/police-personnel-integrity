'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {httpsAuthority}=require('./recovery-witness-https-fixture'),{createWitnessedRetention}=require('../client/witnessed-retention');
const binding=n=>({policy:'FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1',operation:String(n).repeat(64),selection_sha256:'a'.repeat(64)});
const stages=n=>({stages:['intent','plan','attempt','ack','final'].slice(0,n).map((stage,i)=>({stage,sha256:String(i+2).repeat(64)}))});
async function setup(t){const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'ppi-https-peer-fixture-'));fs.chmodSync(root,0o700);const repo=path.join(root,'repo');fs.mkdirSync(repo,{mode:0o700});let authority;
 t.after(async()=>{try{if(authority)await authority.close();}finally{fs.rmSync(root,{recursive:true,force:true});}});authority=await httpsAuthority(root,'fabric-https-witness',repo);return {root,repo,authority};}
test('child authenticates HTTPS, explicit admin provisions, and five checkpoints persist',async t=>{
 const {authority}=await setup(t);assert.notEqual(authority.pid(),process.pid);assert.deepEqual(authority.provisioned(),[]);const client=authority(binding(1));let current=await client.read();for(let n=1;n<=5;n++)current=await client.advance(current,stages(n));assert.equal(current.sequence,5);assert.equal(client.secure_witness,true);assert.equal(client.fixture_witness,false);assert.equal(authority.provisioned().length,1);
});
for(const after of [false,true])test('IPC injects HTTPS failure '+(after?'after':'before')+' commit',async t=>{
 const {authority}=await setup(t),b=binding(1),client=authority(b),previous=await client.read();await authority.failNext(b,'intent',after);await assert.rejects(client.advance(previous,stages(1)),/HTTP request refused/);assert.equal((await client.read()).sequence,after?1:0);const result=await client.advance(previous,stages(1));assert.equal(result.sequence,1);assert.deepEqual(await client.advance(previous,stages(1)),result);
});
test('fresh child restart preserves same authoritative checkpoint without reset',async t=>{
 const {authority}=await setup(t),client=authority(binding(1)),current=await client.advance(await client.read(),stages(1)),pid=authority.pid();await authority.restart();assert.notEqual(authority.pid(),pid);assert.deepEqual(await client.read(),current);assert.equal(authority.provisioned().length,1);
});
test('outage never falls back and restart reads original tip',async t=>{
 const {authority}=await setup(t),client=authority(binding(1)),current=await client.advance(await client.read(),stages(1));await authority.stop();await assert.rejects(client.read());await authority.start();assert.deepEqual(await client.read(),current);
});
test('CA-valid denied TLS identity cannot read a provisioned checkpoint',async t=>{
 const {authority}=await setup(t),b=binding(1),client=authority(b),before=await client.read();await assert.rejects(authority.deniedClient(b).read());assert.deepEqual(await client.read(),before);
});
test('IPC failure selects one operation without changing another',async t=>{
 const {authority}=await setup(t),b=binding(1),a=authority(b),c=authority(binding(2));await authority.failNext(b,'intent');await c.advance(await c.read(),stages(1));await assert.rejects(a.advance(await a.read(),stages(1)));assert.equal((await c.read()).sequence,1);assert.equal((await a.read()).sequence,0);
});
test('Fabric and public child witnesses keep separate authoritative tips',async t=>{
 const {root,repo,authority}=await setup(t),other=await httpsAuthority(root,'public-https-witness',repo);t.after(()=>other.close());const b=binding(1),a=authority(b),c=other(b);assert.notEqual(authority.pid(),other.pid());await a.advance(await a.read(),stages(1));assert.equal((await c.read()).sequence,0);assert.equal((await a.read()).sequence,1);
});
test('process witness rejects whole-directory rollback of retained attempt',async t=>{
 const {root,repo,authority}=await setup(t),b=binding(1),client=authority(b),directory=path.join(root,'retained');fs.mkdirSync(directory,{mode:0o700});const options={directory,repo,binding:b,key:crypto.randomBytes(32),recoveryProtection:client},store=createWitnessedRetention(options);await store.session(async()=>{for(const stage of ['intent','plan','attempt'])await store.save(stage,{opaque:stage});});store.close();await authority.restart();assert.equal((await client.read()).sequence,3);for(const n of fs.readdirSync(directory))fs.unlinkSync(path.join(directory,n));const restored=createWitnessedRetention(options);try{await assert.rejects(restored.session(()=>assert.fail('NO SUBMISSION')),/rollback/);}finally{restored.close();}
});
test('fixture close stops owned child and refuses reuse',async t=>{
 const {authority}=await setup(t),client=authority(binding(1));await authority.close();assert.equal(authority.pid(),undefined);assert.throws(()=>authority(binding(1)),/closed/);await assert.rejects(client.read());
});
