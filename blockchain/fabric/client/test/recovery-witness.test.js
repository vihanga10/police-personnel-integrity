'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const W=require('../recovery-witness'),{createWitnessedRetention}=require('../witnessed-retention');
const {canonical,sha}=require('../../findings-chaincode/lib/findings');
const R='FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1';
const pem=(k,privateKey=false)=>k.export({type:privateKey?'pkcs8':'spki',format:'pem'});
function fixture(t){
    const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'ppi-witness-'));fs.chmodSync(root,0o700);const directory=path.join(root,'retention'),authority=path.join(root,'authority'),repo=path.join(root,'repo');for(const p of [directory,authority,repo])fs.mkdirSync(p,{mode:0o700});t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
    const backend=crypto.generateKeyPairSync('ed25519'),serviceKey=crypto.generateKeyPairSync('ed25519'),binding={policy:R,operation:'a'.repeat(64),selection_sha256:'b'.repeat(64)},key=crypto.randomBytes(32);
    const service=W.createWitnessService({directory:authority,privateKey:pem(serviceKey.privateKey,true),writerPublicKey:pem(backend.publicKey)});
    const client=(transport=service.transport,changes={})=>W.createWitnessClient({transport,privateKey:pem(backend.privateKey,true),witnessPublicKey:service.publicKey,binding,...changes});
    const store=(readOnly=false,recoveryProtection=client())=>createWitnessedRetention({directory,repo,key,binding,readOnly,recoveryProtection});
    const provision=()=>service.provision(binding);
    return {root,directory,authority,repo,backend,serviceKey,binding,key,service,client,store,provision};
}
async function using(s,fn){try{return await s.session(()=>fn(s));}finally{s.close();}}
function bytes(dir){return Object.fromEntries(fs.readdirSync(dir).filter(n=>n!=='.gateway-lock').sort().map(n=>[n,fs.readFileSync(path.join(dir,n)).toString('hex')]));}
function restore(dir,data){for(const n of fs.readdirSync(dir))fs.unlinkSync(path.join(dir,n));for(const [n,b]of Object.entries(data))fs.writeFileSync(path.join(dir,n),Buffer.from(b,'hex'),{mode:0o600});}

test('provision separately, append immutable signed checkpoints, restart and read-only verification',async t=>{
    const f=fixture(t);f.provision();await using(f.store(),async s=>{await s.save('intent',{a:1});await s.save('plan',{transaction:'opaque fixture'});await s.save('attempt',{id:'opaque fixture'});await s.save('final',{verified:true});await s.save('final',{verified:true});});
    const tip=await f.client().read();assert.equal(tip.sequence,4);assert.equal(tip.snapshot.stages.length,4);
    const before=bytes(f.directory);await using(f.store(true),s=>s.check());assert.deepEqual(bytes(f.directory),before);
    assert.throws(()=>f.provision(),/reset forbidden/);
    const records=fs.readdirSync(path.join(f.authority,sha(f.binding))).map(n=>fs.readFileSync(path.join(f.authority,sha(f.binding),n),'utf8')).join('');assert.ok(!records.includes('opaque fixture'));assert.ok(!records.includes('"a":1'));
});
test('unprovisioned witness never enrolls or permits a local write',async t=>{const f=fixture(t);await assert.rejects(using(f.store(),s=>s.save('intent',{a:1})),/not provisioned/);assert.deepEqual(bytes(f.directory),{});});
for(const stage of ['empty','intent','plan','attempt'])test('restored valid older '+stage+' inventory fails before any new work',async t=>{
    const f=fixture(t);f.provision();let old;
    await using(f.store(),async s=>{if(stage==='empty')old=bytes(f.directory);for(const n of ['intent','plan','attempt','ack','final']){await s.save(n,{stage:n});if(stage===n)old=bytes(f.directory);}});
    restore(f.directory,old);await assert.rejects(using(f.store(),()=>{throw new Error('MUST NOT ENTER');}),/rollback/);await assert.rejects(using(f.store(true),()=>{throw new Error('MUST NOT ENTER');}),/rollback/);
});
test('lost witness acknowledgement after commit is recovered from a fresh challenge, without a new local write',async t=>{
    const f=fixture(t);f.provision();let lost=true;const transport={...f.service.transport,async call(q){const r=await f.service.transport.call(q);if(q.body.action==='ADVANCE'&&lost){lost=false;throw new Error('ACK_LOST');}return r;}};
    await assert.rejects(using(f.store(false,f.client(transport)),s=>s.save('intent',{a:1})),/ACK_LOST/);
    const before=bytes(f.directory);await using(f.store(true),s=>s.check());assert.deepEqual(bytes(f.directory),before);assert.equal((await f.client().read()).sequence,1);
});
test('interrupted local write before witness delivery blocks read-only and repairs once in writable recovery',async t=>{
    const f=fixture(t);f.provision();let fail=true;const transport={...f.service.transport,async call(q){if(q.body.action==='ADVANCE'&&fail){fail=false;throw new Error('BEFORE_DELIVERY');}return f.service.transport.call(q);}};
    await assert.rejects(using(f.store(false,f.client(transport)),s=>s.save('intent',{a:1})),/BEFORE_DELIVERY/);
    const before=bytes(f.directory);await assert.rejects(using(f.store(true),s=>s.check()),/unconfirmed/);await using(f.store(),s=>s.check());assert.deepEqual(bytes(f.directory),before);assert.equal((await f.client().read()).sequence,1);
});
test('lag of multiple stages cannot be adopted',async t=>{
    const f=fixture(t);f.provision();const local=require('../findings-retention').createRetention({directory:f.directory,repo:f.repo,key:f.key,binding:f.binding});await using(local,async s=>{s.save('intent',{a:1});s.save('plan',{b:2});});await assert.rejects(using(f.store(),()=>{}),/divergence/);
});
test('fresh nonce rejects captured signed old witness reply',async t=>{
    const f=fixture(t);f.provision();let captured;const transport={...f.service.transport,async call(q){if(captured)return captured;captured=await f.service.transport.call(q);return captured;}};const c=f.client(transport);await c.read();await assert.rejects(c.read(),/Fresh bound/);
});
test('wrong service key and unauthorized backend requests fail',async t=>{
    const f=fixture(t);f.provision();const rogue=crypto.generateKeyPairSync('ed25519');await assert.rejects(f.client(undefined,{witnessPublicKey:pem(rogue.publicKey)}).read(),/signature/);await assert.rejects(f.client(undefined,{privateKey:pem(rogue.privateKey,true)}).read(),/signature/);
});
test('binding mismatch and storage overlap are rejected before entry',t=>{
    const f=fixture(t);f.provision();assert.throws(()=>f.store(false,{...f.client(),binding:{...f.binding,operation:'c'.repeat(64)}}),/bound recovery/);assert.throws(()=>f.store(false,{...f.client(),authority_directory:f.directory}),/Separate witness/);assert.throws(()=>f.store(false,null),/Mandatory/);
});
test('stale compare-and-swap cannot remove, change or append over a newer checkpoint',async t=>{
    const f=fixture(t);f.provision();const c=f.client(),old=await c.read(),first={stages:[{stage:'intent',sha256:'1'.repeat(64)}]};const next=await c.advance(old,first);assert.deepEqual(await c.advance(old,first),next);
    await assert.rejects(c.advance(old,{stages:[{stage:'intent',sha256:'2'.repeat(64)}]}),/compare-and-swap/);
    await assert.rejects(c.advance(next,{stages:[]}),/append-only/);await assert.rejects(c.advance(next,{stages:[{stage:'intent',sha256:'2'.repeat(64)},{stage:'plan',sha256:'3'.repeat(64)}]}),/append-only/);
});
for(const problem of ['tamper','missing','extra','mode','link'])test('authority history rejects '+problem,async t=>{
    const f=fixture(t);f.provision();await using(f.store(),s=>s.save('intent',{a:1}));const dir=path.join(f.authority,sha(f.binding)),file=path.join(dir,'01.json');
    if(problem==='tamper'){const e=JSON.parse(fs.readFileSync(file));e.body.snapshot.stages[0].sha256='f'.repeat(64);fs.writeFileSync(file,canonical(e));}
    if(problem==='missing')fs.unlinkSync(path.join(dir,'00.json'));if(problem==='extra')fs.writeFileSync(path.join(dir,'extra'),'x',{mode:0o600});if(problem==='mode')fs.chmodSync(file,0o644);if(problem==='link')fs.linkSync(file,path.join(f.root,'linked'));
    await assert.rejects(f.client().read());
});
test('authority write lock blocks competing writers, never removed by failed caller',async t=>{
    const f=fixture(t);f.provision();const old=await f.client().read(),lock=path.join(f.authority,'.witness-lock');fs.mkdirSync(lock,{mode:0o700});await assert.rejects(f.client().advance(old,{stages:[{stage:'intent',sha256:'1'.repeat(64)}]}));assert.ok(fs.existsSync(lock));fs.rmdirSync(lock);
});

test('durable authority survives a fresh Node process reopening the same checkpoint history',async t=>{
    const f=fixture(t);f.provision();await using(f.store(),s=>s.save('intent',{a:1}));const expected=await f.client().read();
    const script="const fs=require('node:fs'),W=require(process.argv[1]);const q=JSON.parse(fs.readFileSync(0,'utf8'));const s=W.createWitnessService(q.options);process.stdout.write(JSON.stringify(s.latest(q.binding)));";
    const result=require('node:child_process').spawnSync(process.execPath,['-e',script,require.resolve('../recovery-witness')],{input:JSON.stringify({options:{directory:f.authority,privateKey:pem(f.serviceKey.privateKey,true),writerPublicKey:pem(f.backend.publicKey)},binding:f.binding}),encoding:'utf8',timeout:10000});
    assert.equal(result.status,0,result.stderr);assert.deepEqual(JSON.parse(result.stdout),expected);
});
test('transport hang is bounded and cannot permit a local write',async t=>{
    const f=fixture(t);f.provision();const transport={...f.service.transport,call:async()=>new Promise(()=>{})},c=f.client(transport,{timeoutMs:50});await assert.rejects(using(f.store(false,c),s=>s.save('intent',{a:1})),/timeout/);assert.deepEqual(bytes(f.directory),{});
});
test('signed stale, malformed and cross-operation replies are rejected',async t=>{
    const f=fixture(t);f.provision();for(const mutate of [r=>{r.issued_at=Date.now()-60000;},r=>{r.binding.operation='f'.repeat(64);},r=>{r.checkpoint.sequence=42;},r=>{r.extra='unexpected';}]){
        const transport={...f.service.transport,async call(q){const e=await f.service.transport.call(q);mutate(e.body);return W.sign(e.body,f.serviceKey.privateKey);}};await assert.rejects(f.client(transport).read());
    }
});
test('final checkpoint is terminal even when its optional acknowledgement is absent',async t=>{
    const f=fixture(t);f.provision();await using(f.store(),async s=>{for(const stage of ['intent','plan','attempt','final'])await s.save(stage,{stage});});const c=f.client(),old=await c.read(),next=structuredClone(old.snapshot);next.stages.splice(3,0,{stage:'ack',sha256:'1'.repeat(64)});await assert.rejects(c.advance(old,next),/append-only/);
});
test('a lookalike client cannot replace the authenticated client capability',t=>{const f=fixture(t);f.provision();assert.throws(()=>f.store(false,{...f.client()}),/Authenticated witness client/);});
