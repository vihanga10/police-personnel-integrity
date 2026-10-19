'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),https=require('node:https');
const W=require('../recovery-witness'),H=require('../recovery-witness-https'),A=require('../recovery-witness-service');
const {canonical,sha}=require('../../findings-chaincode/lib/findings');
const {createWitnessedRetention}=require('../witnessed-retention');
const {fixture}=require('./recovery-witness-tls-fixture');
const next=(n)=>({stages:['intent','plan','attempt','ack','final'].slice(0,n).map((stage,i)=>({stage,sha256:String(i+3).repeat(64)}))});
function grant(f,changes={}) { return W.sign({policy:H.POLICY,action:'READ',binding:f.binding,nonce:crypto.randomBytes(32).toString('hex'),issued_at:Date.now(),expected_sha256:null,snapshot:null,...changes},f.pem(f.backend.privateKey,true)); }
function bytes(dir){return Object.fromEntries(fs.readdirSync(dir).map(n=>[n,fs.readFileSync(path.join(dir,n)).toString('hex')]));}

test('real TLS 1.3 mutual authentication and signed append-only checkpoints, exact retry and restart',async t=>{
 const f=fixture(t);f.service.provision(f.binding);const endpoint=await f.listen(),client=f.client(endpoint);
 assert.equal(client.secure_witness,true);assert.equal(client.fixture_witness,false);
 let protocols=[];f.server.on('secureConnection',socket=>protocols.push(socket.getProtocol()));let c=await client.read();assert.equal(c.policy,H.POLICY);assert.deepEqual(protocols,['TLSv1.3']);
 for(let i=1;i<=5;i++){const previous=c;c=await client.advance(c,next(i));assert.deepEqual(await client.advance(previous,next(i)),c);}
 const restarted=W.createWitnessService({directory:f.authority,privateKey:f.pem(f.signing.privateKey,true),writerPublicKey:f.pem(f.backend.publicKey),policy:H.POLICY});
 assert.deepEqual(restarted.latest(f.binding),c);const before=bytes(path.join(f.authority,sha(f.binding)));assert.deepEqual(await client.read(),c);assert.deepEqual(bytes(path.join(f.authority,sha(f.binding))),before);
});
test('HTTPS never enrolls an unknown operation',async t=>{const f=fixture(t),e=await f.listen();await assert.rejects(f.client(e).read());assert.deepEqual(fs.readdirSync(f.authority),[]);});
for(const fault of ['pin','hostname','ca','client','application-key','witness-key','scope'])test('real HTTPS rejects '+fault,async t=>{
 const f=fixture(t);f.service.provision(f.binding);const endpoint=await f.listen();let options={},changes={};
 if(fault==='pin')options.server_certificate_sha256='0'.repeat(64);
 if(fault==='hostname'){const alternate=H.createHttpsServer(f.serverOptions);options.endpoint=(await f.listen(alternate,'0.0.0.0')).replace('127.0.0.1','127.0.0.2');}
 if(fault==='ca')options.ca=f.read('other.pem');
 if(fault==='client'){options.cert=f.read('other.pem');options.key=f.read('other.key');}
 if(fault==='application-key')changes.privateKey=f.pem(crypto.generateKeyPairSync('ed25519').privateKey,true);
 if(fault==='witness-key')changes.witnessPublicKey=f.pem(crypto.generateKeyPairSync('ed25519').publicKey);
 if(fault==='scope')changes.binding={...f.binding,operation:'9'.repeat(64)};
 const transport=f.transport(endpoint,options),c=W.createWitnessClient({transport,binding:f.binding,privateKey:f.pem(f.backend.privateKey,true),witnessPublicKey:f.service.publicKey,...changes});
 await assert.rejects(c.read());assert.equal(f.service.latest(f.binding).sequence,0);
});
for(const fault of ['stale','signature','policy','malformed','extra','noncanonical'])test('HTTPS rejects application message '+fault,async t=>{
 const f=fixture(t);f.service.provision(f.binding);const e=await f.listen();let q=grant(f);
 if(fault==='stale')q=grant(f,{issued_at:Date.now()-60000});
 if(fault==='signature')q.signature=Buffer.alloc(64).toString('base64');
 if(fault==='policy')q=grant(f,{policy:W.POLICY});
 if(fault==='extra')q.body.nic='PRIVATE';
 if(fault==='malformed')q={body:null,signature:q.signature};
 if(fault==='noncanonical'){
  await new Promise(resolve=>{const req=https.request(e,{method:'POST',ca:f.read('ca.pem'),cert:f.read('client.pem'),key:f.read('client.key'),headers:{'content-type':'application/json','content-length':Buffer.byteLength(JSON.stringify(q,null,2))}},res=>{assert.equal(res.statusCode,503);res.resume();res.on('end',resolve);});req.end(JSON.stringify(q,null,2));});
 }else await assert.rejects(f.transport(e).call(q));
 assert.equal(f.service.latest(f.binding).sequence,0);
});
test('lost HTTPS acknowledgement after durable commit reconciles original checkpoint, without downgrade',async t=>{
 const f=fixture(t);f.service.provision(f.binding);const real=f.service.transport.call;
 // Test-only wrapper changes response delivery, not client authentication.
 let lose=true;const service={policy:H.POLICY,transport:{async call(q){const r=await real(q);if(lose&&q.body.action==='ADVANCE'){lose=false;throw new Error('ACK_LOST');}return r;}}};
 const server=H.createHttpsServer({...f.serverOptions,service}),e=await f.listen(server),c=f.client(e),old=await c.read();
 await assert.rejects(c.advance(old,next(1)));assert.equal(f.service.latest(f.binding).sequence,1);
 const observed=await c.read();assert.deepEqual(await c.advance(old,next(1)),observed);
 await assert.rejects(c.advance(old,{stages:[{stage:'intent',sha256:'f'.repeat(64)}]}));assert.equal(f.service.latest(f.binding).sequence,1);
});
test('secure retention confirms attempt over HTTPS and refuses a restored empty directory',async t=>{
 const f=fixture(t);f.service.provision(f.binding);const endpoint=await f.listen(),client=f.client(endpoint);
 const repo=path.join(f.root,'repo'),directory=path.join(f.root,'retained');for(const p of [repo,directory])fs.mkdirSync(p,{mode:0o700});
 const options={repo,directory,key:crypto.randomBytes(32),binding:f.binding,recoveryProtection:client};
 const store=createWitnessedRetention(options);
 await store.session(async()=>{for(const stage of ['intent','plan','attempt'])await store.save(stage,{opaque:stage});});store.close();
 assert.equal((await client.read()).sequence,3);
 for(const n of fs.readdirSync(directory))fs.unlinkSync(path.join(directory,n));
 const reopened=createWitnessedRetention(options);await assert.rejects(reopened.session(()=>assert.fail('MUST NOT SUBMIT')),/rollback/);reopened.close();
});
test('real HTTPS deadline after sent request is bounded and never retried',async t=>{
 const f=fixture(t);f.service.provision(f.binding);let calls=0;
 const service={policy:H.POLICY,transport:{call:()=>{calls++;return new Promise(()=>{});}}};
 const s=H.createHttpsServer({...f.serverOptions,service}),e=await f.listen(s),transport=f.transport(e,{timeout_ms:100});
 const start=Date.now();await assert.rejects(transport.call(grant(f)));assert.ok(Date.now()-start<2000);assert.equal(calls,1);
});
for(const fault of ['redirect','oversize','bad-json','encoding','wrong-length','unsigned'])test('client rejects HTTP response '+fault,async t=>{
 const f=fixture(t);const s=https.createServer({ca:f.read('ca.pem'),cert:f.read('server.pem'),key:f.read('server.key'),requestCert:true,rejectUnauthorized:true},(req,res)=>{
 req.resume();req.on('end',()=>{let body=Buffer.from('{}'),status=200,headers={'content-type':'application/json'};
 if(fault==='redirect'){status=307;headers.location='https://example.invalid/';}
 if(fault==='oversize')body=Buffer.alloc(40000,120);
 if(fault==='bad-json')body=Buffer.from('no');
 if(fault==='encoding')headers['content-encoding']='gzip';
 headers['content-length']=body.length+(fault==='wrong-length'?5:0);res.writeHead(status,headers);res.end(body);});
 });const e=await f.listen(s);await assert.rejects(f.client(e).read());
});
for(const fault of ['http','userinfo','query','hash','route','trailing','timeout','key-mismatch','accessor','lookalike'])test('secure factory refuses '+fault,async t=>{
 const f=fixture(t);let options={endpoint:'https://127.0.0.1:9443'+H.ROUTE,ca:f.read('ca.pem'),cert:f.read('client.pem'),key:f.read('client.key'),server_certificate_sha256:f.certPin('server.pem'),timeout_ms:1000};
 if(fault==='http')options.endpoint=options.endpoint.replace('https:','http:');
 if(fault==='userinfo')options.endpoint=options.endpoint.replace('https://','https://user:password@');
 if(fault==='query')options.endpoint+='?x=y';if(fault==='hash')options.endpoint+='#x';if(fault==='route')options.endpoint+='/other';if(fault==='trailing')options.endpoint+='/';
 if(fault==='timeout')options.timeout_ms=0;if(fault==='key-mismatch')options.key=f.read('other.key');
 if(fault==='accessor')Object.defineProperty(options,'key',{get(){assert.fail('NO GETTER');},enumerable:true});
 if(fault==='lookalike'){assert.throws(()=>W.createWitnessClient({transport:{secure_transport:true,call:()=>{}},privateKey:f.pem(f.backend.privateKey,true),witnessPublicKey:f.service.publicKey,binding:f.binding}));}
 else assert.throws(()=>H.createHttpsTransport(options));
});
function admin(f){
 const write=(name,data)=>{const p=path.join(f.root,name);fs.writeFileSync(p,data,{mode:0o600});return p;};
 const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
 const witness=write('witness.key',f.pem(f.signing.privateKey,true)),writer=write('writer.pub',f.pem(f.backend.publicKey));
 const config={policy:H.POLICY,directory:f.authority,repository:path.join(f.root,'repo'),host:'127.0.0.1',port:9443,timeout_ms:1000,
 tls_ca_file:path.join(f.root,'ca.pem'),tls_certificate_file:path.join(f.root,'server.pem'),tls_private_key_file:path.join(f.root,'server.key'),tls_certificate_sha256:f.certPin('server.pem'),client_certificate_sha256:f.certPin('client.pem'),witness_private_key_file:witness,writer_public_key_file:writer,witness_public_key_sha256:digest(f.signing.publicKey.export({type:'spki',format:'der'})),writer_public_key_sha256:digest(f.backend.publicKey.export({type:'spki',format:'der'}))};
 const file=write('service.json',canonical(config)),bindingFile=write('binding.json',canonical(f.binding));
 return {config,file,bindingFile,pin:digest(fs.readFileSync(file)),bindingPin:digest(fs.readFileSync(bindingFile)),write,digest};
}
test('administrative check is read-only, explicit provision succeeds once, reset and wrong pins refused',async t=>{
 const f=fixture(t),a=admin(f);const loaded=A.loadService(a.file,a.pin);assert.equal(loaded.server.listening,false);assert.deepEqual(fs.readdirSync(f.authority),[]);
 const {execFileSync,spawnSync}=require('node:child_process'),cli=path.resolve(__dirname,'../recovery-witness-service.js'),base=['--config',a.file,'--config-sha256',a.pin];
 execFileSync(process.execPath,[cli,'check',...base]);assert.deepEqual(fs.readdirSync(f.authority),[]);
 const args=[cli,'provision',...base,'--binding',a.bindingFile,'--binding-sha256',a.bindingPin];execFileSync(process.execPath,args);
 assert.equal(spawnSync(process.execPath,args).status,1);assert.equal(f.service.latest(f.binding).sequence,0);
 assert.throws(()=>A.loadService(a.file,'0'.repeat(64)),/pin/);
});
for(const fault of ['mode','symlink','hardlink','repository','key-pin','server-pin','schema'])test('service provisioning configuration rejects '+fault,async t=>{
 const f=fixture(t),a=admin(f);let file=a.file,pin=a.pin;
 if(fault==='mode')fs.chmodSync(file,0o644);
 if(fault==='symlink'){file=path.join(f.root,'link.json');fs.symlinkSync(a.file,file);}
 if(fault==='hardlink')fs.linkSync(file,path.join(f.root,'hard.json'));
 if(fault==='repository')a.config.repository=f.root;
 if(fault==='key-pin')a.config.writer_public_key_sha256='0'.repeat(64);
 if(fault==='server-pin')a.config.tls_certificate_sha256='0'.repeat(64);
 if(fault==='schema')a.config.extra=true;
 if(['repository','key-pin','server-pin','schema'].includes(fault)){fs.writeFileSync(file,canonical(a.config));pin=a.digest(fs.readFileSync(file));}
 assert.throws(()=>A.loadService(file,pin));assert.deepEqual(fs.readdirSync(f.authority),[]);
});
test('trusted backend config pins credentials and endpoint before any network request',async t=>{
 const f=fixture(t),a=admin(f);f.service.provision(f.binding);const endpoint=await f.listen();
 const writer=a.write('backend-sign.key',f.pem(f.backend.privateKey,true)),witness=a.write('witness.pub',f.service.publicKey);
 const c={policy:H.POLICY,endpoint,tls_ca_file:path.join(f.root,'ca.pem'),tls_certificate_file:path.join(f.root,'client.pem'),tls_private_key_file:path.join(f.root,'client.key'),tls_certificate_sha256:f.certPin('client.pem'),server_certificate_sha256:f.certPin('server.pem'),timeout_ms:1000,writer_private_key_file:writer,writer_public_key_sha256:a.config.writer_public_key_sha256,witness_public_key_file:witness,witness_public_key_sha256:a.config.witness_public_key_sha256};
 const file=a.write('backend.json',canonical(c)),pin=a.digest(fs.readFileSync(file));
 const {createConfiguredClient}=require('../recovery-witness-client-config'),options={file,sha256:pin,binding:f.binding,repository:a.config.repository};
 const client=createConfiguredClient(options);assert.equal((await client.read()).sequence,0);assert.equal(client.secure_witness,true);
 assert.throws(()=>createConfiguredClient({...options,sha256:'0'.repeat(64)}));
 c.writer_public_key_sha256='0'.repeat(64);fs.writeFileSync(file,canonical(c));assert.throws(()=>createConfiguredClient({...options,sha256:a.digest(fs.readFileSync(file))}));
});
test('explicit CLI service restarts in fresh processes with durable signed HTTPS checkpoints',async t=>{
 const f=fixture(t),a=admin(f),probe=await f.listen();const port=f.server.address().port;
 f.server.closeAllConnections();await new Promise(r=>f.server.close(r));a.config.port=port;fs.writeFileSync(a.file,canonical(a.config));a.pin=a.digest(fs.readFileSync(a.file));
 const {spawn,execFileSync}=require('node:child_process'),cli=path.resolve(__dirname,'../recovery-witness-service.js'),base=['--config',a.file,'--config-sha256',a.pin];
 execFileSync(process.execPath,[cli,'provision',...base,'--binding',a.bindingFile,'--binding-sha256',a.bindingPin]);
 const children=[];t.after(()=>{for(const child of children)if(child.exitCode===null)child.kill('SIGTERM');});
 async function start(){const child=spawn(process.execPath,[cli,'serve',...base],{stdio:['ignore','pipe','pipe']});children.push(child);
 await new Promise((resolve,reject)=>{let text='';const timer=setTimeout(()=>reject(new Error('Test listener deadline')),5000);child.stdout.on('data',b=>{text+=b;if(text.includes('listening.')){clearTimeout(timer);resolve();}});child.on('error',e=>{clearTimeout(timer);reject(e);});child.on('exit',()=>{clearTimeout(timer);reject(new Error('Fixture listener exited'));});});return child;}
 async function stop(child){await new Promise(resolve=>{child.once('exit',resolve);child.kill('SIGTERM');});}
 let child=await start();const client=f.client(probe),old=await client.read(),current=await client.advance(old,next(1));await stop(child);
 child=await start();assert.deepEqual(await client.read(),current);await stop(child);
});

test('mutual TLS preserves intermediate certificate chains with root-only trust',async t=>{
 const f=fixture(t),{execFileSync}=require('node:child_process');
 const run=(...args)=>execFileSync('openssl',args,{cwd:f.root,stdio:'pipe',timeout:20000});
 run('req','-newkey','rsa:2048','-nodes','-keyout','intermediate.key','-out','intermediate.csr','-subj','/CN=Disposable Intermediate');
 fs.writeFileSync(path.join(f.root,'intermediate.ext'),'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n');
 run('x509','-req','-in','intermediate.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','intermediate.pem','-days','2','-extfile','intermediate.ext');
 for(const name of ['server','client'])run('x509','-req','-in',name+'.csr','-CA','intermediate.pem','-CAkey','intermediate.key','-CAcreateserial','-out',name+'.pem','-days','2','-extfile',name+'.ext');
 for(const n of fs.readdirSync(f.root))if(fs.statSync(path.join(f.root,n)).isFile())fs.chmodSync(path.join(f.root,n),0o600);
 f.service.provision(f.binding);const cert=Buffer.concat([f.read('server.pem'),f.read('intermediate.pem')]);
 const server=H.createHttpsServer({...f.serverOptions,cert,client_certificate_sha256:f.certPin('client.pem')}),endpoint=await f.listen(server);
 const transport=f.transport(endpoint,{cert:Buffer.concat([f.read('client.pem'),f.read('intermediate.pem')])});
 const client=W.createWitnessClient({transport,binding:f.binding,privateKey:f.pem(f.backend.privateKey,true),witnessPublicKey:f.service.publicKey});assert.equal((await client.read()).sequence,0);
});
test('TLS handshake refuses a caller with no client certificate',async t=>{
 const f=fixture(t);f.service.provision(f.binding);const endpoint=await f.listen();
 await assert.rejects(new Promise((resolve,reject)=>{const req=https.request(endpoint,{method:'POST',ca:f.read('ca.pem'),minVersion:'TLSv1.3'},res=>{res.resume();resolve();});req.on('error',reject);req.end();}));
 assert.equal(f.service.latest(f.binding).sequence,0);
});
test('secure service refuses old fixture history rather than enrolling it as empty',async t=>{
 const f=fixture(t);const old=W.createWitnessService({directory:f.authority,privateKey:f.pem(f.signing.privateKey,true),writerPublicKey:f.pem(f.backend.publicKey)});old.provision(f.binding);
 const endpoint=await f.listen();await assert.rejects(f.client(endpoint).read());assert.throws(()=>f.service.provision(f.binding),/reset forbidden/);assert.equal(old.latest(f.binding).sequence,0);
});
