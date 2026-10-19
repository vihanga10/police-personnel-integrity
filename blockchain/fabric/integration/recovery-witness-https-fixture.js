'use strict';
// Explicit ephemeral test provisioner. Two child services, same test host/admin.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),net=require('node:net');
const {execFileSync,spawn}=require('node:child_process');
const {canonical,sha}=require('../findings-chaincode/lib/findings');
const {createConfiguredClient}=require('../client/recovery-witness-client-config');
const H=require('../client/recovery-witness-https');
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
const pem=(key,secret=false)=>key.export({type:secret?'pkcs8':'spki',format:'pem'});
async function httpsAuthority(root,name,repository=path.join(root,'source')){
    if(!['fabric-https-witness','public-https-witness'].includes(name))throw new Error('Named disposable HTTPS authority required');
    const base=path.join(root,name);fs.mkdirSync(base,{mode:0o700});
    const write=(name,bytes)=>{const file=path.join(base,name);fs.writeFileSync(file,bytes,{flag:'wx',mode:0o600});return file;};
    const read=name=>fs.readFileSync(path.join(base,name));
    const run=(...args)=>execFileSync('openssl',args,{cwd:base,stdio:'pipe',timeout:30000});
    write('ca.cnf','[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n');
    run('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','2','-subj','/CN=Disposable Witness CA','-config','ca.cnf','-extensions','v3_ca');
    for(const [who,usage]of [['server','serverAuth'],['client','clientAuth'],['denied','clientAuth']]){
        run('req','-newkey','rsa:2048','-nodes','-keyout',who+'.key','-out',who+'.csr','-subj','/CN=Disposable '+who);
        write(who+'.ext','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+(who==='server'?'\nsubjectAltName=IP:127.0.0.1':'')+'\n');
        run('x509','-req','-in',who+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out',who+'.pem','-days','2','-extfile',who+'.ext');
    }
    for(const n of fs.readdirSync(base))fs.chmodSync(path.join(base,n),0o600);
    const backend=crypto.generateKeyPairSync('ed25519'),witness=crypto.generateKeyPairSync('ed25519');
    const backendDir=path.join(base,'backend'),authority=path.join(base,'authority'),serviceDir=path.join(base,'service');
    for(const d of [backendDir,authority,serviceDir])fs.mkdirSync(d,{mode:0o700});
    const file=(dir,name,value)=>{const p=path.join(dir,name);fs.writeFileSync(p,value,{flag:'wx',mode:0o600});return p;};
    const backendKey=file(backendDir,'writer.key',pem(backend.privateKey,true)),witnessPub=file(backendDir,'witness.pub',pem(witness.publicKey));
    const signing=file(serviceDir,'witness.key',pem(witness.privateKey,true)),writerPub=file(serviceDir,'writer.pub',pem(backend.publicKey));
    const certHash=who=>digest(new crypto.X509Certificate(read(who+'.pem')).raw);
    const keyHash=k=>digest(k.export({type:'spki',format:'der'}));
    const probe=net.createServer();await new Promise((resolve,reject)=>{probe.once('error',reject);probe.listen(0,'127.0.0.1',resolve);});
    const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));
    // A port collision fails startup, never selects someone else's service.
    const config={policy:H.POLICY,directory:authority,repository,host:'127.0.0.1',port,timeout_ms:3000,
        tls_ca_file:path.join(base,'ca.pem'),tls_certificate_file:path.join(base,'server.pem'),tls_private_key_file:path.join(base,'server.key'),tls_certificate_sha256:certHash('server'),client_certificate_sha256:certHash('client'),witness_private_key_file:signing,writer_public_key_file:writerPub,witness_public_key_sha256:keyHash(witness.publicKey),writer_public_key_sha256:keyHash(backend.publicKey)};
    const configFile=file(serviceDir,'config.json',canonical(config)),configPin=digest(fs.readFileSync(configFile));
    const endpoint='https://127.0.0.1:'+port+H.ROUTE;
    const backendConfig={policy:H.POLICY,endpoint,tls_ca_file:path.join(base,'ca.pem'),tls_certificate_file:path.join(base,'client.pem'),tls_private_key_file:path.join(base,'client.key'),tls_certificate_sha256:certHash('client'),server_certificate_sha256:certHash('server'),timeout_ms:3000,writer_private_key_file:backendKey,writer_public_key_sha256:keyHash(backend.publicKey),witness_public_key_file:witnessPub,witness_public_key_sha256:keyHash(witness.publicKey)};
    const clientFile=file(backendDir,'config.json',canonical(backendConfig)),clientPin=digest(fs.readFileSync(clientFile));
    const clients=new Map(),bindings=new Map();let child=null,closed=false;
    const cli=path.resolve(__dirname,'../client/recovery-witness-service.js');
    async function start(){
        if(closed||child)throw new Error('Disposable witness state differs');
        const created=spawn(process.execPath,[path.join(__dirname,'recovery-witness-https-child.js'),configFile,configPin],{stdio:['ignore','ignore','pipe','ipc']});child=created;
        // Private errors are generic; never emit generated keys or request content.
        created.stderr.resume();
        try{await new Promise((resolve,reject)=>{
            const timer=setTimeout(()=>{created.kill('SIGTERM');reject(new Error('Disposable HTTPS witness startup deadline'));},10000);
            const failed=()=>{clearTimeout(timer);reject(new Error('Disposable HTTPS witness startup failed'));};
            created.once('error',failed);created.once('exit',failed);
            created.on('message',message=>{if(message?.kind==='ready'){clearTimeout(timer);created.removeListener('error',failed);created.removeListener('exit',failed);
                if(message.pid!==created.pid||message.port!==port||message.policy!==H.POLICY)reject(new Error('Disposable HTTPS witness startup receipt differs'));else resolve();}});
        });}catch(error){await stop();throw error;}
    }
    async function stop(){
        if(!child)return;const current=child;child=null;
        if(!current.pid||current.exitCode!==null||current.signalCode!==null)return;
        await new Promise(resolve=>{const timer=setTimeout(()=>current.kill('SIGKILL'),3000);current.once('exit',()=>{clearTimeout(timer);resolve();});current.kill('SIGTERM');});
    }
    function client(binding){
        if(closed)throw new Error('Disposable witness closed');const id=sha(binding);
        if(!clients.has(id)){
            const bindingFile=file(backendDir,'binding-'+id+'.json',canonical(binding));
            execFileSync(process.execPath,[cli,'provision','--config',configFile,'--config-sha256',configPin,'--binding',bindingFile,'--binding-sha256',digest(fs.readFileSync(bindingFile))],{stdio:'pipe',timeout:10000});
            clients.set(id,createConfiguredClient({file:clientFile,sha256:clientPin,binding,repository}));bindings.set(id,structuredClone(binding));
        }
        return clients.get(id);
    }
    client.failNext=async(binding,stage,after=false)=>{
        if(!child||closed||!['intent','plan','attempt','ack','final'].includes(stage))throw new Error('Disposable fault control unavailable');
        const current=child,id=crypto.randomBytes(16).toString('hex');
        await new Promise((resolve,reject)=>{const timer=setTimeout(()=>finish(new Error('Disposable fault control deadline')),3000);
            const receive=m=>{if(m?.kind==='ack'&&m.id===id)finish();},exited=()=>finish(new Error('Disposable witness stopped'));
            function finish(error){clearTimeout(timer);current.removeListener('message',receive);current.removeListener('exit',exited);error?reject(error):resolve();}
            current.on('message',receive);current.once('exit',exited);current.send({kind:'fault',id,binding_sha256:sha(binding),stage,after},error=>{if(error)finish(error);});
        });
    };
    client.restart=async()=>{await stop();await start();};
    client.stop=stop;client.start=start;client.close=async()=>{closed=true;await stop();};
    client.deniedClient=binding=>require('../client/recovery-witness').createWitnessClient({transport:client.badTransport(),binding,privateKey:pem(backend.privateKey,true),witnessPublicKey:pem(witness.publicKey)});
    client.pid=()=>child?.pid;client.authorityDirectory=authority;
    client.provisioned=()=>[...bindings.values()].map(b=>structuredClone(b));
    client.badTransport=()=>H.createHttpsTransport({endpoint,ca:read('ca.pem'),cert:read('denied.pem'),key:read('denied.key'),server_certificate_sha256:certHash('server'),timeout_ms:3000});
    await start();return client;
}
module.exports={httpsAuthority};
