'use strict';
// Test-only credentials; requires system openssl, writes only owned temporary root.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {execFileSync}=require('node:child_process');
const W=require('../recovery-witness'),H=require('../recovery-witness-https');
function fixture(t) {
    const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'ppi-witness-mtls-'));fs.chmodSync(root,0o700);
    t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
    const run=(...args)=>execFileSync('openssl',args,{cwd:root,stdio:'pipe',timeout:20000});
    run('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','2','-subj','/CN=PPI Disposable Test CA');
    for(const [name,extensions] of [['server','subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth'],['client','extendedKeyUsage=clientAuth'],['other','extendedKeyUsage=clientAuth']]) {
        run('req','-newkey','rsa:2048','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name);
        fs.writeFileSync(path.join(root,name+'.ext'),'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'+extensions);
        run('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out',name+'.pem','-days','2','-extfile',name+'.ext');
    }
    for(const name of fs.readdirSync(root))fs.chmodSync(path.join(root,name),0o600);
    const read=n=>fs.readFileSync(path.join(root,n));
    const backend=crypto.generateKeyPairSync('ed25519'),signing=crypto.generateKeyPairSync('ed25519');
    const pem=(k,priv=false)=>k.export({type:priv?'pkcs8':'spki',format:'pem'});
    const binding={policy:'FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1',operation:'1'.repeat(64),selection_sha256:'2'.repeat(64)};
    const authority=path.join(root,'authority');fs.mkdirSync(authority,{mode:0o700});
    const service=W.createWitnessService({directory:authority,privateKey:pem(signing.privateKey,true),writerPublicKey:pem(backend.publicKey),policy:H.POLICY});
    const certPin=n=>crypto.createHash('sha256').update(new crypto.X509Certificate(read(n)).raw).digest('hex');
    const serverOptions={ca:read('ca.pem'),cert:read('server.pem'),key:read('server.key'),client_certificate_sha256:certPin('client.pem'),timeout_ms:1000,service};
    const server=H.createHttpsServer(serverOptions);const servers=[server];
    t.after(async()=>{for(const s of servers){s.closeAllConnections();await new Promise(resolve=>s.close(resolve));}});
    async function listen(s=server,host='127.0.0.1'){if(!servers.includes(s))servers.push(s);await new Promise((resolve,reject)=>{s.once('error',reject);s.listen(0,host,resolve);});return 'https://127.0.0.1:'+s.address().port+H.ROUTE;}
    function transport(endpoint,changes={}){return H.createHttpsTransport({endpoint,ca:read('ca.pem'),cert:read('client.pem'),key:read('client.key'),server_certificate_sha256:certPin('server.pem'),timeout_ms:1000,...changes});}
    function client(endpoint,changes={}){return W.createWitnessClient({transport:transport(endpoint),binding,privateKey:pem(backend.privateKey,true),witnessPublicKey:service.publicKey,...changes});}
    return {root,authority,read,backend,signing,pem,binding,service,certPin,server,serverOptions,listen,transport,client};
}
module.exports={fixture};
