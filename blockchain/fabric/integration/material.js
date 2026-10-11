'use strict';
// Create ephemeral identities signed ONLY by the freshly generated fixture CAs.
const fs=require('node:fs'),path=require('node:path'),{execFileSync}=require('node:child_process');
const crypto=require('node:crypto');
const root=process.env.PPI_TEST_ROOT;
if(!root||!fs.existsSync(path.join(root,'ISOLATED-RUN.json')))throw new Error('Disposable launcher marker required');
const org=path.join(root,'crypto/peerOrganizations/org1.example.com');
function one(dir,pattern){const a=fs.readdirSync(dir).filter(n=>pattern.test(n));if(a.length!==1)throw new Error('Fixture CA selection differs');return path.join(dir,a[0]);}
function issue(name,ca,attributes,tls=false){
    const dir=path.join(root,name);fs.mkdirSync(dir,{mode:0o700});
    const key=path.join(dir,'key.pem'),req=path.join(dir,'request.pem'),cert=path.join(dir,'cert.pem'),ext=path.join(dir,'extensions');
    execFileSync('openssl',['ecparam','-name','prime256v1','-genkey','-noout','-out',key]);
    execFileSync('openssl',['req','-new','-key',key,'-out',req,'-subj','/CN='+name+'/OU=client']);
    const attr=attributes?'\n1.2.3.4.5.6.7.8.1=DER:'+Buffer.from(JSON.stringify({attrs:attributes})).toString('hex').match(/../g).join(':'):'';
    fs.writeFileSync(ext,'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature'+(tls?'\nextendedKeyUsage=clientAuth':'')+attr+'\n',{mode:0o600});
    execFileSync('openssl',['x509','-req','-in',req,'-CA',one(ca,/\.pem$/),'-CAkey',one(ca,/_sk$/),'-set_serial','0x'+crypto.randomBytes(16).toString('hex'),'-out',cert,'-days','1','-sha256','-extfile',ext],{stdio:['ignore','ignore','ignore']});
    for(const n of fs.readdirSync(dir))fs.chmodSync(path.join(dir,n),0o600);
    return {certificate:cert,private_key:key};
}
issue('writer',path.join(org,'ca'),{'findings.anchor':'true'});
issue('denied',path.join(org,'ca'),{'evidence.anchor':'true'});
issue('tls-client',path.join(org,'tlsca'),null,true);
for(const directory of [root]){function visit(d){fs.chmodSync(d,0o700);for(const n of fs.readdirSync(d)){const p=path.join(d,n),s=fs.lstatSync(p);if(s.isSymbolicLink())throw new Error('Fixture symlink refused');if(s.isDirectory())visit(p);else if(s.isFile())fs.chmodSync(p,s.mode&~0o077);}}visit(directory);}
console.log('Disposable fixture identities created.');
