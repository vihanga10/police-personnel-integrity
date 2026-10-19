'use strict';
// Trusted backend constructor. Never pass HTTP request-chosen configuration or pins.
const path=require('node:path'),crypto=require('node:crypto');
const {privateRead,pinnedJson}=require('./recovery-witness-service');
const W=require('./recovery-witness'),H=require('./recovery-witness-https');
const check=(v,m)=>{if(!v)throw new Error(m);};
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
function createConfiguredClient({file,sha256,binding,repository}) {
    const c=pinnedJson(file,sha256),fields=['policy','endpoint','tls_ca_file','tls_certificate_file','tls_private_key_file','tls_certificate_sha256','server_certificate_sha256','timeout_ms','writer_private_key_file','writer_public_key_sha256','witness_public_key_file','witness_public_key_sha256'];
    check(c&&Object.getPrototypeOf(c)===Object.prototype&&Object.keys(c).sort().join(',')===fields.sort().join(','),'Exact backend witness configuration required');
    check(c.policy===H.POLICY,'Secure backend witness policy required');
    check(typeof repository==='string'&&path.isAbsolute(repository)&&path.resolve(repository)===repository,'Canonical backend repository exclusion required');
    const outside=(a,b)=>{const r=path.relative(a,b);return r==='..'||r.startsWith('..'+path.sep);};
    const files=[file,c.tls_ca_file,c.tls_certificate_file,c.tls_private_key_file,c.writer_private_key_file,c.witness_public_key_file];
    check(files.every(p=>typeof p==='string'&&path.isAbsolute(p)&&outside(repository,p)&&outside(p,repository)),'Backend witness material must be outside repository');
    const cert=privateRead(c.tls_certificate_file),key=privateRead(c.tls_private_key_file),ca=privateRead(c.tls_ca_file);
    const writer=privateRead(c.writer_private_key_file),witness=privateRead(c.witness_public_key_file);
    const pub=k=>crypto.createPublicKey(k).export({type:'spki',format:'der'});
    check(digest(new crypto.X509Certificate(cert).raw)===c.tls_certificate_sha256&&digest(pub(writer))===c.writer_public_key_sha256&&digest(pub(witness))===c.witness_public_key_sha256,'Backend TLS/application key pins differ');
    const transport=H.createHttpsTransport({endpoint:c.endpoint,ca,cert,key,server_certificate_sha256:c.server_certificate_sha256,timeout_ms:c.timeout_ms});
    return W.createWitnessClient({transport,privateKey:writer,witnessPublicKey:witness,binding,timeoutMs:c.timeout_ms});
}
module.exports={createConfiguredClient};
