'use strict';
// Administrative CLI: existing private directories and supplied credentials only.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {canonical} = require('../findings-chaincode/lib/findings');
const W = require('./recovery-witness');
const H = require('./recovery-witness-https');
const check = (v,m) => { if (!v) throw new Error(m); };
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function privateRead(file) {
    const before = W.privatePath(file,false);
    W.privatePath(path.dirname(file),true);
    check(before.size > 0 && before.size <= 32768,'Bounded private configuration/material required');
    const fd = fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
    try {
        const now = fs.fstatSync(fd);
        check(now.ino === before.ino && now.dev === before.dev && now.nlink === 1,'Private file changed while opening');
        return fs.readFileSync(fd);
    } finally { fs.closeSync(fd); }
}
function outside(a,b) {
    const rel = path.relative(a,b); return rel === '..' || rel.startsWith('..'+path.sep);
}
function pinnedJson(file,pin) {
    check(typeof pin === 'string' && /^[0-9a-f]{64}$/.test(pin),'Explicit file SHA-256 pin required');
    const raw = privateRead(file); check(digest(raw) === pin,'Administrative file pin differs');
    const text = raw.toString('utf8'), value = JSON.parse(text);
    check(Buffer.from(text).equals(raw) && canonical(value) === text,'Canonical administrative JSON required');
    return value;
}
function loadService(configFile,configSha256) {
    const c = pinnedJson(configFile,configSha256);
    const names = ['policy','directory','repository','host','port','timeout_ms','tls_ca_file',
        'tls_certificate_file','tls_private_key_file','tls_certificate_sha256','client_certificate_sha256',
        'witness_private_key_file','writer_public_key_file','witness_public_key_sha256','writer_public_key_sha256'];
    check(c && Object.getPrototypeOf(c) === Object.prototype && Object.keys(c).sort().join(',') === names.sort().join(','),'Exact service configuration required');
    check(c.policy === H.POLICY,'Secure service policy required');
    check(typeof c.host === 'string' && require('node:net').isIP(c.host) !== 0,'Explicit service bind IP required');
    check(Number.isSafeInteger(c.port) && c.port >= 1024 && c.port <= 65535,'Explicit unprivileged service port required');
    W.privatePath(c.directory,true); W.privatePath(path.dirname(c.directory),true);
    check(typeof c.repository === 'string' && path.isAbsolute(c.repository) && path.resolve(c.repository) === c.repository,'Canonical repository exclusion path required');
    const paths = [configFile,c.directory,c.tls_ca_file,c.tls_certificate_file,c.tls_private_key_file,c.witness_private_key_file,c.writer_public_key_file];
    check(paths.every(p => outside(c.repository,p) && outside(p,c.repository)), 'Service storage and material must be outside repository');
    const cert = privateRead(c.tls_certificate_file), key = privateRead(c.tls_private_key_file), ca = privateRead(c.tls_ca_file);
    check(digest(new crypto.X509Certificate(cert).raw) === c.tls_certificate_sha256,'Configured server certificate pin differs');
    const signing = privateRead(c.witness_private_key_file), writer = privateRead(c.writer_public_key_file);
    const pub = k => crypto.createPublicKey(k).export({type:'spki',format:'der'});
    check(digest(pub(signing)) === c.witness_public_key_sha256 && digest(pub(writer)) === c.writer_public_key_sha256,'Configured application key pins differ');
    const service = W.createWitnessService({directory:c.directory,privateKey:signing,writerPublicKey:writer,policy:H.POLICY});
    const server = H.createHttpsServer({ca,cert,key,client_certificate_sha256:c.client_certificate_sha256,timeout_ms:c.timeout_ms,service});
    return {config:c,service,server}; // Still no socket and no checkpoint writes.
}
async function main(args) {
    const command = args[0], pairs = args.slice(1), options = {};
    check(['check','provision','serve'].includes(command) && pairs.length % 2 === 0,'Use check, provision or serve with explicit pinned options');
    for(let i=0;i<pairs.length;i+=2) {
        check(['--config','--config-sha256','--binding','--binding-sha256'].includes(pairs[i]) && !Object.hasOwn(options,pairs[i]),'Unknown or duplicate administrative option');
        options[pairs[i]] = pairs[i+1];
    }
    check(options['--config'] && options['--config-sha256'],'Pinned service configuration required');
    check(command === 'provision' ? options['--binding'] && options['--binding-sha256'] : !options['--binding'] && !options['--binding-sha256'],'Binding options only for explicit provisioning');
    const {config,service,server} = loadService(options['--config'],options['--config-sha256']);
    if(command === 'check') { console.log('Secure witness configuration checked; no listener or checkpoint created.'); return; }
    if(command === 'provision') {
        service.provision(W.binding(pinnedJson(options['--binding'],options['--binding-sha256'])));
        console.log('One new secure witness binding provisioned. Existing history cannot be reset.'); return;
    }
    await new Promise((resolve,reject) => {server.once('error',reject);server.listen(config.port,config.host,resolve);});
    console.log('Pinned mutual-TLS recovery witness listening. Independent deployment must be assessed separately.');
    for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{server.closeAllConnections();server.close(()=>process.exit(0));});
}
if(require.main === module)main(process.argv.slice(2)).catch(()=>{console.error('Secure witness administration stopped; inspect private configuration and owned storage.');process.exitCode=1;});
module.exports={privateRead,pinnedJson,loadService,main};
