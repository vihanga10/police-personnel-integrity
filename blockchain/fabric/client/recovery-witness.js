'use strict';
// Durable witness protocol. Fixture default; pinned mTLS requires explicit secure policy.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {canonical,sha}=require('../findings-chaincode/lib/findings');
const clients=new WeakSet();
const POLICY='FINDINGS_RECOVERY_WITNESS_FIXTURE_V1',STAGES=['intent','plan','attempt','ack','final'];
const check=(v,m)=>{if(!v)throw new Error(m);};
const exact=(v,k)=>check(v&&Object.getPrototypeOf(v)===Object.prototype&&Reflect.ownKeys(v).length===k.length&&k.every(n=>Object.hasOwn(Object.getOwnPropertyDescriptor(v,n)||{},'value')),'Exact witness schema required');
const hash=v=>check(typeof v==='string'&&/^[0-9a-f]{64}$/.test(v),'Witness digest differs');
function binding(b){exact(b,['policy','operation','selection_sha256']);check(b.policy==='FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1','Witness retention policy differs');hash(b.operation);hash(b.selection_sha256);return b;}
function snapshot(s){exact(s,['stages']);check(Array.isArray(s.stages)&&s.stages.length<=5,'Bounded recovery snapshot required');const seen=new Set();let previous=-1;
    for(const item of s.stages){exact(item,['stage','sha256']);hash(item.sha256);const n=STAGES.indexOf(item.stage);check(n>previous&&!seen.has(item.stage),'Recovery stage ordering differs');previous=n;seen.add(item.stage);}
    if(seen.size)check(seen.has('intent'),'Recovery intent required');if(seen.has('attempt'))check(seen.has('plan'),'Recovery plan required');if(seen.has('ack')||seen.has('final'))check(seen.has('attempt'),'Recovery attempt required');return s;
}
function extendsOne(old,next){snapshot(old);snapshot(next);return !old.stages.some(x=>x.stage==='final')&&next.stages.length===old.stages.length+1&&old.stages.every(x=>next.stages.some(y=>canonical(x)===canonical(y)));}
function privatePath(p,dir){check(path.isAbsolute(p)&&path.resolve(p)===p,'Canonical absolute witness path required');for(let q=p;;q=path.dirname(q)){check(!fs.lstatSync(q).isSymbolicLink(),'Witness symlink refused');if(q===path.dirname(q))break;}
    const s=fs.lstatSync(p);check((dir?s.isDirectory():s.isFile())&&s.uid===process.getuid()&&(s.mode&0o077)===0&&(dir||s.nlink===1),'Owner-only witness path required');return s;}
function sign(body,key){return {body,signature:crypto.sign(null,Buffer.from(canonical(body)),key).toString('base64')};}
function verify(envelope,key){exact(envelope,['body','signature']);check(typeof envelope.signature==='string','Witness signature required');const sig=Buffer.from(envelope.signature,'base64');check(sig.length===64&&sig.toString('base64')===envelope.signature&&crypto.verify(null,Buffer.from(canonical(envelope.body)),key,sig),'Witness signature invalid');return envelope.body;}
function edKey(key,privateKey=false){const k=privateKey?crypto.createPrivateKey(key):crypto.createPublicKey(key);check(k.asymmetricKeyType==='ed25519','Witness Ed25519 key required');return k;}
function durable(file,data){const fd=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(fd,canonical(data));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}const d=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(d);}finally{fs.closeSync(d);}}
function createWitnessService({directory,privateKey,writerPublicKey,policy=POLICY}){
    check(policy===POLICY||policy==='FINDINGS_RECOVERY_WITNESS_MTLS_V1','Witness service policy differs');
    const identity=privatePath(directory,true);privatePath(path.dirname(directory),true);const signing=edKey(privateKey,true),writer=edKey(writerPublicKey),pub=crypto.createPublicKey(signing);
    function guard(){const s=privatePath(directory,true);check(s.ino===identity.ino&&s.dev===identity.dev,'Witness directory replaced');}
    function location(b){binding(b);return path.join(directory,sha(b));}
    function latest(b){guard();const dir=location(b);check(fs.existsSync(dir),'Recovery witness not provisioned');privatePath(dir,true);
        const names=fs.readdirSync(dir).sort();check(names.length>0&&names.length<=6&&names.every((n,i)=>n===String(i).padStart(2,'0')+'.json'),'Witness history incomplete or unexpected');let last=null;
        for(let i=0;i<names.length;i++){const file=path.join(dir,names[i]);privatePath(file,false);check(fs.statSync(file).size<20000,'Witness record too large');const raw=fs.readFileSync(file,'utf8'),e=JSON.parse(raw);check(raw===canonical(e),'Witness encoding differs');const fd=fs.openSync(file,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}const c=verify(e,pub);exact(c,['policy','binding','sequence','previous_sha256','snapshot']);snapshot(c.snapshot);
            check(c.policy===policy&&canonical(c.binding)===canonical(b)&&c.sequence===i&&c.previous_sha256===(last?sha(last):'0'.repeat(64)),'Witness checkpoint lineage differs');
            check(i===0?c.snapshot.stages.length===0:extendsOne(last.snapshot,c.snapshot),'Witness checkpoint progression differs');last=c;}
        const fd=fs.openSync(dir,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}return last;
    }
    // Administrative provisioning is separate from the authenticated client API.
    function provision(b){guard();const dir=location(b);check(!fs.existsSync(dir),'Witness already provisioned; reset forbidden');fs.mkdirSync(dir,{mode:0o700});durable(path.join(dir,'00.json'),sign({policy:policy,binding:structuredClone(b),sequence:0,previous_sha256:'0'.repeat(64),snapshot:{stages:[]}},signing));const d=fs.openSync(directory,'r');try{fs.fsyncSync(d);}finally{fs.closeSync(d);}}
    async function call(envelope){guard();const q=verify(envelope,writer);exact(q,['policy','action','binding','nonce','issued_at','expected_sha256','snapshot']);binding(q.binding);hash(q.nonce);check(q.policy===policy&&['READ','ADVANCE'].includes(q.action)&&Number.isSafeInteger(q.issued_at)&&Math.abs(Date.now()-q.issued_at)<=30000,'Fresh witness request required');
        const dir=location(q.binding);let held=false;const lock=path.join(directory,'.witness-lock');
        try{
            if(q.action==='ADVANCE'){hash(q.expected_sha256);snapshot(q.snapshot);fs.mkdirSync(lock,{mode:0o700});held=true;}
            else check(q.expected_sha256===null&&q.snapshot===null,'Read witness request differs');
            let current=latest(q.binding);
            if(q.action==='ADVANCE'){
                if(sha(current)!==q.expected_sha256){check(canonical(current.snapshot)===canonical(q.snapshot)&&current.previous_sha256===q.expected_sha256,'Witness compare-and-swap conflict');}
                else{check(extendsOne(current.snapshot,q.snapshot),'Witness append-only progression required');const next={policy:policy,binding:q.binding,sequence:current.sequence+1,previous_sha256:sha(current),snapshot:q.snapshot};durable(path.join(dir,String(next.sequence).padStart(2,'0')+'.json'),sign(next,signing));current=next;}
            }
            return sign({policy:policy,action:q.action,binding:q.binding,nonce:q.nonce,issued_at:Date.now(),checkpoint:current},signing);
        }finally{if(held)fs.rmdirSync(lock);}
    }
    return {policy,provision,latest,transport:{fixture_transport:policy===POLICY,authority_directory:directory,call},publicKey:pub.export({type:'spki',format:'pem'})};
}
function createWitnessClient({transport,privateKey,witnessPublicKey,binding:b,timeoutMs=5000}){
    binding(b);check(Number.isSafeInteger(timeoutMs)&&timeoutMs>=50&&timeoutMs<=30000,'Bounded witness timeout required');const secure=transport?.secure_transport===true&&require('./recovery-witness-https').isHttpsTransport(transport);check((transport?.fixture_transport===true||secure)&&typeof transport.call==='function','Authenticated witness transport required');const policy=secure?'FINDINGS_RECOVERY_WITNESS_MTLS_V1':POLICY;const call=transport.call.bind(transport),scope=Object.freeze(structuredClone(b)),writer=edKey(privateKey,true),witness=edKey(witnessPublicKey);
    async function request(action,expected=null,next=null){const q={policy:policy,action,binding:scope,nonce:crypto.randomBytes(32).toString('hex'),issued_at:Date.now(),expected_sha256:expected,snapshot:next};let timer;let response;try{response=await Promise.race([Promise.resolve().then(()=>call(sign(q,writer))),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Witness transport timeout; original update may be uncertain')),timeoutMs);})]);}finally{clearTimeout(timer);}const r=verify(response,witness);exact(r,['policy','action','binding','nonce','issued_at','checkpoint']);
        check(r.policy===policy&&r.action===action&&canonical(r.binding)===canonical(scope)&&r.nonce===q.nonce&&Number.isSafeInteger(r.issued_at)&&Math.abs(Date.now()-r.issued_at)<=30000,'Fresh bound witness response required');const c=r.checkpoint;exact(c,['policy','binding','sequence','previous_sha256','snapshot']);snapshot(c.snapshot);hash(c.previous_sha256);check(c.policy===policy&&canonical(c.binding)===canonical(scope)&&Number.isSafeInteger(c.sequence)&&c.sequence===c.snapshot.stages.length,'Witness response checkpoint differs');
        if(action==='ADVANCE')check(c.previous_sha256===expected&&canonical(c.snapshot)===canonical(next),'Witness advance acknowledgement differs');return structuredClone(c);
    }
    const client=Object.freeze({fixture_witness:!secure,secure_witness:secure,endpoint:secure?transport.endpoint:null,authority_directory:transport.authority_directory,binding:scope,read:()=>request('READ'),advance:(old,next)=>request('ADVANCE',sha(old),structuredClone(snapshot(next)))});clients.add(client);return client;
}
module.exports={isWitnessClient:client=>clients.has(client),POLICY,STAGES,binding,snapshot,extendsOne,privatePath,createWitnessService,createWitnessClient,sign,verify};
