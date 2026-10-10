'use strict';
// Trusted backend library. Provisioning and lock recovery are separate operations.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {canonical,sha}=require('../findings-chaincode/lib/findings');
const check=(v,m)=>{if(!v)throw new Error(m);};
const POLICY='FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1';
const stages=['intent','plan','attempt','ack','final'];
function exact(v,k){check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...k].sort().join(','),'Retention schema differs');}
function privatePath(full,directory){
    for(let p=full;;p=path.dirname(p)){check(!fs.lstatSync(p).isSymbolicLink(),'Retention symlink refused');if(p===path.dirname(p))break;}
    const s=fs.lstatSync(full);check((directory?s.isDirectory():s.isFile())&&s.uid===process.getuid()&&(s.mode&0o077)===0&&
        (directory||s.nlink===1),'Owner-only retention path required');return s;
}
function createRetention({directory,repo,key,binding,readOnly=false}){
    check(typeof directory==='string'&&path.isAbsolute(directory)&&!directory.split(path.sep).includes('..'),'Absolute retention directory required');
    const root=path.resolve(directory),repository=path.resolve(repo),rel=path.relative(repository,root),reverse=path.relative(root,repository);
    const inside=r=>r===''||(!r.startsWith('..'+path.sep)&&r!=='..'&&!path.isAbsolute(r));
    check(!inside(rel)&&!inside(reverse),'Separate retention directory outside repository required');
    check(Buffer.isBuffer(key)&&key.length===32&&typeof readOnly==='boolean','Dedicated AES-256 retention key required');
    exact(binding,['policy','operation','selection_sha256']);
    check(binding.policy===POLICY&&[binding.operation,binding.selection_sha256].every(v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v)),'Retention binding differs');
    privatePath(path.dirname(root),true);
    const secret=Buffer.from(key),scope=canonical(binding),identity=privatePath(root,true);let closed=false,locked=false;
    const lock=path.join(root,'.gateway-lock');
    const names=new Set(stages.map(s=>s+'.encrypted.json'));
    function guard(){
        check(!closed,'Retention closed');const s=privatePath(root,true);check(s.dev===identity.dev&&s.ino===identity.ino,'Retention directory replaced');
        for(const name of fs.readdirSync(root))check(names.has(name)||(name==='.gateway-lock'&&locked),'Unexpected retention artifact; inspect interrupted write or lock');
    }
    function stage(s){check(stages.includes(s),'Unknown retention stage');return path.join(root,s+'.encrypted.json');}
    function read(s){guard();const file=stage(s);if(!fs.existsSync(file))return null;
        privatePath(file,false);const stat=fs.statSync(file);check(stat.size<=1000000,'Retention artifact too large');
        const raw=fs.readFileSync(file,'utf8'),e=JSON.parse(raw);exact(e,['policy','nonce','tag','ciphertext']);
        check(raw===canonical(e)&&e.policy===POLICY,'Retention envelope differs');
        const decode=(v,n)=>{check(typeof v==='string','Retention encoding differs');const b=Buffer.from(v,'base64');check(b.toString('base64')===v&&(n===undefined||b.length===n),'Retention encoding differs');return b;};
        const cipher=crypto.createDecipheriv('aes-256-gcm',secret,decode(e.nonce,12));
        cipher.setAAD(Buffer.from(canonical({binding:JSON.parse(scope),stage:s})));cipher.setAuthTag(decode(e.tag,16));
        const bytes=Buffer.concat([cipher.update(decode(e.ciphertext)),cipher.final()]),value=JSON.parse(bytes.toString('utf8'));
        check(bytes.toString('utf8')===canonical(value),'Retention plaintext encoding differs');return value;
    }
    function sync(){
        guard();for(const s of stages){const file=stage(s);if(fs.existsSync(file)){privatePath(file,false);const fd=fs.openSync(file,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}}
        const dir=fs.openSync(root,'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}
    }
    function save(s,value){guard();check(!readOnly&&locked,'Exclusive writable retention session required');
        const previous=read(s);if(previous!==null){check(canonical(previous)===canonical(value),'Immutable retention stage differs');sync();return;}
        const plain=Buffer.from(canonical(value));check(plain.length<=400000,'Retention value too large');
        const nonce=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',secret,nonce);
        cipher.setAAD(Buffer.from(canonical({binding:JSON.parse(scope),stage:s})));
        const encrypted=Buffer.concat([cipher.update(plain),cipher.final()]);
        const bytes=Buffer.from(canonical({policy:POLICY,nonce:nonce.toString('base64'),tag:cipher.getAuthTag().toString('base64'),ciphertext:encrypted.toString('base64')}));
        const tmp=path.join(root,'.pending-'+crypto.randomBytes(16).toString('hex'));let fd,linked=false;
        try{fd=fs.openSync(tmp,'wx',0o600);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
            fs.linkSync(tmp,stage(s));linked=true;fs.unlinkSync(tmp);
            const dir=fs.openSync(root,'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}
            check(canonical(read(s))===canonical(value),'Retained value readback differs');
        }finally{if(fd!==undefined)fs.closeSync(fd);if(fs.existsSync(tmp))fs.unlinkSync(tmp);}
        // If fsync fails after link, the artifact remains. The caller MUST stop.
        return linked;
    }
    async function session(fn){guard();check(!locked,'Retention session already active');
        if(readOnly)return fn();
        fs.mkdirSync(lock,{mode:0o700});locked=true;
        try{sync();return await fn();}finally{fs.rmdirSync(lock);locked=false;}
    }
    guard();return {read,save,session,check:guard,
        callbacks:{load:async op=>{check(op===binding.operation,'Retention operation differs');return read('plan');},
            save:async(op,plan)=>{check(op===binding.operation,'Retention operation differs');save('plan',plan);}},
        close(){check(!locked,'Cannot close active retention');secret.fill(0);closed=true;},
        inventoryDigest(){guard();return sha(stages.map(s=>({stage:s,value:read(s)})));}};
}
module.exports={createRetention,POLICY};
