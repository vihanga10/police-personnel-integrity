'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {FindingsAdapter}=require('../findings-adapter');const B=require('../findings-block');
const {runProtectedLoaded,POLICY}=require('../protected-findings-gateway');
const {createRetention,POLICY:RETENTION}=require('../findings-retention');
const {canonical,sha,RECORD_POLICY}=require('../../findings-chaincode/lib/findings');
const fixture=require('../../findings-chaincode/test/commitment-vector.json');
function v(n){let value=BigInt(n),out=[];do{let b=Number(value&127n);value>>=7n;if(value)b|=128;out.push(b);}while(value);return Buffer.from(out);}
const f=(n,b)=>{b=Buffer.from(b);return Buffer.concat([v(n*8+2),v(b.length),b]);};
const num=(n,x)=>Buffer.concat([v(n*8),v(x)]);
const cat=(...b)=>Buffer.concat(b);
const dest=()=>({genesis_sha256:'a'.repeat(64),channel:'personnel',chaincode:'findings-anchor-v1',namespace:'findings-anchor-v1',organizations:['Org1MSP','Org2MSP']});
const payload=()=>structuredClone(fixture.payload);
function tx(p=payload(),d=dest(),options={}) {
    const certificate=options.certificate||Buffer.from('fixture enrollment certificate');
    const creator=cat(f(1,'Org1MSP'),f(2,certificate)),nonce=Buffer.from('fixture nonce'),id=B.hash(cat(nonce,creator));
    const ch=cat(num(1,3),f(4,options.channel||d.channel),f(5,id));
    const header=cat(f(1,ch),f(2,cat(f(1,creator),f(2,nonce))));
    const spec=cat(num(1,1),f(2,f(2,options.chaincode||d.chaincode)),f(3,cat(f(1,options.method||'FindingsAnchor:AnchorFindings'),f(1,canonical(p)))));
    const raw=cat(f(1,header),f(2,f(1,cat(f(1,'signature header'),f(2,f(1,f(1,f(1,spec))))))));
    const envelope=f(1,raw),bytes=cat(f(1,id),f(2,envelope));
    const expected={policy:RECORD_POLICY,payload:structuredClone(p),transaction_id:id};
    return {id,raw,bytes,expected,certificate};
}
function block(t,{code=0,number=12,dataHash,raw=t.raw,idDuplicate=false,flagCount=1,signature='fixture signature'}={}) {
    const envelope=cat(f(1,raw),f(2,signature)),entries=idDuplicate?[envelope,envelope]:[envelope];
    const header=cat(num(1,number),f(2,Buffer.alloc(32,8)),f(3,dataHash||Buffer.from(B.hash(cat(...entries)),'hex')));
    return cat(f(1,header),f(2,cat(...entries.map(e=>f(1,e)))),f(3,cat(f(1,''),f(1,''),f(1,Buffer.alloc(flagCount,code)))));
}
function setup(t){
    const home=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'findings-bridge-'));fs.chmodSync(home,0o700);
    const directory=path.join(home,'recovery'),repo=path.join(home,'repo');fs.mkdirSync(directory,{mode:0o700});fs.mkdirSync(repo,{mode:0o700});
    t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
    const pair=crypto.generateKeyPairSync('ed25519'),publicKey=pair.publicKey.export({type:'spki',format:'pem'}),key=crypto.randomBytes(32);
    const s={private_sha256:'1'.repeat(64),public_sha256:payload().public_sha256,history_sha256:'2'.repeat(64),code_revision:'3'.repeat(40),
        gateway_config_sha256:'4'.repeat(64),destination:dest(),payload:payload()};
    const transaction=tx(s.payload,s.destination),counts={endorse:0,submit:0,observe:0,close:0},actions=[];let committed=false;
    const transport={certificate:transaction.certificate,inspect:async()=>dest(),endorse:async()=>{counts.endorse++;return {id:transaction.id,bytes:transaction.bytes.toString('base64'),expected:transaction.expected};},
        submit:async bytes=>{counts.submit++;assert.deepEqual(bytes,transaction.bytes);committed=true;return transaction.id;},
        observe:async()=>{counts.observe++;if(!committed)throw new Error('commit unavailable');return {Org1MSP:{block:block(transaction),record:transaction.expected},Org2MSP:{block:block(transaction),record:transaction.expected}};}};
    function grant(mode='EXECUTE',changes={}){const now=Date.now();const body={policy:POLICY,key_id:'fixture',mode,issued_at:new Date(now-1000).toISOString(),expires_at:new Date(now+120000).toISOString(),selection:s,...changes};
        return {body,signature:crypto.sign(null,Buffer.from(canonical(body)),pair.privateKey).toString('base64')};}
    const options={verifiedSelection:s,approval:grant(),trustedKeys:{fixture:publicKey},directory,repo,key,mode:'EXECUTE',
        checkLoaded:async(action,selected,mode)=>{actions.push([action,mode]);assert.deepEqual(selected,s);return s;},
        adapterFactory:async({retention,authorize,mode,expectedConfigSha256,destination})=>{assert.equal(expectedConfigSha256,s.gateway_config_sha256);assert.deepEqual(destination,s.destination);
            const a=new FindingsAdapter({transport,retention,authorize,mode,destination});a.close=()=>counts.close++;return a;}};
    return {home,directory,repo,key,s,transaction,counts,actions,transport,options,grant,commit:()=>{committed=true;},
        run:changes=>runProtectedLoaded({...options,...changes}),file:stage=>path.join(directory,stage+'.encrypted.json')};
}
function openStore(s,readOnly=false,changes={}){return createRetention({directory:s.directory,repo:s.repo,key:s.key,
    binding:{policy:RETENTION,operation:sha({policy:POLICY,selection:s.s}),selection_sha256:sha(s.s)},readOnly,...changes});}
const bytes=s=>Object.fromEntries(fs.readdirSync(s.directory).map(n=>[n,fs.readFileSync(path.join(s.directory,n)).toString('hex')]));

test('protected adapter flow retains encrypted intent/plan/attempt/ack/final and checks gate',async t=>{
    const s=setup(t),result=await s.run();assert.equal(result.status,'FABRIC_COMMIT_VERIFIED');assert.equal(result.both_chains_anchored,false);
    assert.equal(s.counts.submit,1);assert.equal(s.counts.endorse,1);assert.equal(s.counts.close,1);
    assert.deepEqual(fs.readdirSync(s.directory).sort(),['ack','attempt','final','intent','plan'].map(n=>n+'.encrypted.json').sort());
    for(const file of fs.readdirSync(s.directory)){const text=fs.readFileSync(path.join(s.directory,file),'utf8');assert.ok(!text.includes(s.transaction.id));assert.ok(!text.includes(s.s.public_sha256));assert.equal(fs.statSync(path.join(s.directory,file)).mode&0o077,0);}
    assert.ok(s.actions.some(([a])=>a==='SUBMIT'));assert.ok(s.actions.some(([a])=>a==='RETURN'));
});
test('restart uses original plan and re-observes final without endorsement/submission',async t=>{
    const s=setup(t),first=await s.run(),before=bytes(s),again=await s.run({approval:s.grant()});assert.deepEqual(again.receipt,first.receipt);
    assert.deepEqual(bytes(s),before);assert.equal(s.counts.submit,1);assert.equal(s.counts.endorse,1);assert.equal(s.counts.observe,2);
});
test('read-only reconciliation has zero storage writes and zero broadcasts',async t=>{
    const s=setup(t);await s.run();const before=bytes(s);const r=await s.run({mode:'RECONCILE',approval:s.grant('RECONCILE')});
    assert.equal(r.mode,'RECONCILE');assert.deepEqual(bytes(s),before);assert.equal(s.counts.submit,1);
});
test('default mode is read-only and refuses an EXECUTE approval',async t=>{
    const s=setup(t),o={...s.options};delete o.mode;await assert.rejects(runProtectedLoaded(o));assert.equal(s.counts.endorse,0);
});
test('read-only cannot create missing intent or plan',async t=>{
    const s=setup(t);await assert.rejects(s.run({mode:'RECONCILE',approval:s.grant('RECONCILE')}),/intent required/);assert.deepEqual(fs.readdirSync(s.directory),[]);
});
test('lost submit acknowledgement leaves durable attempt and reconciles original transaction',async t=>{
    const s=setup(t),old=s.transport.submit;s.transport.submit=async(...args)=>{await old(...args);throw new Error('ack lost');};
    await assert.rejects(s.run(),/ack lost/);assert.ok(fs.existsSync(s.file('attempt')));assert.ok(!fs.existsSync(s.file('ack')));
    const r=await s.run();assert.equal(r.receipt.transaction_id,s.transaction.id);assert.equal(s.counts.submit,1);assert.equal(s.counts.endorse,1);
});
test('interruption after durable attempt but before broadcast never triggers automatic retry',async t=>{
    const s=setup(t),gate=s.options.checkLoaded;s.options.checkLoaded=async(...args)=>{if(args[0]==='BEFORE_SUBMIT')throw new Error('interrupted');return gate(...args);};
    await assert.rejects(s.run(),/interrupted/);assert.ok(fs.existsSync(s.file('attempt')));assert.equal(s.counts.submit,0);
    s.options.checkLoaded=gate;await assert.rejects(s.run(),/unavailable/);assert.equal(s.counts.submit,0);assert.equal(s.counts.endorse,1);
});
test('interruption after plan and before attempt safely resumes first submission',async t=>{
    const s=setup(t),gate=s.options.checkLoaded;s.options.checkLoaded=async(...args)=>{if(args[0]==='BEFORE_ATTEMPT')throw new Error('interrupted');return gate(...args);};
    await assert.rejects(s.run(),/interrupted/);assert.ok(fs.existsSync(s.file('plan')));assert.ok(!fs.existsSync(s.file('attempt')));
    s.options.checkLoaded=gate;await s.run();assert.equal(s.counts.submit,1);assert.equal(s.counts.endorse,1);
});
test('lost acknowledgement can reconcile read-only without creating final artifact',async t=>{
    const s=setup(t),old=s.transport.submit;s.transport.submit=async(...args)=>{await old(...args);throw new Error('lost');};await assert.rejects(s.run());
    const before=bytes(s);await s.run({mode:'RECONCILE',approval:s.grant('RECONCILE')});assert.deepEqual(bytes(s),before);assert.ok(!fs.existsSync(s.file('final')));
});
test('failed observation preserves plan and only observes on retry',async t=>{
    const s=setup(t),old=s.transport.observe;s.transport.observe=async()=>{throw new Error('query timeout');};await assert.rejects(s.run(),/timeout/);
    s.transport.observe=old;await s.run();assert.equal(s.counts.submit,1);assert.equal(s.counts.endorse,1);
});
for(const kind of ['expired','future','signature','selection','mode','untrusted','overlong'])test('approval rejection '+kind,async t=>{
    const s=setup(t);let a=s.grant();
    if(kind==='expired')a=s.grant('EXECUTE',{issued_at:new Date(Date.now()-20000).toISOString(),expires_at:new Date(Date.now()-10000).toISOString()});
    if(kind==='future')a=s.grant('EXECUTE',{issued_at:new Date(Date.now()+10000).toISOString()});
    if(kind==='signature')a.signature=Buffer.alloc(64).toString('base64');
    if(kind==='selection')a=s.grant('EXECUTE',{selection:{...s.s,history_sha256:'8'.repeat(64)}});
    if(kind==='mode')a=s.grant('RECONCILE');
    if(kind==='untrusted')a=s.grant('EXECUTE',{key_id:'other'});
    if(kind==='overlong')a=s.grant('EXECUTE',{expires_at:new Date(Date.now()+700000).toISOString()});
    await assert.rejects(s.run({approval:a}));assert.equal(s.counts.endorse,0);assert.deepEqual(fs.readdirSync(s.directory),[]);
});
for(const action of ['ENTRY','RETAIN','BEFORE_ATTEMPT','SUBMIT','ACK','OBSERVE','FINAL','RETURN'])test('protected gate stops at '+action,async t=>{
    const s=setup(t),old=s.options.checkLoaded;s.options.checkLoaded=async(...args)=>{if(args[0]===action)throw new Error('permit expired');return old(...args);};
    await assert.rejects(s.run(),/permit expired/);if(['ENTRY','RETAIN','BEFORE_ATTEMPT','SUBMIT'].includes(action))assert.equal(s.counts.submit,0);
});
test('loaded selection drift stops before endorsement',async t=>{
    const s=setup(t);await assert.rejects(s.run({checkLoaded:async()=>({...s.s,history_sha256:'9'.repeat(64)})}),/check differs/);assert.equal(s.counts.endorse,0);
});
for(const kind of ['ciphertext','key','binding','stage'])test('AEAD rejects '+kind+' substitution',async t=>{
    const s=setup(t);await s.run();let change={};
    if(kind==='ciphertext'){const e=JSON.parse(fs.readFileSync(s.file('plan')));const b=Buffer.from(e.ciphertext,'base64');b[0]^=1;e.ciphertext=b.toString('base64');fs.writeFileSync(s.file('plan'),canonical(e));}
    if(kind==='key')change.key=crypto.randomBytes(32);
    if(kind==='binding')change.binding={policy:RETENTION,operation:'f'.repeat(64),selection_sha256:'f'.repeat(64)};
    if(kind==='stage')fs.copyFileSync(s.file('intent'),s.file('plan'));
    const store=openStore(s,true,change);assert.throws(()=>store.read('plan'));store.close();
});
for(const kind of ['symlink','permissions','hardlink','extra','pending','stale-lock'])test('retention refuses '+kind,async t=>{
    const s=setup(t);await s.run();
    if(kind==='symlink'){const alias=path.join(s.home,'alias');fs.symlinkSync(s.directory,alias);assert.throws(()=>openStore(s,false,{directory:alias}));return;}
    if(kind==='permissions')fs.chmodSync(s.directory,0o755);
    if(kind==='hardlink')fs.linkSync(s.file('plan'),path.join(s.home,'alias-file'));
    if(kind==='extra')fs.writeFileSync(path.join(s.directory,'other'),'x');
    if(kind==='pending')fs.writeFileSync(path.join(s.directory,'.pending-crash'),'x');
    if(kind==='stale-lock')fs.mkdirSync(path.join(s.directory,'.gateway-lock'),{mode:0o700});
    await assert.rejects(s.run());assert.equal(s.counts.submit,1);
});
test('exclusive sessions reject concurrent operation and release after exceptions',async t=>{
    const s=setup(t),a=openStore(s),b=openStore(s);let release;const hold=new Promise(r=>release=r);const running=a.session(async()=>{await hold;throw new Error('interrupted');});
    await assert.rejects(b.session(async()=>{}));release();await assert.rejects(running);await b.session(async()=>{});a.close();b.close();
});
test('immutable stages refuse replacement and external deletion of attempt rejects lineage',async t=>{
    const s=setup(t);await s.run();const store=openStore(s);await store.session(async()=>assert.throws(()=>store.save('plan',{different:true}),/Immutable/));store.close();
    fs.unlinkSync(s.file('attempt'));await assert.rejects(s.run(),/lineage missing/);assert.equal(s.counts.submit,1);
});
test('final receipt always rechecked; missing or invalid commit cannot return saved success',async t=>{
    const s=setup(t);await s.run();s.transport.observe=async()=>{throw new Error('ledger unavailable');};await assert.rejects(s.run(),/unavailable/);assert.equal(s.counts.submit,1);
});
test('different approved selection cannot reuse encrypted directory',async t=>{
    const s=setup(t);await s.run();s.s.history_sha256='f'.repeat(64);await assert.rejects(s.run({approval:s.grant()}));assert.equal(s.counts.submit,1);
});
test('separate directory and copied key required; closing erases only internal key',async t=>{
    const s=setup(t);assert.throws(()=>openStore(s,false,{directory:s.repo}),/Separate/);assert.throws(()=>openStore(s,false,{key:Buffer.alloc(16)}));
    const original=Buffer.from(s.key),store=openStore(s);store.close();assert.deepEqual(s.key,original);assert.throws(()=>store.read('plan'),/closed/);
});
test('attempt fsync failure stops broadcast and preserves uncertainty marker',async t=>{
    const s=setup(t),original=fs.fsyncSync;let triggered=false;
    fs.fsyncSync=function(fd){if(!triggered&&fs.existsSync(s.file('attempt'))){triggered=true;throw new Error('attempt fsync failure');}return original(fd);};
    try{await assert.rejects(s.run(),/fsync failure/);}finally{fs.fsyncSync=original;}
    assert.ok(triggered);assert.equal(s.counts.submit,0);assert.ok(fs.existsSync(s.file('attempt')));
    await assert.rejects(s.run(),/unavailable/);assert.equal(s.counts.submit,0);
});
test('post-commit final persistence failure recovers original transaction with no broadcast',async t=>{
    const s=setup(t),original=fs.fsyncSync;let triggered=false;
    fs.fsyncSync=function(fd){if(!triggered&&fs.existsSync(s.file('final'))){triggered=true;throw new Error('final fsync failure');}return original(fd);};
    try{await assert.rejects(s.run(),/fsync failure/);}finally{fs.fsyncSync=original;}
    assert.ok(triggered);await s.run();assert.equal(s.counts.submit,1);assert.equal(s.counts.endorse,1);
});
test('directory replacement is rejected by inode pin before storage access',async t=>{
    const s=setup(t),store=openStore(s);fs.renameSync(s.directory,path.join(s.home,'old'));fs.mkdirSync(s.directory,{mode:0o700});
    assert.throws(()=>store.read('plan'),/replaced/);store.close();
});
test('read-only retention refuses stage writes even inside a session',async t=>{
    const s=setup(t),store=openStore(s,true);await store.session(async()=>assert.throws(()=>store.save('intent',{}),/writable/));store.close();
});
test('post-query source drift prevents saved success and closes adapter',async t=>{
    const s=setup(t),old=s.options.checkLoaded;s.options.checkLoaded=async(...args)=>{
        if(args[0]==='RETURN')return {...s.s,private_sha256:'f'.repeat(64)};return old(...args);};
    await assert.rejects(s.run(),/check differs/);assert.equal(s.counts.close,1);assert.equal(s.counts.submit,1);
});
test('fresh reconciliation checks loaded history in RECONCILE mode without latestness claim',async t=>{
    const s=setup(t);await s.run();s.actions.length=0;await s.run({mode:'RECONCILE',approval:s.grant('RECONCILE')});
    assert.ok(s.actions.every(([,m])=>m==='RECONCILE'));assert.ok(!s.actions.some(([a])=>['SUBMIT','ENDORSE','RETAIN'].includes(a)));
});
test('restart must fsync existing retained files before network access',async t=>{
    const s=setup(t);await s.run();const count={...s.counts},original=fs.fsyncSync;fs.fsyncSync=()=>{throw new Error('storage not durable');};
    try{await assert.rejects(s.run(),/not durable/);}finally{fs.fsyncSync=original;}
    assert.deepEqual(s.counts,count);assert.ok(!fs.existsSync(path.join(s.directory,'.gateway-lock')));
});
test('owner-private parent required for recovery directory',async t=>{
    const s=setup(t);fs.chmodSync(s.home,0o755);assert.throws(()=>openStore(s),/Owner-only/);
});
