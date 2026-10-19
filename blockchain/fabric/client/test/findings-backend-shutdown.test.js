'use strict';
// Actual worker pipe and retention session. Source/SDK/witness doubles only;
// these subprocess checks create no credentials, service or ledger.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {spawn}=require('node:child_process'),readline=require('node:readline');
const {canonical}=require('../../findings-chaincode/lib/findings');
const {createRetention,POLICY}=require('../findings-retention');
const worker=require.resolve('../findings-backend-worker');
function binding(){return {policy:POLICY,operation:'1'.repeat(64),selection_sha256:'2'.repeat(64)};}
for(const mode of ['denied','eof','wrong-id','crash'])test('actual worker shutdown: '+mode,{timeout:10000},async t=>{
    const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'backend-shutdown-'));fs.chmodSync(root,0o700);
    const directory=path.join(root,'retention'),repo=path.join(root,'repo');fs.mkdirSync(directory,{mode:0o700});fs.mkdirSync(repo,{mode:0o700});
    const key=crypto.randomBytes(32);
    const body=`const Module=require('node:module'),original=Module._load;
const {createRetention}=require(${JSON.stringify(require.resolve('../findings-retention'))});
Module._load=function(id,parent,...rest){
 if(parent?.filename===${JSON.stringify(worker)}){
  if(id==='./witnessed-findings-gateway')return {POLICY:'TEST_ONLY',selection:s=>s,approval:()=>{},runProtectedLoaded:async o=>{
   const retention=createRetention({directory:o.directory,repo:o.repo,key:o.key,binding:${JSON.stringify(binding())}});
   try{return await retention.session(async()=>{retention.save('intent',{fixture:true});await o.checkLoaded('BEFORE_SUBMIT',o.verifiedSelection,o.mode);throw Error('unexpected approval');});}
   finally{retention.close();}
  }};
  if(id==='./findings-gateway')return {privateFile:()=>Buffer.from(${JSON.stringify(key.toString('hex'))},'hex')};
  if(id==='./recovery-witness-client-config')return {createConfiguredClient:()=>({secure_witness:true,fixture_witness:false})};
  if(id.startsWith('../integration/node_modules/'))return {};
 }
 return original.call(this,id,parent,...rest);
};require(${JSON.stringify(worker)}).main();`;
    const child=spawn(process.execPath,['-e',body],{stdio:['pipe','pipe','pipe']});
    let errors='';child.stderr.on('data',v=>errors+=v);
    const exited=new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',(code,signal)=>resolve({code,signal}));});
    t.after(()=>{child.kill('SIGKILL');fs.rmSync(root,{recursive:true,force:true});});
    const lines=readline.createInterface({input:child.stdout});const guards=[];
    lines.on('line',line=>{
        const message=JSON.parse(line);if(message.kind!=='guard')return;guards.push(message.action);
        if(message.action==='ENTRY')child.stdin.write(canonical({kind:'approved',id:message.id,selection:message.selection})+'\n');
        else if(mode==='eof')child.stdin.end();
        else if(mode==='crash')child.kill('SIGKILL');
        else child.stdin.write(canonical({kind:'denied',id:message.id+(mode==='wrong-id'?1:0)})+'\n');
    });
    const job={selection:{fixture:true},approval:{},trustedKeys:{},mode:'EXECUTE',repo,directory,
        gatewayConfigFile:'unused',witnessConfigFile:'unused',witnessConfigSha256:'3'.repeat(64),recoveryKeyFile:'unused'};
    child.stdin.write(canonical({kind:'start',job})+'\n');
    const exit=await exited;assert.equal(errors,'');assert.deepEqual(guards,['ENTRY','BEFORE_SUBMIT']);
    assert.equal(fs.existsSync(path.join(directory,'.gateway-lock')),mode==='crash');
    if(mode==='crash'){
        assert.equal(exit.signal,'SIGKILL');
        assert.throws(()=>createRetention({directory,repo,key,binding:binding()}),/Unexpected retention artifact/);
    }else{
        assert.equal(exit.code,1);const retention=createRetention({directory,repo,key,binding:binding()});
        assert.deepEqual(retention.read('intent'),{fixture:true});retention.close();
    }
});
