'use strict';
// Production transport + private real Git fixtures; no actual keys, datasets or chains.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), cp = require('node:child_process');
const F = require('../deployment-files');
const ORIGINAL_CONFIG = 'b1fb4596332921c0c68a66504098fb3b4ba988e36d6f79ab465d6b22fc7aba61';
const PUBLIC = 'fa0a2820a3732739d719cdead513f0929f1b458ae69a2cbc7766b62ae449ad1b';
function fixture(t, fault) {
    const base = fs.mkdtempSync(path.join(os.tmpdir(),'read-rpc-test-'));
    t.after(()=>fs.rmSync(base,{recursive:true,force:true}));
    const repo=path.join(base,'repo'), dir=path.join(repo,'blockchain/public'), privateDir=path.join(base,'private');
    fs.mkdirSync(dir,{recursive:true}); fs.mkdirSync(privateDir,{mode:0o700});
    const original={policy:'SEPOLIA_DEPLOYMENT_NETWORK_V1',rpc_urls:['https://fixture.publicnode.com','https://fixture.alchemy.com/v2/FIXTURE_SECRET'],
        max_fee_gwei:'2',priority_fee_gwei:'1',max_total_fee_eth:'0.025',confirmations:12};
    const configSha=F.digest(original);
    for(const name of ['deployment-files.js','rpc-read-recovery.js','rpc-read-batch.js','rpc-read-pacing.js','audit-read-rpc-profile.js']) {
        let source=fs.readFileSync(path.join(__dirname,'..',name),'utf8');
        // Actual original private config is unavailable; test substitution is explicit and confined to disposable source.
        if(name==='audit-read-rpc-profile.js') source=source.replace(ORIGINAL_CONFIG,configSha);
        fs.writeFileSync(path.join(dir,name),source);
    }
    const script=`const fs=require('node:fs'),F=require('./deployment-files'),R=require('./rpc-read-recovery'),P=require('./audit-read-rpc-profile');
const original=JSON.parse(process.env.FIXTURE_ORIGINAL); const calls=[];
globalThis.fetch=async(url,request)=>{
 calls.push({url_sha:F.digest(url),redirect:request.redirect,body:JSON.parse(request.body)});
 if(process.env.FIXTURE_FAULT==='change_during_read') fs.appendFileSync(process.env.PPI_AUDIT_READ_RPC_PROFILE,' ');
 if(process.env.FIXTURE_FAULT==='provider_error') throw Error('URL_TOKEN_FIXTURE_SECRET');
 const body=JSON.parse(request.body),answer=x=>({jsonrpc:'2.0',id:x.id,...(process.env.FIXTURE_FAULT==='historical_error'?{error:{code:-32000,message:'historical state unavailable URL_TOKEN_FIXTURE_SECRET'}}:{result:'0x1234'})});
 return {ok:true,status:200,text:async()=>JSON.stringify(Array.isArray(body)?body.map(answer):answer(body))};
};
(async()=>{
 try {
  if(process.env.FIXTURE_FAULT==='engine') {
   const E=require(process.env.FIXTURE_ENGINE),S=require(process.env.FIXTURE_SUPPORT),network=require(process.env.FIXTURE_NETWORK);
   const f=S.fake();f.config=network.configuration(original);
   await E.run({...f,mode:'EXECUTE'}); // Invented in-memory fixture only; no network is used for seeding.
   const files=fs.readdirSync(f.directory),before=files.map(n=>[n,F.digest(fs.readFileSync(require('node:path').join(f.directory,n),'utf8'))]);
   const count=f.state.broadcasts.length,source=f.rpcs;let reads=0;
   globalThis.fetch=async(url,request)=>{
    const peer=url.includes('.quiknode.pro/')?0:1,body=JSON.parse(request.body);
    if(request.redirect!=='error')throw Error('Redirect protection absent');
    const answer=async x=>{if(x.method==='eth_sendRawTransaction')throw Error('Write attempted');reads++;return {jsonrpc:'2.0',id:x.id,result:await source[peer].call(x.method,x.params)};};
    const values=Array.isArray(body)?await Promise.all(body.map(answer)):await answer(body);
    return {ok:true,status:200,text:async()=>JSON.stringify(values)};
   };
   const fetchFixture=globalThis.fetch;
   const routed=original.rpc_urls.map(url=>R.endpoint(url,{fetchImpl:fetchFixture,sleep:async()=>{}}));
   const result=await E.run({...f,rpcs:routed,mode:'RECONCILE',wallet:{address:f.wallet.address,signTransaction:()=>{throw Error('Signed during reconciliation');}}});
   const after=fs.readdirSync(f.directory).map(n=>[n,F.digest(fs.readFileSync(require('node:path').join(f.directory,n),'utf8'))]);
   console.log(JSON.stringify({status:result.status,identity:result.identity,officers:result.officers,
    original_valid_transactions:result.original_valid_transactions,submitted:result.submitted_transactions_this_run,
    unchanged:JSON.stringify(before)===JSON.stringify(after)&&count===f.state.broadcasts.length,reads,attestation:P.attestation()}));
   return;
  }
  const r=original.rpc_urls.map(R.endpoint);
  const method=process.env.FIXTURE_FAULT==='write'?'eth_sendRawTransaction':process.env.FIXTURE_FAULT==='unknown_write'?'personal_sendTransaction':'eth_call';
  await r[0].call(method,[{},'0xb57f66']);
  await r[1].batch(Array.from({length:10},()=>({method:'eth_call',params:[{},'0xb57f66']})));
  console.log(JSON.stringify({status:'PASSED',calls,attestation:P.attestation()}));
 } catch(e) { console.log(JSON.stringify({status:'STOPPED',calls,diagnostic:R.safeFailure(e)})); }
})();`;
    const scriptFile=path.join(dir,'publish-research.js'); fs.writeFileSync(scriptFile,script);
    const git=(...args)=>cp.execFileSync('git',['-C',repo,...args],{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
    git('init','-q','-b','feat/identity-resolution'); git('add','.');
    git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','Fixture');
    const head=git('rev-parse','HEAD'), configFile=path.join(privateDir,'network.json'),profileFile=path.join(privateDir,'profile.json');
    fs.writeFileSync(configFile,F.stable(original)+'\n',{mode:0o600});
    const p={policy:P_POLICY(),code_revision:head,original_config_file:configFile,original_config_sha256:configSha,
        original_rpc_sha256:original.rpc_urls.map(F.digest),public_payload_sha256:PUBLIC,
        rpc_urls:['https://fixture.ethereum-sepolia.quiknode.pro/QUICKNODE_FIXTURE_SECRET/',original.rpc_urls[1]]};
    if(fault==='wrong_revision')p.code_revision='0'.repeat(40);
    if(fault==='wrong_policy')p.policy='OTHER';
    if(fault==='wrong_public')p.public_payload_sha256='0'.repeat(64);
    if(fault==='wrong_config')p.original_config_sha256='0'.repeat(64);
    if(fault==='wrong_legacy_endpoint')p.original_rpc_sha256[0]='0'.repeat(64);
    if(fault==='changed_alchemy')p.rpc_urls[1]='https://other.alchemy.com/OTHER';
    if(fault==='wrong_host')p.rpc_urls[0]='https://fixture.quiknode.pro.attacker.invalid/SECRET';
    if(fault==='query')p.rpc_urls[0]+='?secret=1';
    if(fault==='credentials')p.rpc_urls[0]='https://user:password@fixture.quiknode.pro/SECRET';
    if(fault==='http')p.rpc_urls[0]=p.rpc_urls[0].replace('https:','http:');
    if(fault==='root_only')p.rpc_urls[0]='https://fixture.quiknode.pro/';
    if(fault==='extra_field')p.extra=true;
    fs.writeFileSync(profileFile,F.stable(p)+'\n',{mode:0o600});
    const sha=F.digest(fs.readFileSync(profileFile,'utf8'));
    if(fault==='file_mode')fs.chmodSync(profileFile,0o644);
    if(fault==='parent_mode')fs.chmodSync(privateDir,0o755);
    if(fault==='hardlink')fs.linkSync(profileFile,path.join(privateDir,'linked.json'));
    if(fault==='symlink'){fs.renameSync(profileFile,profileFile+'.actual');fs.symlinkSync(profileFile+'.actual',profileFile);}
    if(fault==='dirty_git')fs.writeFileSync(path.join(repo,'unreviewed'),'Fixture');
    if(fault==='changed_original')fs.writeFileSync(configFile,'{}\n');
    if(fault==='duplicate_json')fs.writeFileSync(profileFile,fs.readFileSync(profileFile,'utf8').replace('{','{"policy":"OTHER",'));
    const env={...process.env,FIXTURE_ORIGINAL:JSON.stringify(original),FIXTURE_FAULT:fault||'',
        FIXTURE_ENGINE:path.resolve(__dirname,'../publication-engine.js'),FIXTURE_SUPPORT:path.resolve(__dirname,'public-publisher-support.js'),
        FIXTURE_NETWORK:path.resolve(__dirname,'../sepolia-rpc.js'),
        PPI_AUDIT_READ_RPC_PROFILE:profileFile,PPI_AUDIT_READ_RPC_SHA256:fault==='wrong_hash'?'0'.repeat(64):sha};
    if(fault==='half_env')delete env.PPI_AUDIT_READ_RPC_SHA256;
    const before=fs.readFileSync(configFile);
    const args=[scriptFile,'root','backup','ticket','journal','result',fault==='execute'?'EXECUTE':'RECONCILE',head];
    const result=cp.spawnSync(process.execPath,args,{env,encoding:'utf8',timeout:180000});
    assert.equal(result.status,0,result.stderr); assert.equal(result.stderr,'');
    assert(!result.stdout.includes('FIXTURE_SECRET')&&!result.stdout.includes('password'));
    assert.deepEqual(fs.readFileSync(configFile),before);
    return {value:JSON.parse(result.stdout.trim()),p,sha};
}
function P_POLICY(){return 'ANCHORED_AUDIT_READ_RPC_PROFILE_V1';}
test('both read routes preserve fixed requests and record pinned transport evidence',t=>{
    const {value,p,sha}=fixture(t);
    assert.equal(value.status,'PASSED');assert.equal(value.calls.length,2);
    assert.deepEqual(value.calls.map(c=>c.url_sha),p.rpc_urls.map(F.digest));
    assert(value.calls.every(c=>c.redirect==='error'));
    assert.equal(value.calls[0].body.params[1],'0xb57f66');
    assert(value.calls[1].body.every(c=>c.method==='eth_call'&&c.params[1]==='0xb57f66'));
    assert.equal(value.attestation.read_verification.profile_sha256,sha);
    assert.deepEqual(value.attestation.read_verification.providers,['QUICKNODE','ALCHEMY']);
});
for(const fault of ['wrong_revision','wrong_policy','wrong_public','wrong_config','wrong_legacy_endpoint','changed_alchemy',
    'wrong_host','query','credentials','http','root_only','extra_field','file_mode','parent_mode','hardlink','symlink',
    'dirty_git','changed_original','duplicate_json','wrong_hash','half_env','execute','write','unknown_write'])
    test('profile rejects '+fault+' before network access',t=>{
        const {value}=fixture(t,fault);assert.equal(value.status,'STOPPED');assert.equal(value.calls.length,0);
    });
test('a changed profile stops instead of changing routes or returning partial coverage',t=>{
    const {value}=fixture(t,'change_during_read');assert.equal(value.status,'STOPPED');assert.equal(value.calls.length,1);
    assert.equal(value.diagnostic.category,'READ_PROFILE_REJECTED');assert.equal(value.diagnostic.read_retryable,false);
});
test('historical unavailability never retries or falls back to original RPC',t=>{
    const {value}=fixture(t,'historical_error');assert.equal(value.status,'STOPPED');assert.equal(value.calls.length,1);
    assert.equal(value.diagnostic.category,'HISTORICAL_STATE_UNAVAILABLE');assert.equal(value.diagnostic.read_retryable,false);
});
test('transport failure is bounded and leaks no credential in diagnostics',t=>{
    const {value}=fixture(t,'provider_error');assert.equal(value.status,'STOPPED');assert.equal(value.calls.length,3);
    assert.equal(value.diagnostic.category,'TRANSPORT_UNAVAILABLE');
});
test('full 6596 fixture commitments and 68 original signed receipts reconcile through new read routes',t=>{
    const {value,p}=fixture(t,'engine');assert.equal(value.status,'PASSED');
    assert.equal(value.officers,6596);assert.equal(value.original_valid_transactions,68);
    assert.equal(value.submitted,0);assert.equal(value.unchanged,true);assert(value.reads>=2*6596);
    assert.equal(value.identity.config_sha256,p.original_config_sha256);
    assert.deepEqual(value.attestation.read_verification.providers,['QUICKNODE','ALCHEMY']);
});
