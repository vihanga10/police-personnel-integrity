'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {FindingsAdapter}=require('../findings-adapter');const B=require('../findings-block');
const {runProtectedLoaded,POLICY}=require('../witnessed-findings-gateway');
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
async function setup(t){
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
    const tls=require('./recovery-witness-tls-fixture').fixture(t);
    const binding={policy:RETENTION,operation:sha({policy:POLICY,selection:s}),selection_sha256:sha(s)};
    tls.service.provision(binding);const endpoint=await tls.listen();
    options.recoveryProtection=tls.client(endpoint,{binding});
    const service=tls.service;
    return {service,home,directory,repo,key,s,transaction,counts,actions,transport,options,grant,commit:()=>{committed=true;},
        run:changes=>runProtectedLoaded({...options,...changes}),file:stage=>path.join(directory,stage+'.encrypted.json')};
}
function openStore(s,readOnly=false,changes={}){return createRetention({directory:s.directory,repo:s.repo,key:s.key,
    binding:{policy:RETENTION,operation:sha({policy:POLICY,selection:s.s}),selection_sha256:sha(s.s)},readOnly,...changes});}
const bytes=s=>Object.fromEntries(fs.readdirSync(s.directory).map(n=>[n,fs.readFileSync(path.join(s.directory,n)).toString('hex')]));


test('protected Fabric runner uses real HTTPS witness barrier and read-only restart',async t=>{
 const f=await setup(t);const submit=f.transport.submit;
 f.transport.submit=async(...args)=>{const tip=await f.options.recoveryProtection.read();assert.ok(tip.snapshot.stages.some(x=>x.stage==='attempt'));return submit(...args);};
 const result=await f.run();assert.equal(result.recovery_witness_fixture,false);assert.equal(result.recovery_witness_transport,'MTLS');assert.equal(result.independent_witness_deployment_verified,false);
 const before=bytes(f);const repeated=await f.run({mode:'RECONCILE',approval:f.grant('RECONCILE')});assert.deepEqual(repeated.receipt,result.receipt);assert.deepEqual(bytes(f),before);assert.equal(f.counts.submit,1);assert.equal(f.counts.endorse,1);
});
test('secure witness outage prevents protected Fabric SDK construction and submission',async t=>{
 const f=await setup(t); // Close the actual listening witness before invoking the runner.
 // A bound client whose endpoint becomes unavailable must not fall back to the fixture.
 const serverClient=f.options.recoveryProtection;
 // Pin a valid authenticated transport to an unused loopback port instead.
 const tls=require('./recovery-witness-tls-fixture').fixture(t),H=require('../recovery-witness-https'),W=require('../recovery-witness');
 const probe=await tls.listen();tls.server.closeAllConnections();await new Promise(r=>tls.server.close(r));
 const client=W.createWitnessClient({transport:tls.transport(probe,{timeout_ms:100}),privateKey:tls.pem(tls.backend.privateKey,true),witnessPublicKey:tls.service.publicKey,binding:serverClient.binding});
 await assert.rejects(f.run({recoveryProtection:client,adapterFactory:()=>assert.fail('NO SDK')}));assert.equal(f.counts.submit,0);assert.equal(f.counts.endorse,0);
});
