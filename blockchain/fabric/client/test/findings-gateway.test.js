'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {execFileSync}=require('node:child_process');
const {FindingsAdapter}=require('../findings-adapter');const B=require('../findings-block');
const {connectFindings}=require('../findings-gateway');const {identity}=require('../block-identity');
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
function setup() {
    const d=dest(),p=payload(),t=tx(p,d),store=new Map(),counts={endorse:0,submit:0,inspect:0},auth=[];
    const retention={load:async op=>structuredClone(store.get(op)||null),save:async(op,plan)=>{assert.ok(!store.has(op));store.set(op,structuredClone(plan));}};
    const transport={certificate:t.certificate,inspect:async()=>{counts.inspect++;return structuredClone(d);},
        endorse:async()=>{counts.endorse++;return {id:t.id,bytes:t.bytes.toString('base64'),expected:structuredClone(t.expected)};},
        submit:async bytes=>{counts.submit++;assert.ok(bytes.equals(t.bytes));return t.id;},
        observe:async()=>({Org1MSP:{block:block(t),record:structuredClone(t.expected)},Org2MSP:{block:block(t),record:structuredClone(t.expected)}})};
    const authorize=async(...args)=>auth.push(args[0]);
    const adapter=new FindingsAdapter({transport,destination:d,retention,authorize,mode:'EXECUTE'});
    return {d,p,t,store,retention,transport,counts,auth,authorize,adapter,operation:'d'.repeat(64)};
}
const prepare=s=>s.adapter.prepare(s.operation,s.p,s.d);

test('retained exact transaction produces two-organization VALID receipt',async()=>{
    const s=setup(),plan=await prepare(s);assert.equal(s.counts.submit,0);assert.equal(s.store.size,1);
    await s.adapter.submit(plan,s.p,s.d);const result=await s.adapter.observeCommitted(plan,s.p,s.d);
    assert.equal(result.status,'FINAL');assert.equal(result.transaction_id,s.t.id);
    assert.deepEqual(result.verification.organizations,['Org1MSP','Org2MSP']);assert.equal(result.verification.validation_code,'VALID');
    assert.ok(s.auth.includes('SUBMIT'));assert.equal(s.counts.endorse,1);
});
test('prepare retry returns same retained bytes without replacement endorsement',async()=>{
    const s=setup(),a=await prepare(s),b=await prepare(s);assert.deepEqual(a,b);assert.equal(s.counts.endorse,1);
});
test('read-only mode refuses both endorsement and submission',async()=>{
    const s=setup(),plan=await prepare(s),a=new FindingsAdapter({...s,destination:s.d,mode:'READ_ONLY'});
    await assert.rejects(a.prepare(s.operation,s.p,s.d),/Read-only/);await assert.rejects(a.submit(plan,s.p,s.d),/Read-only/);
    assert.equal((await a.observeCommitted(plan,s.p,s.d)).status,'FINAL');assert.equal(s.counts.submit,0);
});
for(const kind of ['save-fails','recovery-differs','authorization','network','endorsement-existing'])test('pre-submit failure '+kind,async()=>{
    const s=setup();
    if(kind==='save-fails')s.retention.save=async()=>{throw new Error('disk outage');};
    else if(kind==='recovery-differs')s.retention.load=async()=>null;
    else if(kind==='authorization')s.adapter.authorize=async action=>{if(action==='ENDORSE')throw new Error('expired');};
    else if(kind==='network')s.transport.inspect=async()=>({...s.d,genesis_sha256:'f'.repeat(64)});
    else s.transport.endorse=async()=>({id:s.t.id,bytes:s.t.bytes.toString('base64'),expected:{...s.t.expected,transaction_id:'f'.repeat(64)}});
    await assert.rejects(prepare(s));assert.equal(s.counts.submit,0);
});
for(const kind of ['retention','approval','destination','payload','bytes'])test('submission rejects drift '+kind,async()=>{
    const s=setup(),plan=await prepare(s);let p=s.p,d=s.d;
    if(kind==='retention')s.store.clear();
    else if(kind==='approval')s.adapter.authorize=async action=>{if(action==='SUBMIT')throw new Error('expired');};
    else if(kind==='destination')d={...d,channel:'other'};
    else if(kind==='payload')p={...p,merkle_root:'f'.repeat(64)};
    else {const wire=JSON.parse(plan.transaction);wire.bytes=Buffer.from('bad').toString('base64');plan.transaction=canonical(wire);}
    await assert.rejects(s.adapter.submit(plan,p,d));assert.equal(s.counts.submit,0);
});
test('ambiguous submit preserves retained bytes and read-only reconciliation uses them',async()=>{
    const s=setup(),plan=await prepare(s);s.transport.submit=async()=>{s.counts.submit++;throw new Error('acknowledgement lost');};
    await assert.rejects(s.adapter.submit(plan,s.p,s.d),/lost/);assert.deepEqual(await prepare(s),plan);
    assert.equal((await s.adapter.observeCommitted(plan,s.p,s.d)).status,'FINAL');assert.equal(s.counts.endorse,1);
});
test('unavailable transaction never becomes ABSENT and cannot trigger a replacement',async()=>{
    const s=setup(),plan=await prepare(s);s.transport.observe=async()=>{throw new Error('query timeout');};
    await assert.rejects(s.adapter.observeCommitted(plan,s.p,s.d),/timeout/);assert.equal(s.counts.submit,0);assert.equal(s.counts.endorse,1);
});
for(const kind of ['invalid','one-org','record','block-different','missing-tx','datahash','signature','duplicate','flags'])test('commit proof rejects '+kind,async()=>{
    const s=setup(),plan=await prepare(s),old=s.transport.observe;
    s.transport.observe=async()=>{const result=await old();
        if(kind==='invalid')result.Org2MSP.block=block(s.t,{code:11});
        else if(kind==='one-org')delete result.Org2MSP;
        else if(kind==='record')result.Org2MSP.record.payload.public_sha256='f'.repeat(64);
        else if(kind==='block-different')result.Org2MSP.block=block(s.t,{number:13});
        else if(kind==='missing-tx')result.Org2MSP.block=block(tx(s.p,s.d,{certificate:Buffer.from('other')}));
        else if(kind==='datahash')result.Org2MSP.block=block(s.t,{dataHash:Buffer.alloc(32)});
        else if(kind==='signature')result.Org2MSP.block=block(s.t,{signature:''});
        else if(kind==='duplicate')result.Org2MSP.block=block(s.t,{idDuplicate:true,flagCount:2});
        else result.Org2MSP.block=block(s.t,{flagCount:0});return result;};
    await assert.rejects(s.adapter.observeCommitted(plan,s.p,s.d));
});
for(const change of [{channel:'other'},{chaincode:'officer-evidence-v1'},{method:'DeleteFindings'},{certificate:Buffer.from('different')}])test('prepared invocation binding '+JSON.stringify(change),async()=>{
    const s=setup(),bad=tx(s.p,s.d,change);s.transport.endorse=async()=>({id:bad.id,bytes:bad.bytes.toString('base64'),expected:bad.expected});
    await assert.rejects(prepare(s));assert.equal(s.store.size,0);
});
for(const bytes of [Buffer.from([10,255]),Buffer.from([10,128,0]),Buffer.from([15]),Buffer.from([0]),Buffer.alloc(16777217)])test('bounded protobuf rejects malformed '+bytes.length,()=>assert.throws(()=>B.fields(bytes)));

function gatewayFixture(t) {
    const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'findings-gateway-'));fs.chmodSync(root,0o700);
    t.after(()=>fs.rmSync(root,{recursive:true,force:true}));const repo=path.join(root,'repo');fs.mkdirSync(repo,{mode:0o700});
    function cert(name){const c=path.join(root,name+'.pem'),k=path.join(root,name+'.key');
        execFileSync('openssl',['ecparam','-name','prime256v1','-genkey','-noout','-out',k],{stdio:'ignore'});
        execFileSync('openssl',['req','-new','-x509','-key',k,'-out',c,'-subj','/CN='+name,'-days','1'],{stdio:'ignore'});
        fs.chmodSync(c,0o600);fs.chmodSync(k,0o600);return {certificate:c,private_key:k,certificate_sha256:B.hash(fs.readFileSync(c)),private_key_sha256:B.hash(fs.readFileSync(k))};}
    const enrollment=cert('fixture-enrollment'),tls=cert('fixture-tls'),data=f(1,'fixture config');
    const genesis=cat(f(1,f(3,Buffer.from(B.hash(data),'hex'))),f(2,data),f(3,f(1,'fixture metadata')));
    const genesisFile=path.join(root,'genesis.block');fs.writeFileSync(genesisFile,genesis,{mode:0o600});
    const definition=Buffer.from('fixture approved definition');const d=dest();d.genesis_sha256=B.hash(genesis);
    const c={policy:'FINDINGS_AUTHENTICATED_GATEWAY_V1',destination:d,genesis_file:genesisFile,genesis_identity:identity(genesis),identity:enrollment,tls_client:tls,
        peers:[1,2].map(n=>({msp_id:'Org'+n+'MSP',endpoint:'localhost:'+(n===1?7051:9051),hostname:'peer0.org'+n+'.example.com',tls_certificate:tls.certificate,
            tls_sha256:tls.certificate_sha256,definition_sha256:B.hash(definition)}))};
    const configFile=path.join(root,'config.json');fs.writeFileSync(configFile,canonical(c),{mode:0o600});
    const sdkCalls=[],grpcCalls=[],queryCalls=[],closed=[];let number=0;
    const transaction=tx(payload(),d,{certificate:fs.readFileSync(enrollment.certificate)});
    const sdk={hash:{sha256:'sha256'},signers:{newPrivateKeySigner:key=>key},connect:options=>{
        sdkCalls.push(options);const n=++number;
        return {close:()=>closed.push('gateway'+n),newTransaction:bytes=>({getTransactionId:()=>transaction.id,getResult:()=>Buffer.from(canonical(transaction.expected)),submit:async()=>({getTransactionId:()=>transaction.id})}),
            getNetwork:channel=>({getContract:(name,contract)=>({newProposal:(method,options)=>({
                evaluate:async()=>{queryCalls.push({n,name,contract,method,options});
                    if(method==='GetBlockByNumber')return genesis;
                    if(method==='QueryChaincodeDefinition'){assert.ok(Buffer.isBuffer(options.arguments[0]));assert.equal(B.one(B.fields(options.arguments[0]),1).toString(),d.chaincode);return definition;}
                    if(method==='GetBlockByTxID')return block(transaction);
                    if(method==='ReadFindings')return Buffer.from(canonical(transaction.expected));throw new Error('Unexpected query');},
                endorse:async()=>({getTransactionId:()=>transaction.id,getBytes:()=>transaction.bytes,getResult:()=>Buffer.from(canonical(transaction.expected))})
            })})})};
    }};
    const grpc={credentials:{createSsl:(...args)=>{grpcCalls.push(args);return 'mutual TLS';}},Client:class {
        constructor(endpoint,credentials,options){this.endpoint=endpoint;this.options=options;}close(){closed.push(this.endpoint);}
    }};
    const store=new Map(),retention={load:async id=>store.get(id)||null,save:async(id,p)=>store.set(id,p)};
    const options={configFile,expectedConfigSha256:B.hash(fs.readFileSync(configFile)),repo,retention,authorize:async()=>{}};
    return {c,options,sdk,grpc,sdkCalls,grpcCalls,queryCalls,closed,d,configFile,root};
}
test('factory wires pinned mTLS, binary lifecycle query, exact organization paths and read-only default',async t=>{
    const s=gatewayFixture(t),adapter=connectFindings(s.options,{sdk:s.sdk,grpc:s.grpc});
    assert.deepEqual(await adapter.inspect(s.d),s.d);assert.equal(s.grpcCalls.length,2);
    for(const args of s.grpcCalls)assert.ok(args.every(Buffer.isBuffer));
    for(const options of s.sdkCalls){assert.equal(options.identity.mspId,'Org1MSP');assert.equal(options.tlsClientCertificateHash.length,32);}
    assert.deepEqual(s.queryCalls.filter(q=>q.method==='GetBlockByNumber').map(q=>q.options.endorsingOrganizations),[['Org1MSP'],['Org2MSP']]);
    await assert.rejects(adapter.prepare('d'.repeat(64),payload(),s.d),/Read-only/);
    adapter.close();adapter.close();assert.equal(s.closed.length,4);
});
test('factory full fake-SDK path retains then submits and verifies both blocks',async t=>{
    const s=gatewayFixture(t),adapter=connectFindings({...s.options,mode:'EXECUTE'},{sdk:s.sdk,grpc:s.grpc});
    const plan=await adapter.prepare('d'.repeat(64),payload(),s.d);await adapter.submit(plan,payload(),s.d);
    assert.equal((await adapter.observeCommitted(plan,payload(),s.d)).status,'FINAL');adapter.close();
});
test('factory rejects changed configuration and credentials before SDK construction',t=>{
    const s=gatewayFixture(t);fs.appendFileSync(s.configFile,'\n');
    assert.throws(()=>connectFindings(s.options,{sdk:s.sdk,grpc:s.grpc}),/config differs/);assert.equal(s.sdkCalls.length,0);
});
test('factory detects file drift after connection',async t=>{
    const s=gatewayFixture(t),adapter=connectFindings(s.options,{sdk:s.sdk,grpc:s.grpc});
    fs.appendFileSync(s.c.tls_client.certificate,'\n');await assert.rejects(adapter.inspect(s.d),/changed/);adapter.close();
});
test('factory rejects symlink configuration and permissive directory',t=>{
    const s=gatewayFixture(t),link=path.join(s.root,'link.json');fs.symlinkSync(s.configFile,link);
    assert.throws(()=>connectFindings({...s.options,configFile:link},{sdk:s.sdk,grpc:s.grpc}),/symlink/);
    fs.chmodSync(s.root,0o755);assert.throws(()=>connectFindings(s.options,{sdk:s.sdk,grpc:s.grpc}),/Owner-only/);
});
test('factory rejects mismatched private key pins before creating SDK connections',t=>{
    const s=gatewayFixture(t);s.c.identity.private_key_sha256='f'.repeat(64);
    fs.writeFileSync(s.configFile,canonical(s.c));s.options.expectedConfigSha256=B.hash(fs.readFileSync(s.configFile));
    assert.throws(()=>connectFindings(s.options,{sdk:s.sdk,grpc:s.grpc}),/credential bytes/);assert.equal(s.sdkCalls.length,0);
});
for(const kind of ['genesis','definition'])test('factory stops on peer '+kind+' identity drift',async t=>{
    const s=gatewayFixture(t),original=s.sdk.connect;
    s.sdk.connect=options=>{const g=original(options),network=g.getNetwork;g.getNetwork=channel=>{
        const n=network(channel),contract=n.getContract;n.getContract=(...args)=>{
            const c=contract(...args),proposal=c.newProposal;c.newProposal=(method,options)=>{
                const p=proposal(method,options);
                if(method===(kind==='genesis'?'GetBlockByNumber':'QueryChaincodeDefinition'))p.evaluate=async()=>Buffer.from('bad');return p;
            };return c;
        };return n;
    };return g;};
    const a=connectFindings(s.options,{sdk:s.sdk,grpc:s.grpc});await assert.rejects(a.inspect(s.d));a.close();
});
test('partially initialized factory closes all resources and closed adapter cannot query',async t=>{
    const s=gatewayFixture(t),original=s.sdk.connect;
    s.sdk.connect=options=>{const g=original(options);if(s.sdkCalls.length===2)g.getNetwork=()=>{throw new Error('initialization failure');};return g;};
    assert.throws(()=>connectFindings(s.options,{sdk:s.sdk,grpc:s.grpc}),/initialization failure/);assert.equal(s.closed.length,4);
    const other=gatewayFixture(t),a=connectFindings(other.options,{sdk:other.sdk,grpc:other.grpc});a.close();
    await assert.rejects(a.inspect(other.d),/closed/);
});
test('authorization expiration after peer observations prevents FINAL success',async()=>{
    const s=setup(),plan=await prepare(s);let reconciles=0;
    s.adapter.authorize=async action=>{if(action==='RECONCILE'&&++reconciles===2)throw new Error('expired after observations');};
    await assert.rejects(s.adapter.observeCommitted(plan,s.p,s.d),/expired/);
});
test('SDK reconstruction mismatch stops before broadcasting',async t=>{
    const s=gatewayFixture(t),original=s.sdk.connect;let broadcasts=0;
    s.sdk.connect=options=>{const g=original(options),newTransaction=g.newTransaction;
        g.newTransaction=bytes=>{const tx=newTransaction(bytes);tx.getTransactionId=()=> 'f'.repeat(64);
            tx.submit=async()=>{broadcasts++;throw new Error('must not broadcast');};return tx;};return g;};
    const a=connectFindings({...s.options,mode:'EXECUTE'},{sdk:s.sdk,grpc:s.grpc});const plan=await a.prepare('d'.repeat(64),payload(),s.d);
    await assert.rejects(a.submit(plan,payload(),s.d),/reconstructed transaction differs/);assert.equal(broadcasts,0);a.close();
});
test('matching approved hashes cannot substitute a different enrollment private key',t=>{
    const s=gatewayFixture(t);s.c.identity.private_key=s.c.tls_client.private_key;s.c.identity.private_key_sha256=s.c.tls_client.private_key_sha256;
    fs.writeFileSync(s.configFile,canonical(s.c));s.options.expectedConfigSha256=B.hash(fs.readFileSync(s.configFile));
    assert.throws(()=>connectFindings(s.options,{sdk:s.sdk,grpc:s.grpc}),/Certificate\/private key differ/);assert.equal(s.sdkCalls.length,0);
});
test('certificate expiration after connection blocks network queries',async t=>{
    const s=gatewayFixture(t),a=connectFindings(s.options,{sdk:s.sdk,grpc:s.grpc}),now=Date.now;
    try {Date.now=()=>now()+2*86400000;await assert.rejects(a.inspect(s.d),/expired/);assert.equal(s.queryCalls.length,0);}
    finally {Date.now=now;a.close();}
});

// Consolidated V2 regression checks; existing V1 fixtures retain raw-byte pins.
for(const scenario of ['map-order','changed-policy','index-lag','permission-error'])test('V2 factory '+scenario,async t=>{
    const s=gatewayFixture(t),{definitionHash}=require('../findings-definition');
    const base=Buffer.from('08011203312e301a04657363632204767363632a2e0a2c120c120a080212020800120208011a0d120b0a074f7267314d535010031a0d120b0a074f7267324d535010033200','hex');
    const a=Buffer.from('420b0a074f7267314d53501001','hex'),b=Buffer.from('420b0a074f7267324d53501001','hex');
    const approved=cat(base,a,b),reordered=cat(base,b,a);let reads=0,queries=0;
    s.c.policy='FINDINGS_AUTHENTICATED_GATEWAY_V2';for(const peer of s.c.peers)peer.definition_sha256=definitionHash(approved);
    fs.writeFileSync(s.configFile,canonical(s.c));s.options.expectedConfigSha256=B.hash(fs.readFileSync(s.configFile));
    const original=s.sdk.connect;s.sdk.connect=options=>{const g=original(options),network=g.getNetwork;
        g.getNetwork=channel=>{const n=network(channel),contract=n.getContract;n.getContract=(...args)=>{const c=contract(...args),proposal=c.newProposal;
            c.newProposal=(method,options)=>{const p=proposal(method,options),evaluate=p.evaluate;p.evaluate=async()=>{
                if(method==='QueryChaincodeDefinition'){queries++;if(scenario==='changed-policy'){const bad=Buffer.from(reordered);bad[35]^=1;return bad;}return reordered;}
                if(method==='GetBlockByTxID'){reads++;if(scenario==='permission-error')throw Object.assign(new Error('access denied'),{code:9});
                    if(scenario==='index-lag'&&reads<3)throw Object.assign(new Error('no such transaction ID ['+options.arguments[1]+'] in index'),{code:2});}
                return evaluate();};return p;};return c;};return n;};return g;};
    const adapter=connectFindings(s.options,{sdk:s.sdk,grpc:s.grpc});t.after(()=>adapter.close());
    if(scenario==='changed-policy'){await assert.rejects(adapter.inspect(s.d),/definition differs/);assert.equal(reads,0);}
    else if(scenario==='permission-error'){await assert.rejects(adapter.transport.observe('a'.repeat(64),payload().publication_id),/access denied/);assert.equal(reads,1);}
    else if(scenario==='index-lag'){const observation=await adapter.transport.observe('a'.repeat(64),payload().publication_id);assert.deepEqual(Object.keys(observation),['Org1MSP','Org2MSP']);assert.equal(reads,4);}
    else{assert.deepEqual(await adapter.inspect(s.d),s.d);assert.equal(queries,2);}
});
