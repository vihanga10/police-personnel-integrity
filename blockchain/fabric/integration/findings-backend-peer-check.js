'use strict';
// Real SDK/gRPC/peers, fixture data only. Not a research readiness runner.
const fs=require('node:fs'),path=require('node:path'),net=require('node:net'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const sdk=require('@hyperledger/fabric-gateway'),grpc=require('@grpc/grpc-js');
const {canonical,sha}=require('../findings-chaincode/lib/findings');const B=require('../client/findings-block');
const {identity}=require('../client/block-identity'),{connectFindings}=require('../client/findings-gateway');
const {runProtectedLoaded,POLICY}=require('../client/witnessed-findings-gateway');
const {definitionHash}=require('../client/findings-definition');
const root=process.env.PPI_TEST_ROOT;
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const random=()=>crypto.randomBytes(32).toString('hex');
const POLICY_RUN='PPI_DISPOSABLE_FINDINGS_FABRIC_V1';
const one=dir=>{const a=fs.readdirSync(dir).filter(n=>fs.statSync(path.join(dir,n)).isFile());assert.equal(a.length,1);return path.join(dir,a[0]);};
async function main(){
    assert.ok(root);assert.equal(JSON.parse(fs.readFileSync(path.join(root,'ISOLATED-RUN.json'))).policy,POLICY_RUN);
    const witnessFor=await require('./recovery-witness-https-fixture').httpsAuthority(root,'fabric-https-witness','/work/fabric');
    const witnessForSelection=s=>witnessFor({policy:'FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1',operation:sha({policy:POLICY,selection:s}),selection_sha256:sha(s)});
    const servers=[],sockets=new Set(),gateways=[];let counts={endorse:0,submit:0};const checks=[];const done=name=>{checks.push(name);console.log('Peer check '+checks.length+'/12:',name);};
    try{
        // Proxies exist only INSIDE this disposable runner container. The Factory's
        // unchanged fixed loopback endpoint policy remains intact; TLS ends at peers.
        for(const [number,port] of [[1,7051],[2,9051]]){
            const server=net.createServer(socket=>{const other=net.connect(port,'peer0.org'+number+'.example.com');
                for(const s of [socket,other]){sockets.add(s);s.on('error',()=>{socket.destroy();other.destroy();});s.on('close',()=>sockets.delete(s));}
                socket.pipe(other);other.pipe(socket);});
            await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});servers.push(server);
        }
        function pair(name){return {certificate:path.join(root,name,'cert.pem'),private_key:path.join(root,name,'key.pem')};}
        const writer=pair('writer'),tls=pair('tls-client');
        function direct(number,identity=writer){
            const ca=fs.readFileSync(path.join(root,'crypto/peerOrganizations/org'+number+'.example.com/peers/peer0.org'+number+'.example.com/tls/ca.crt'));
            const client=new grpc.Client('localhost:'+ (number===1?7051:9051),grpc.credentials.createSsl(ca,fs.readFileSync(tls.private_key),fs.readFileSync(tls.certificate)),
                {'grpc.ssl_target_name_override':'peer0.org'+number+'.example.com','grpc.default_authority':'peer0.org'+number+'.example.com'});
            const g=sdk.connect({client,identity:{mspId:'Org1MSP',credentials:fs.readFileSync(identity.certificate)},
                signer:sdk.signers.newPrivateKeySigner(crypto.createPrivateKey(fs.readFileSync(identity.private_key))),hash:sdk.hash.sha256,
                tlsClientCertificateHash:crypto.createHash('sha256').update(new crypto.X509Certificate(fs.readFileSync(tls.certificate)).raw).digest(),
                evaluateOptions:()=>({deadline:Date.now()+15000}),endorseOptions:()=>({deadline:Date.now()+30000}),submitOptions:()=>({deadline:Date.now()+15000}),commitStatusOptions:()=>({deadline:Date.now()+30000})});
            gateways.push({g,client});return g;
        }
        const peers=[direct(1),direct(2)],network=n=>peers[n-1].getNetwork('personnel');
        const evalPeer=(n,cc,method,args)=>network(n).getContract(cc).newProposal(method,{arguments:args,endorsingOrganizations:['Org'+n+'MSP']}).evaluate();
        const genesis=fs.readFileSync(path.join(root,'genesis.block')),dest={genesis_sha256:hash(genesis),channel:'personnel',chaincode:'findings-anchor-v1',namespace:'findings-anchor-v1',organizations:['Org1MSP','Org2MSP']};
        const pins=p=>({...p,certificate_sha256:hash(fs.readFileSync(p.certificate)),private_key_sha256:hash(fs.readFileSync(p.private_key))});
        const descriptors=[];
        for(const n of [1,2]){
            assert.deepEqual(identity(await evalPeer(n,'qscc','GetBlockByNumber',['personnel','0'])),identity(genesis));
            const query=Buffer.concat([Buffer.from([0x0a,Buffer.byteLength(dest.chaincode)]),Buffer.from(dest.chaincode)]);
            const definition=await evalPeer(n,'_lifecycle','QueryChaincodeDefinition',[query]);
            const file=path.join(root,'peer'+n+'-tls.pem');fs.copyFileSync(path.join(root,'crypto/peerOrganizations/org'+n+'.example.com/peers/peer0.org'+n+'.example.com/tls/ca.crt'),file);fs.chmodSync(file,0o600);
            descriptors.push({msp_id:'Org'+n+'MSP',endpoint:'localhost:'+(n===1?7051:9051),hostname:'peer0.org'+n+'.example.com',tls_certificate:file,tls_sha256:hash(fs.readFileSync(file)),definition_sha256:definitionHash(definition)});
        }
        done('real mTLS and both peer genesis/lifecycle queries');
        const config={policy:'FINDINGS_AUTHENTICATED_GATEWAY_V2',destination:dest,genesis_file:path.join(root,'genesis.block'),genesis_identity:identity(genesis),identity:pins(writer),tls_client:pins(tls),peers:descriptors};
        const configFile=path.join(root,'gateway.json');fs.writeFileSync(configFile,canonical(config),{mode:0o600});const configPin=hash(fs.readFileSync(configFile));
        function payload(){return {policy:'FINDINGS_FABRIC_ANCHOR_V1',namespace:'findings-anchor-v1',publication_id:random(),public_sha256:random(),merkle_root:random(),publication_commitment:random()};}
        const approvals=crypto.generateKeyPairSync('ed25519'),trustedKeys={fixture:approvals.publicKey.export({type:'spki',format:'pem'})};
        function scope(p){return {private_sha256:random(),public_sha256:p.public_sha256,history_sha256:random(),code_revision:'1'.repeat(40),gateway_config_sha256:configPin,destination:dest,payload:p};}
        function grant(s,mode){const now=Date.now(),body={policy:POLICY,key_id:'fixture',mode,issued_at:new Date(now-1000).toISOString(),expires_at:new Date(now+599000).toISOString(),selection:s};return {body,signature:crypto.sign(null,Buffer.from(canonical(body)),approvals.privateKey).toString('base64')};}
        const factory=lost=>async options=>{const adapter=connectFindings({configFile,expectedConfigSha256:options.expectedConfigSha256,repo:'/work/fabric',retention:options.retention,authorize:options.authorize,mode:options.mode});
            const endorse=adapter.transport.endorse.bind(adapter.transport),submit=adapter.transport.submit.bind(adapter.transport);
            adapter.transport.endorse=async(...a)=>{counts.endorse++;return endorse(...a);};adapter.transport.submit=async(...a)=>{counts.submit++;if(lost==='before')throw new Error('INJECTED_BEFORE_DELIVERY');const result=await submit(...a);if(lost)throw new Error('INJECTED_ACK_LOSS');return result;};return adapter;};
        const p=payload(),s=scope(p),directory=path.join(root,'recovery');fs.mkdirSync(directory,{mode:0o700});const key=crypto.randomBytes(32);
        const run=(mode='EXECUTE',extras={})=>runProtectedLoaded({recoveryProtection:witnessForSelection(s),verifiedSelection:s,approval:grant(s,mode),trustedKeys,directory,repo:'/work/fabric',key,
            checkLoaded:async(_action,value)=>{assert.deepEqual(value,s);return s;},adapterFactory:factory(false),mode,...extras});
        // The loaded gate above is explicitly a fixture. It does NOT replay actual
        // research snapshots or establish a real AlgorithmPermit/readiness proof.
        async function eventually(fn){let last;for(let i=0;i<30;i++){try{return await fn();}catch(e){last=e;await new Promise(r=>setTimeout(r,500));}}throw last;}
        const first=await run();assert.equal(first.recovery_witness_transport,'MTLS');assert.equal(first.recovery_witness_fixture,false);assert.equal(first.receipt.status,'FINAL');assert.equal(first.both_chains_anchored,false);assert.equal(counts.submit,1);
        done('protected bridge actual endorsed/VALID transaction and both readbacks');
        const stages=fs.readdirSync(directory);assert.equal(stages.length,5);for(const name of stages)assert.ok(!fs.readFileSync(path.join(directory,name),'utf8').includes(first.receipt.transaction_id));
        done('encrypted real transaction material retained');
        const retained=JSON.parse(fs.readFileSync(path.join(directory,'plan.encrypted.json')));assert.equal(retained.policy,'FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1');
        const same=await run();assert.equal(same.receipt.transaction_id,first.receipt.transaction_id);assert.equal(counts.endorse,1);assert.equal(counts.submit,1);
        done('restart does not endorse or submit again');
        const before=stages.map(n=>hash(fs.readFileSync(path.join(directory,n))));await run('RECONCILE');assert.deepEqual(stages.map(n=>hash(fs.readFileSync(path.join(directory,n)))),before);
        done('read-only real-peer reconciliation has no recovery writes');
        const denied=direct(1,pair('denied')).getNetwork('personnel').getContract('findings-anchor-v1','FindingsAnchor');
        await assert.rejects(denied.newProposal('AnchorFindings',{arguments:[canonical(payload())],endorsingOrganizations:['Org1MSP','Org2MSP']}).endorse(),e=>[e.message,...(e.details||[]).map(d=>d.message)].join(' ').includes('Findings writer not authorized'));
        done('genuine chaincode rejects evidence-only writer certificate');
        const contract=network(1).getContract('findings-anchor-v1','FindingsAnchor');
        await assert.rejects(contract.newProposal('AnchorFindings',{arguments:[canonical({...p,merkle_root:random()})],endorsingOrganizations:['Org1MSP','Org2MSP']}).endorse(),e=>[e.message,...(e.details||[]).map(d=>d.message)].join(' ').includes('Conflicting immutable findings publication'));
        done('immutable committed handle rejects conflicting content');
        await assert.rejects(contract.newProposal('AnchorFindings',{arguments:[canonical({...payload(),nic:'fixture forbidden field'})],endorsingOrganizations:['Org1MSP','Org2MSP']}).endorse(),e=>[e.message,...(e.details||[]).map(d=>d.message)].join(' ').includes('Unexpected findings fields'));
        done('real chaincode rejects personal/extraneous payload field');
        assert.throws(()=>connectFindings({configFile,expectedConfigSha256:'f'.repeat(64),repo:'/work/fabric',retention:{},authorize:async()=>{}}));
        done('configuration drift rejected before real SDK construction');
        const p2=payload(),s2=scope(p2),dir2=path.join(root,'ack-loss');fs.mkdirSync(dir2,{mode:0o700});const key2=crypto.randomBytes(32),beforeCount={...counts};
        const run2=(lost,mode='EXECUTE')=>runProtectedLoaded({recoveryProtection:witnessForSelection(s2),verifiedSelection:s2,approval:grant(s2,mode),trustedKeys,directory:dir2,repo:'/work/fabric',key:key2,
            checkLoaded:async()=>s2,adapterFactory:factory(lost),mode});
        await assert.rejects(run2(true),/INJECTED_ACK_LOSS/);const recovered=await eventually(()=>run2(false,'RECONCILE'));
        assert.equal(counts.submit,beforeCount.submit+1);assert.equal(counts.endorse,beforeCount.endorse+1);assert.ok(!fs.existsSync(path.join(dir2,'final.encrypted.json')));
        done('lost real submission acknowledgement recovers original ID read-only');
        const q=payload(),conflict={...q,merkle_root:random()};
        const a=await contract.newProposal('AnchorFindings',{arguments:[canonical(q)],endorsingOrganizations:['Org1MSP','Org2MSP']}).endorse();
        const b=await contract.newProposal('AnchorFindings',{arguments:[canonical(conflict)],endorsingOrganizations:['Org1MSP','Org2MSP']}).endorse();
        const original=Buffer.from(a.getBytes());assert.deepEqual(Buffer.from(peers[0].newTransaction(original).getBytes()),original);
        assert.equal(JSON.parse(Buffer.from(peers[0].newTransaction(original).getResult()).toString()).transaction_id,a.getTransactionId());
        done('real endorsed SDK transaction bytes/result rehydrated before broadcast');
        assert.equal((await (await a.submit()).getStatus()).successful,true);const invalid=await (await b.submit()).getStatus();assert.equal(invalid.successful,false);assert.equal(invalid.code,11);
        const pb=require('@hyperledger/fabric-protos').gateway.PreparedTransaction.deserializeBinary(b.getBytes());const raw=Buffer.from(pb.getEnvelope().getPayload_asU8());
        const invalidBlock=await eventually(()=>evalPeer(1,'qscc','GetBlockByTxID',['personnel',b.getTransactionId()]));assert.throws(()=>B.committed(invalidBlock,raw,b.getTransactionId(),'personnel'),/not VALID/);
        for(const n of [1,2]){const r=JSON.parse(Buffer.from(await eventually(()=>evalPeer(n,'findings-anchor-v1','FindingsAnchor:ReadFindings',[q.publication_id]))).toString());assert.equal(r.transaction_id,a.getTransactionId());assert.deepEqual(r.payload,q);}
        done('real MVCC invalid commit rejected and original publication preserved');
        assert.equal(checks.length,12);fs.writeFileSync(path.join(root,'PEER-PASSED.json'),canonical({policy:POLICY_RUN,checks:checks.length,research_records_used:0,checks_completed:checks,sdk:'1.8.0',fabric:'2.5.16'}),{mode:0o600});
        console.log('12 actual SDK/peer checks passed; fixture data only.');
        const backend=await require('./backend-service-check').checks({root,scope,payload,grant,trustedKeys,configFile,witnessFor,witnessForSelection,evalPeer});
        assert.equal(backend.checks,11);
        fs.writeFileSync(path.join(root,'BACKEND-BRIDGE-PASSED.json'),canonical(backend),{mode:0o600});
        const httpsChecks=[];
        function secureDone(name){httpsChecks.push(name);console.log('HTTPS witness check '+httpsChecks.length+'/6:',name);}
        const bindingFor=value=>({policy:'FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1',operation:sha({policy:POLICY,selection:value}),selection_sha256:sha(value)});
        const beforeRestart=witnessFor.pid(),originalTip=await witnessForSelection(s).read(),savedCounts={...counts};
        await witnessFor.restart();assert.notEqual(witnessFor.pid(),beforeRestart);assert.deepEqual(await witnessForSelection(s).read(),originalTip);
        assert.equal((await run('RECONCILE')).receipt.transaction_id,first.receipt.transaction_id);assert.deepEqual(counts,savedCounts);
        secureDone('fresh HTTPS witness process preserves authoritative checkpoint and original Fabric transaction');
        await assert.rejects(run('RECONCILE',{recoveryProtection:witnessFor.deniedClient(bindingFor(s)),adapterFactory:()=>assert.fail('DENIED CLIENT MUST NOT OPEN SDK')}));assert.deepEqual(counts,savedCounts);
        secureDone('CA-valid but unapproved TLS client stops before SDK construction');
        await witnessFor.stop();await assert.rejects(run('RECONCILE',{adapterFactory:()=>assert.fail('OFFLINE WITNESS MUST NOT OPEN SDK')}));assert.deepEqual(counts,savedCounts);
        await witnessFor.start();assert.equal((await run('RECONCILE')).receipt.transaction_id,first.receipt.transaction_id);assert.deepEqual(counts,savedCounts);
        secureDone('HTTPS witness outage blocks SDK access and restart only reconciles original ID');
        const backup=Object.fromEntries(fs.readdirSync(directory).map(name=>[name,fs.readFileSync(path.join(directory,name))]));
        for(const name of fs.readdirSync(directory))fs.unlinkSync(path.join(directory,name));
        await assert.rejects(run('RECONCILE',{adapterFactory:()=>assert.fail('ROLLBACK MUST NOT OPEN SDK')}),/rollback/);assert.deepEqual(counts,savedCounts);
        for(const [name,bytes]of Object.entries(backup))fs.writeFileSync(path.join(directory,name),bytes,{mode:0o600});
        assert.equal((await run('RECONCILE')).receipt.transaction_id,first.receipt.transaction_id);assert.deepEqual(counts,savedCounts);
        secureDone('whole recovery-directory rollback rejected against fresh HTTPS tip before SDK access');
        for(const after of [false,true]){
            const barrierSelection=scope(payload()),barrierDirectory=path.join(root,after?'https-barrier-after':'https-barrier-before');fs.mkdirSync(barrierDirectory,{mode:0o700});const barrierKey=crypto.randomBytes(32),barrierBinding=bindingFor(barrierSelection);
            witnessForSelection(barrierSelection);await witnessFor.failNext(barrierBinding,'attempt',after);const prior={...counts};
            const barrierRun=mode=>runProtectedLoaded({recoveryProtection:witnessForSelection(barrierSelection),verifiedSelection:barrierSelection,approval:grant(barrierSelection,mode),trustedKeys,directory:barrierDirectory,repo:'/work/fabric',key:barrierKey,mode,checkLoaded:async()=>barrierSelection,adapterFactory:factory(false)});
            await assert.rejects(barrierRun('EXECUTE'),/Witness HTTP request refused/);assert.equal(counts.submit,prior.submit);assert.equal(counts.endorse,prior.endorse+1);
            assert.equal((await witnessForSelection(barrierSelection).read()).sequence,after?3:2);
            if(!after)await assert.rejects(barrierRun('RECONCILE'),/unconfirmed/);else await assert.rejects(barrierRun('RECONCILE'),/no such transaction ID|Failed to get block for txID/);
            await assert.rejects(barrierRun('EXECUTE'),/no such transaction ID|Failed to get block for txID/);assert.equal(counts.submit,prior.submit);assert.equal(counts.endorse,prior.endorse+1);
            secureDone('real SDK attempt rejected on HTTPS witness failure '+(after?'after':'before')+' commit; no broadcast or replacement');
        }
        assert.equal(httpsChecks.length,6);
        const dual=require('../../public/findings/integration/https-witnessed-dual-check');
        const fabric={witnessed:true,scope,eventually,run:({selection:chosen,mode,directory,key,lost=false})=>runProtectedLoaded({recoveryProtection:witnessForSelection(chosen),verifiedSelection:chosen,approval:grant(chosen,mode),trustedKeys,directory,repo:'/work/fabric',key,mode,checkLoaded:async(_a,v)=>{assert.deepEqual(v,chosen);return chosen;},adapterFactory:factory(lost)})};
        const summary=await dual.checks({root,fabric,repo:'/work/fabric',done:name=>console.log('Dual-chain check:',name)});
        assert.equal(summary.checks,16);
        fs.writeFileSync(path.join(root,'HTTPS-WITNESS-PASSED.json'),canonical({...summary,fabric_actual_peers:true,fabric_checks:12,actual_witness_barrier_checks:2,https_checks:httpsChecks.length,https_checks_completed:httpsChecks,https_witness_transport:true,witness_process_restarted:true}),{mode:0o600});

    }finally{await witnessFor.close();for(const {g,client} of gateways){g.close();client.close();}for(const socket of sockets)socket.destroy();await Promise.all(servers.map(s=>new Promise(r=>s.close(r))));}
}
main().catch(e=>{
    const clean=value=>String(value??'')
        .replace(/-----BEGIN[^]*?-----END [^-]+-----/g,'[PEM REDACTED]')
        .slice(0,8000);
    console.error('Real peer checks stopped:',e.constructor.name);
    console.error('Message:',clean(e.message));
    console.error('Code:',clean(e.code));
    console.error('Stack:',clean(e.stack));
    if(Array.isArray(e.details)){
        for(const d of e.details){
            console.error('Peer detail:',clean(d.message));
        }
    }
    process.exitCode=1;
});
