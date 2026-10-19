'use strict';
// Library only: constructing an authenticated connection does not enable broadcasting.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {canonical}=require('../findings-chaincode/lib/findings');
const {identity}=require('./block-identity');
const {definitionHash}=require('./findings-definition');
const {observeRead}=require('./findings-observation');
const V2='FINDINGS_AUTHENTICATED_GATEWAY_V2';
const {FindingsAdapter,destination}=require('./findings-adapter');
const {hash}=require('./findings-block');
const check=(v,m)=>{if(!v)throw new Error(m);};
const exact=(v,k)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...k].sort().join(','),'Gateway configuration schema differs');
function privateFile(file,repo) {
    check(typeof file==='string'&&path.isAbsolute(file)&&!file.split(path.sep).includes('..'),'Absolute private configuration path required');
    const full=path.resolve(file),rel=path.relative(path.resolve(repo),full);
    check(rel!==''&&!(!rel.startsWith('..'+path.sep)&&rel!=='..'&&!path.isAbsolute(rel)),'Gateway credentials must be outside repository');
    for(let p=full;;p=path.dirname(p)){check(!fs.lstatSync(p).isSymbolicLink(),'Gateway symlink refused');if(p===path.dirname(p))break;}
    const s=fs.statSync(full),parent=fs.statSync(path.dirname(full));
    check(s.isFile()&&s.uid===process.getuid()&&(s.mode&0o077)===0&&parent.uid===process.getuid()&&(parent.mode&0o077)===0,
        'Owner-only credential file/directory required');return fs.readFileSync(full);
}
function connectFindings({configFile,expectedConfigSha256,repo,retention,authorize,mode='READ_ONLY'},deps) {
    let closed=false;
    check(/^[0-9a-f]{64}$/.test(expectedConfigSha256),'Externally approved config digest required');
    const raw=privateFile(configFile,repo);check(hash(raw)===expectedConfigSha256,'Approved gateway config differs');const c=JSON.parse(raw);
    exact(c,['policy','destination','genesis_file','genesis_identity','identity','tls_client','peers']);
    check(['FINDINGS_AUTHENTICATED_GATEWAY_V1',V2].includes(c.policy),'Dedicated Gateway policy required');destination(c.destination);
    exact(c.identity,['certificate','private_key','certificate_sha256','private_key_sha256']);exact(c.tls_client,['certificate','private_key','certificate_sha256','private_key_sha256']);
    check(Array.isArray(c.peers)&&c.peers.length===2,'Two organization paths required');
    const paths=[configFile,c.genesis_file,c.identity.certificate,c.identity.private_key,c.tls_client.certificate,c.tls_client.private_key];
    for(const p of c.peers){exact(p,['msp_id','endpoint','hostname','tls_certificate','tls_sha256','definition_sha256']);
        check(['Org1MSP','Org2MSP'].includes(p.msp_id)&&/^localhost:(7051|9051)$/.test(p.endpoint)&&
            /^peer0\.org[12]\.example\.com$/.test(p.hostname)&&/^[0-9a-f]{64}$/.test(p.definition_sha256),'Pinned local organization path required');
        check((p.msp_id==='Org1MSP')===(p.endpoint==='localhost:7051')&&
            (p.msp_id==='Org1MSP')===(p.hostname==='peer0.org1.example.com'),'Peer endpoint/MSP binding differs');paths.push(p.tls_certificate);
    }
    check(new Set(c.peers.map(p=>p.msp_id)).size===2,'Duplicate organization path');
    for(const pair of [c.identity,c.tls_client])for(const kind of ['certificate','private_key'])
        check(/^[0-9a-f]{64}$/.test(pair[kind+'_sha256'])&&hash(privateFile(pair[kind],repo))===pair[kind+'_sha256'],'Approved credential bytes differ');
    for(const peer of c.peers)check(/^[0-9a-f]{64}$/.test(peer.tls_sha256)&&hash(privateFile(peer.tls_certificate,repo))===peer.tls_sha256,'Approved TLS root differs');
    const pins=new Map(paths.map(p=>[p,hash(privateFile(p,repo))]));
    const genesis=privateFile(c.genesis_file,repo),credentials=privateFile(c.identity.certificate,repo),keyBytes=privateFile(c.identity.private_key,repo),
        tlsCert=privateFile(c.tls_client.certificate,repo),tlsKey=privateFile(c.tls_client.private_key,repo);
    check(hash(genesis)===c.destination.genesis_sha256&&canonical(identity(genesis))===canonical(c.genesis_identity),'Approved genesis differs');
    const key=crypto.createPrivateKey(keyBytes),cert=new crypto.X509Certificate(credentials),clientCert=new crypto.X509Certificate(tlsCert),clientKey=crypto.createPrivateKey(tlsKey);
    check(key.asymmetricKeyType==='ec'&&key.asymmetricKeyDetails.namedCurve==='prime256v1'&&cert.checkPrivateKey(key)&&clientCert.checkPrivateKey(clientKey),'Certificate/private key differ');
    check(!cert.raw.equals(clientCert.raw),'Separate enrollment and transport identities required');
    function local(){
        check(!closed,'Gateway connection closed');
        for(const [p,pin] of pins)check(hash(privateFile(p,repo))===pin,'Pinned Gateway files changed');
        const now=Date.now();for(const x of [cert,clientCert])check(Date.parse(x.validFrom)<=now&&now<Date.parse(x.validTo),'Gateway certificate expired or future');
    }
    local();
    const grpc=deps?.grpc||require('@grpc/grpc-js'),sdk=deps?.sdk||require('@hyperledger/fabric-gateway');const objects=[];
    try {
        for(const peer of c.peers){
            const client=new grpc.Client(peer.endpoint,grpc.credentials.createSsl(privateFile(peer.tls_certificate,repo),tlsKey,tlsCert),
                {'grpc.ssl_target_name_override':peer.hostname,'grpc.default_authority':peer.hostname});
            let gateway;
            try{gateway=sdk.connect({client,identity:{mspId:'Org1MSP',credentials},signer:sdk.signers.newPrivateKeySigner(key),hash:sdk.hash.sha256,
                tlsClientCertificateHash:crypto.createHash('sha256').update(clientCert.raw).digest(),
                evaluateOptions:()=>({deadline:Date.now()+60000}),endorseOptions:()=>({deadline:Date.now()+240000}),
                submitOptions:()=>({deadline:Date.now()+60000}),commitStatusOptions:()=>({deadline:Date.now()+60000})});}
            catch(e){client.close();throw e;}
            const resource={peer,client,gateway};objects.push(resource);
            const network=gateway.getNetwork(c.destination.channel);
            Object.assign(resource,{contract:network.getContract(c.destination.chaincode,'FindingsAnchor'),
                qscc:network.getContract('qscc'),lifecycle:network.getContract('_lifecycle')});
        }
        const first=objects.find(o=>o.peer.msp_id==='Org1MSP');
        const evaluate=(o,contract,method,args)=>contract.newProposal(method,{arguments:args,endorsingOrganizations:[o.peer.msp_id]}).evaluate();
        const transport={
            async inspect(){local();for(const o of objects){
                check(canonical(identity(await evaluate(o,o.qscc,'GetBlockByNumber',[c.destination.channel,'0'])))===canonical(c.genesis_identity),'Peer genesis identity differs');
                const definition=await evaluate(o,o.lifecycle,'QueryChaincodeDefinition',[Buffer.concat([Buffer.from([0x0a,Buffer.byteLength(c.destination.chaincode)]),Buffer.from(c.destination.chaincode)])]);
                check((c.policy===V2?definitionHash(definition):hash(definition))===o.peer.definition_sha256,'Approved chaincode definition differs');
            }local();return structuredClone(c.destination);},
            async endorse(json){local();const t=await first.contract.newProposal('AnchorFindings',{
                arguments:[json],endorsingOrganizations:['Org1MSP','Org2MSP']}).endorse();local();
                return {id:t.getTransactionId(),bytes:Buffer.from(t.getBytes()).toString('base64'),expected:JSON.parse(Buffer.from(t.getResult()).toString('utf8'))};},
            async submit(bytes,id,expected){local();const t=first.gateway.newTransaction(bytes);
                check(t.getTransactionId()===id&&canonical(JSON.parse(Buffer.from(t.getResult()).toString('utf8')))===canonical(expected),'SDK reconstructed transaction differs');
                const commit=await t.submit();local();return commit.getTransactionId();},
            async observe(id,handle){local();const result={};for(const o of objects){
                const read=()=>evaluate(o,o.qscc,'GetBlockByTxID',[c.destination.channel,id]);
                const block=await (c.policy===V2?observeRead(read,id):read());
                const record=JSON.parse(Buffer.from(await evaluate(o,o.contract,'ReadFindings',[handle])).toString('utf8'));
                result[o.peer.msp_id]={block:Buffer.from(block),record};
            }local();return result;}
        };
        Object.defineProperty(transport,'certificate',{get:()=>Buffer.from(credentials)});
        const adapter=new FindingsAdapter({transport,destination:c.destination,retention,authorize,mode});
        adapter.close=()=>{if(closed)return;closed=true;for(const o of objects){o.gateway.close();o.client.close();}};
        return adapter;
    } catch(e){for(const o of objects){o.gateway.close();o.client.close();}throw e;}
}
module.exports={connectFindings,privateFile};
