'use strict';
// Operator setup helper. Reads committed lifecycle definitions and verifies a prepared
// intake gateway read-only. Never endorses or submits a transaction.
const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const {definitionHash}=require('./promotions-definition');
const {identity}=require('./block-identity');
const base='../integration/node_modules/';
const sdk=require(base+'@hyperledger/fabric-gateway'),grpc=require(base+'@grpc/grpc-js');
const check=(v,m)=>{if(!v)throw new Error(m);};
async function definitions(draft){
    const c=JSON.parse(fs.readFileSync(draft)),cert=fs.readFileSync(c.identity.certificate),key=crypto.createPrivateKey(fs.readFileSync(c.identity.private_key));
    const tlsCert=fs.readFileSync(c.tls_client.certificate),tlsKey=fs.readFileSync(c.tls_client.private_key),out={};
    for(const peer of c.peers){
        const client=new grpc.Client(peer.endpoint,grpc.credentials.createSsl(fs.readFileSync(peer.tls_certificate),tlsKey,tlsCert),
            {'grpc.ssl_target_name_override':peer.hostname,'grpc.default_authority':peer.hostname});
        const gateway=sdk.connect({client,identity:{mspId:'Org1MSP',credentials:cert},signer:sdk.signers.newPrivateKeySigner(key),hash:sdk.hash.sha256,
            tlsClientCertificateHash:crypto.createHash('sha256').update(new crypto.X509Certificate(tlsCert).raw).digest(),evaluateOptions:()=>({deadline:Date.now()+60000})});
        try{
            const lifecycle=gateway.getNetwork(c.destination.channel).getContract('_lifecycle');
            const name=Buffer.from(c.destination.chaincode);
            const bytes=await lifecycle.newProposal('QueryChaincodeDefinition',{arguments:[Buffer.concat([Buffer.from([0x0a,name.length]),name])],endorsingOrganizations:[peer.msp_id]}).evaluate();
            out[peer.msp_id]=definitionHash(bytes);
        }finally{gateway.close();client.close();}
    }
    check(out.Org1MSP===out.Org2MSP,'Organizations report different intake definitions');
    return {definitions:out,genesis_identity:identity(fs.readFileSync(c.genesis_file))};
}
async function verify(file,sha){
    const {connectIntake}=require('./intake-gateway');
    const repo=path.resolve(__dirname,'../../..');
    const adapter=connectIntake({configFile:file,expectedConfigSha256:sha,repo,retention:{load:async()=>null,save:async()=>{}},authorize:async()=>{},mode:'READ_ONLY'},{sdk,grpc});
    try{const d=JSON.parse(fs.readFileSync(file)).destination;await adapter.inspect(d);return {status:'READ_ONLY_GATEWAY_VERIFIED'};}finally{adapter.close();}
}
const [mode,a,b]=process.argv.slice(2);
(mode==='definitions'?definitions(a):verify(a,b)).then(r=>console.log(JSON.stringify(r))).catch(e=>{console.error(e.message);process.exitCode=1;});
