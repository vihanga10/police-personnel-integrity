'use strict';
const fs=require('node:fs');const path=require('node:path');const crypto=require('node:crypto');
const {privatePath,read}=require('./journal');
function connections(configFile,readOnlyIdentity=false) {
    const config=read(configFile);const grpc=require('@grpc/grpc-js');const {connect,signers,hash}=require('@hyperledger/fabric-gateway');
    if(config.channel!=='personnel' || config.chaincode!=='officer-evidence-test-v1'||!/^[0-9a-f]{64}$/.test(config.genesis_sha256))throw new Error('Unexpected synthetic test network');
    const wallet=readOnlyIdentity?config.reader:config.anchorer;
    const credentials=fs.readFileSync(privatePath(wallet.certificate));
    const key=crypto.createPrivateKey(fs.readFileSync(privatePath(wallet.private_key)));
    const certificate=new crypto.X509Certificate(credentials);
    if(!certificate.checkPrivateKey(key))throw new Error('Signing key/certificate differ');
    const objects=config.peers.map(peer=>{
        if(!['localhost:7051','localhost:9051'].includes(peer.endpoint))throw new Error('Unexpected gateway endpoint');
        const client=new grpc.Client(peer.endpoint,grpc.credentials.createSsl(fs.readFileSync(privatePath(peer.tls_certificate))),
            {'grpc.ssl_target_name_override':peer.hostname,'grpc.default_authority':peer.hostname});
        const gateway=connect({client,identity:{mspId:'Org1MSP',credentials},signer:signers.newPrivateKeySigner(key),hash:hash.sha256,
            evaluateOptions:()=>({deadline:Date.now()+60000}),endorseOptions:()=>({deadline:Date.now()+240000}),
            submitOptions:()=>({deadline:Date.now()+60000}),commitStatusOptions:()=>({deadline:Date.now()+60000})});
        return {peer,gateway,client,contract:gateway.getNetwork(config.channel).getContract(config.chaincode,'OfficerEvidence')};
    });
    if(objects.map(o=>o.peer.msp_id).sort().join(',')!=='Org1MSP,Org2MSP')throw new Error('Two peer organizations required');
    const first=objects[0];
    return {network:{genesis_sha256:config.genesis_sha256,channel:config.channel,chaincode:config.chaincode},
        driver:{
            endorse:async(method,args)=>{const tx=await first.contract.newProposal(method,{arguments:args,endorsingOrganizations:['Org1MSP','Org2MSP']}).endorse();
                return {id:tx.getTransactionId(),bytes:Buffer.from(tx.getBytes()).toString('base64'),expected:JSON.parse(Buffer.from(tx.getResult()).toString('utf8'))};},
            submit:async bytes=>{const commit=await first.gateway.newTransaction(Buffer.from(bytes,'base64')).submit();
                return {id:commit.getTransactionId(),commit_bytes:Buffer.from(commit.getBytes()).toString('base64')};},
            status:async bytes=>first.gateway.newCommit(Buffer.from(bytes,'base64')).getStatus(),
            observe:async(method,args)=>Object.fromEntries(await Promise.all(objects.map(async o=>[o.peer.msp_id,
                JSON.parse(Buffer.from(await o.contract.evaluateTransaction(method,...args)).toString('utf8'))])))},
        verifyNetwork:async()=>{for(const o of objects){const block=await o.gateway.getNetwork(config.channel).getContract('qscc').evaluateTransaction('GetBlockByNumber',config.channel,'0');
            if(crypto.createHash('sha256').update(block).digest('hex')!==config.genesis_sha256)throw new Error('Peer genesis identity differs');}},
        close:()=>{for(const o of objects){o.gateway.close();o.client.close();}}};
}
module.exports={connections};
