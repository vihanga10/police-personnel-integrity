'use strict';
// Disposable test provisioning ONLY. No production trust or independent host.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const W=require('../client/recovery-witness'),{sha}=require('../findings-chaincode/lib/findings');
function fixtureAuthority(root,name){
    if(!['fabric-witness','public-witness'].includes(name))throw new Error('Named fixture authority required');
    const directory=path.join(root,name);fs.mkdirSync(directory,{mode:0o700});const backend=crypto.generateKeyPairSync('ed25519'),server=crypto.generateKeyPairSync('ed25519'),pem=(k,p=false)=>k.export({type:p?'pkcs8':'spki',format:'pem'});
    const service=W.createWitnessService({directory,privateKey:pem(server.privateKey,true),writerPublicKey:pem(backend.publicKey)}),clients=new Map(),failures=new Map();
    const transport={...service.transport,async call(q){const id=sha(q.body.binding),fault=failures.get(id),hit=q.body.action==='ADVANCE'&&fault&&q.body.snapshot.stages.at(-1).stage===fault.stage;
        if(hit)failures.delete(id);if(hit&&!fault.after)throw new Error('INJECTED_WITNESS_FAILURE');const r=await service.transport.call(q);if(hit&&fault.after)throw new Error('INJECTED_WITNESS_ACK_LOSS');return r;}};
    function client(binding){const id=sha(binding);if(!clients.has(id)){service.provision(binding);clients.set(id,W.createWitnessClient({transport,privateKey:pem(backend.privateKey,true),witnessPublicKey:service.publicKey,binding}));}return clients.get(id);}
    client.failNext=(binding,stage,after=false)=>failures.set(sha(binding),{stage,after});return client;
}
module.exports={fixtureAuthority};
