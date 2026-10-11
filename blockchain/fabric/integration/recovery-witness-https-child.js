'use strict';
// TEST ONLY. Private parent IPC controls faults, never a production network route.
const fs=require('node:fs'),crypto=require('node:crypto');
const {loadService,privateRead}=require('../client/recovery-witness-service');
const H=require('../client/recovery-witness-https');
const {sha}=require('../findings-chaincode/lib/findings');
async function main(){
    if(typeof process.send!=='function')throw new Error('Disposable parent IPC required');
    const [file,pin]=process.argv.slice(2),loaded=loadService(file,pin),c=loaded.config;
    if(c.host!=='127.0.0.1')throw new Error('Disposable loopback witness required');
    const faults=new Map(),real=loaded.service.transport.call;
    const service={policy:H.POLICY,transport:{async call(q){
        const id=sha(q.body.binding),fault=faults.get(id),hit=q.body.action==='ADVANCE'&&fault&&q.body.snapshot.stages.at(-1).stage===fault.stage;
        if(hit)faults.delete(id);
        if(hit&&!fault.after)throw new Error('DISPOSABLE_BEFORE_COMMIT');
        const result=await real(q);
        if(hit&&fault.after)throw new Error('DISPOSABLE_ACK_LOSS');
        return result;
    }}};
    const server=H.createHttpsServer({ca:privateRead(c.tls_ca_file),cert:privateRead(c.tls_certificate_file),key:privateRead(c.tls_private_key_file),client_certificate_sha256:c.client_certificate_sha256,timeout_ms:c.timeout_ms,service});
    const shutdown=()=>{server.closeAllConnections();server.close(()=>process.exit(0));};
    process.on('disconnect',shutdown);process.once('SIGTERM',shutdown);process.once('SIGINT',shutdown);
    process.on('message',message=>{
        if(message?.kind!=='fault'||typeof message.id!=='string'||!['intent','plan','attempt','ack','final'].includes(message.stage)||typeof message.after!=='boolean')return;
        faults.set(message.binding_sha256,{stage:message.stage,after:message.after});
        process.send({kind:'ack',id:message.id});
    });
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(c.port,c.host,resolve);});
    process.send({kind:'ready',pid:process.pid,port:server.address().port,policy:H.POLICY});
}
main().catch(()=>{console.error('Disposable HTTPS witness process stopped.');process.exitCode=1;});
