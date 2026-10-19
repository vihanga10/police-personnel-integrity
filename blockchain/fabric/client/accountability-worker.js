'use strict';
// Managed worker: exact durable plan, one submission attempt, then read-only reconciliation.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {canonical,sha,validate}=require('../accountability-chaincode/lib/accountability');
const {connectAccountability,privateFile}=require('./accountability-gateway');
const {createRetention,POLICY}=require('./accountability-retention');
const check=(v,m)=>{if(!v)throw Error(m);};
async function run(job,deps){
 check(job&&Object.keys(job).sort().join(',')===['repo','config','config_sha256','directory','key_file','payload','source_pins','retry_retained','read_only'].sort().join(','),'Invalid job');validate(job.payload);
 check(typeof job.retry_retained==='boolean'&&typeof job.read_only==='boolean'&&!(job.retry_retained&&job.read_only),'Explicit recovery mode required');
 const pins=job.source_pins;check(pins&&Object.keys(pins).length>0,'Missing source pins');
 const guard=()=>{for(const [name,pin]of Object.entries(pins)){check(/^(?:blockchain\/fabric\/(?:client\/[a-z0-9-]+\.js|accountability-chaincode\/(?:lib\/)?[a-z0-9-]+\.js|integration\/package(?:-lock)?\.json)|backend\/app\/access\/accountability(?:_anchor|_activity)?\.py)$/.test(name),'Invalid source');check(crypto.createHash('sha256').update(fs.readFileSync(path.join(job.repo,name))).digest('hex')===pin,'Worker source changed');}};guard();
 const key=privateFile(job.key_file,job.repo),op=sha(job.payload);check(key.length===32,'Separate key required');
 const retention=createRetention({directory:job.directory,repo:job.repo,key,binding:{policy:POLICY,operation:op,selection_sha256:op}});
 const adapter=(deps?.connect||connectAccountability)({configFile:job.config,expectedConfigSha256:job.config_sha256,repo:job.repo,retention:retention.callbacks,authorize:async()=>guard(),mode:'EXECUTE'},deps);
 const destination=JSON.parse(privateFile(job.config,job.repo)).destination;
 try{return await retention.session(async()=>{
  guard();let plan=await retention.callbacks.load(op);
  if(!plan){check(!job.read_only,'No retained plan available for read-only reconciliation');plan=await adapter.prepare(op,job.payload,destination);}
  if(!retention.read('attempt')&&!job.read_only){
   retention.save('attempt',{operation:op,transaction_id:plan.transaction_id}); // fsynced BEFORE any broadcast
   await adapter.submit(plan,job.payload,destination);
  }else if(job.retry_retained){await adapter.submit(plan,job.payload,destination);}
  // A lost acknowledgement never causes a new transaction or automatic rebroadcast.
  const receipt=await adapter.observeCommitted(plan,job.payload,destination);guard();retention.save('final',receipt);return {receipt};
 });}finally{adapter.close();retention.close();}
}
if(require.main===module){let input='';process.stdin.on('data',b=>{input+=b;if(Buffer.byteLength(input)>65536)process.exit(1);});process.stdin.on('end',()=>{let job;try{job=JSON.parse(input);}catch{process.exitCode=1;return;}check(Number(process.versions.node.split('.')[0])===24,'Pinned Node 24 runtime required');for(const [n,v]of [['@hyperledger/fabric-gateway','1.8.0'],['@grpc/grpc-js','1.14.4'],['@hyperledger/fabric-protos','0.3.7']])check(require('../integration/node_modules/'+n+'/package.json').version===v,'Pinned SDK version differs');const sdk=require('../integration/node_modules/@hyperledger/fabric-gateway'),grpc=require('../integration/node_modules/@grpc/grpc-js');run(job,{sdk,grpc}).then(r=>process.stdout.write(canonical(r)),()=>{process.stdout.write('{"status":"PENDING_RECONCILIATION"}');process.exitCode=1;});});}
module.exports={run};
