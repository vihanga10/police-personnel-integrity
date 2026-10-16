'use strict';
// Owned backend worker. No caller receipts, automatic broadcasts or fixture promotion.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),readline=require('node:readline');
const {privateFile,connectPromotions}=require('../../fabric/client/promotions-gateway');
const {createRetention,POLICY:RETENTION}=require('../../fabric/client/promotions-retention');
const {Wallet}=require('ethers'),W=require('../sepolia-wallet'),N=require('./network');
const {parseUnique}=require('./live-json'),{LivePublicPromotionsAdapter}=require('./live-public-adapter');
const waiting=new Map();let id=0;
const rl=readline.createInterface({input:process.stdin});rl.on('line',line=>{try{const answer=parseUnique(line),item=waiting.get(answer.id);if(item){waiting.delete(answer.id);clearTimeout(item.timer);answer.ok===true?item.resolve():item.reject(new Error('SOURCE_GATE_DENIED'));}}catch{for(const item of waiting.values())item.reject(new Error('SOURCE_GATE_PROTOCOL_FAILED'));}});
async function source(phase){const n=++id;N.check(n<=200,'Source request bound');return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{waiting.delete(n);reject(new Error('SOURCE_GATE_TIMEOUT'));},30000);waiting.set(n,{resolve,reject,timer});process.stdout.write(JSON.stringify({request:'SOURCE_CHECK',id:n,phase})+'\n');});}
async function main(file){
  const repo=path.resolve(__dirname,'../../..'),bytes=privateFile(file,repo);N.check(bytes.length<=65536,'Bounded worker job required');const j=parseUnique(bytes.toString());
  N.exact(j,['policy','mode','fabric_config','fabric_sha256','network_config','network_sha256','destination','wallet_root','wallet_backup','recovery_key','directory','payload']);
  N.check(j.policy==='APPLICATION_PROMOTIONS_CHAIN_JOB_V1'&&['EXECUTE','RECONCILE','RETRY_FABRIC','RETRY_PUBLIC'].includes(j.mode),'Explicit application publication mode required');
  return coordinate(j,repo);
}
function connectPinned(args){
  const base='../../fabric/integration/node_modules/';
  N.check(require(base+'@hyperledger/fabric-gateway/package.json').version==='1.8.0'&&require(base+'@grpc/grpc-js/package.json').version==='1.14.4','Pinned Gateway runtime required');
  return connectPromotions(args,{sdk:require(base+'@hyperledger/fabric-gateway'),grpc:require(base+'@grpc/grpc-js')});
}
async function coordinate(j,repo,{authorize=source,connect=connectPinned,Adapter=LivePublicPromotionsAdapter,loadWallet=W.load}={}){
  const source=authorize;
  await source('ENTRY');const key=privateFile(j.recovery_key,repo);N.check(key.length===32,'Dedicated recovery key required');
  const mode=['EXECUTE','RETRY_FABRIC'].includes(j.mode)?'EXECUTE':'READ_ONLY',scope=N.sha({policy:j.policy,payload:j.payload});
  const dir=path.resolve(j.directory);N.check(!dir.startsWith(repo+path.sep),'Recovery outside repository required');
  const fabricDirectory=path.join(dir,'fabric');const publicDirectory=path.join(dir,'public');
  if(j.mode==='EXECUTE'){for(const d of [fabricDirectory,publicDirectory])if(!fs.existsSync(d))fs.mkdirSync(d,{mode:0o700});}
  const fabricStore=createRetention({directory:fabricDirectory,repo,key,binding:{policy:RETENTION,operation:scope,selection_sha256:scope},readOnly:j.mode==='RECONCILE'});
  const fabric=connect({configFile:j.fabric_config,expectedConfigSha256:j.fabric_sha256,repo,retention:fabricStore.callbacks,authorize:source,mode});
  function retainOperatorRetry(chain,transaction_id){
    const prefix='operator-'+chain+'-retry-';
    N.check(fs.readdirSync(dir).filter(name=>name.startsWith(prefix)).length<3,'Operator retry bound reached; inspect original transaction');
    require('../deployment-files').write(path.join(dir,prefix+crypto.randomUUID()+'.json'),{policy:'PROMOTION_OPERATOR_EXACT_RETRY_V1',chain,transaction_id,scope,recorded_at:new Date().toISOString()});
  }
  let receipt,publicStore;
  try{
    const dest=parseUnique(privateFile(j.fabric_config,repo).toString()).destination;
    receipt=await fabricStore.session(async()=>{
      let plan=fabricStore.read('plan');
      if(!plan){N.check(j.mode==='EXECUTE','No original Fabric plan to reconcile');plan=await fabric.prepare(scope,j.payload,dest);}
      if(j.mode==='EXECUTE'&&!fabricStore.read('attempt')){
        await source('FABRIC_ATTEMPT');fabricStore.save('attempt',{transaction_id:plan.transaction_id});
        await fabric.submit(plan,j.payload,dest);fabricStore.save('ack',{transaction_id:plan.transaction_id});
      }
      if(j.mode==='RETRY_FABRIC'){
        N.check(fabricStore.read('attempt'),'No original Fabric attempt to retry');
        try{return await fabric.observeCommitted(plan,j.payload,dest);}
        catch(error){N.check(error?.code===2&&String(error.message).includes('no such transaction ID ['+plan.transaction_id+']')&&String(error.message).includes('in index'),'Original Fabric read must be reconciled before an exact retry');}
        await source('OPERATOR_RETRY_FABRIC');retainOperatorRetry('fabric',plan.transaction_id);
        await fabric.submit(plan,j.payload,dest);fabricStore.save('ack',{transaction_id:plan.transaction_id});
      }
      const observed=await fabric.observeCommitted(plan,j.payload,dest);
      const prior=fabricStore.read('final');if(prior)N.check(N.canonical(prior)===N.canonical(observed),'Original Fabric receipt changed');
      else if(['EXECUTE','RETRY_FABRIC'].includes(j.mode))fabricStore.save('final',observed);
      return observed;
    });
    if(j.mode==='RETRY_FABRIC')return {status:'FABRIC_ORIGINAL_RECONCILED',fabric:receipt,public:null};
    const payload={policy:'PROMOTIONS_PUBLIC_ANCHOR_V1',namespace:'promotions-anchor-v1',publication_id:j.payload.publication_id,
      public_sha256:j.payload.public_sha256,merkle_root:j.payload.merkle_root,fabric_destination_sha256:N.sha(receipt.destination),fabric_transaction_id:receipt.transaction_id,fabric_receipt_sha256:N.sha(receipt)};
    const publicScope=N.sha({policy:j.policy,payload,destination:j.destination});
    publicStore=createRetention({directory:publicDirectory,repo,key,binding:{policy:RETENTION,operation:publicScope,selection_sha256:publicScope},readOnly:j.mode==='RECONCILE'});
    const adapter=new Adapter({configFile:j.network_config,expectedConfigSha256:j.network_sha256,repo,destination:j.destination,authorize:source});
    const result=await publicStore.session(async()=>{
      let plan=publicStore.read('plan');
      if(!plan){
        N.check(j.mode==='EXECUTE','No original public plan to reconcile');await source('WALLET_RECOVERY');
        const wallet=await loadWallet(j.wallet_root,j.wallet_backup);N.check(!Buffer.from(wallet.privateKey.slice(2),'hex').equals(key),'Separate wallet and recovery key required');
        plan=await adapter.prepare(publicScope,payload,wallet);publicStore.save('plan',plan);
      }
      if(j.mode==='EXECUTE'&&!publicStore.read('attempt')){
        await source('PUBLIC_ATTEMPT');publicStore.save('attempt',{transaction_id:plan.transaction_id});
        await adapter.submit(plan,publicScope,payload);publicStore.save('ack',{transaction_id:plan.transaction_id});
      }
      if(j.mode==='RETRY_PUBLIC'){
        N.check(publicStore.read('attempt'),'No original public attempt to retry');
        const before=await adapter.observe(plan,publicScope,payload);
        if(before.status==='PENDING'&&before.reason==='BOTH_ORIGINAL_RECEIPTS_REQUIRED'){
          await source('OPERATOR_RETRY_PUBLIC');retainOperatorRetry('public',plan.transaction_id);
          await adapter.submit(plan,publicScope,payload);publicStore.save('ack',{transaction_id:plan.transaction_id});
        }
      }
      const observed=await adapter.observe(plan,publicScope,payload),prior=publicStore.read('final');
      if(prior)N.check(N.canonical(prior)===N.canonical(observed),'Original public receipt/finality changed');
      else if(observed.status==='FINAL'&&['EXECUTE','RETRY_PUBLIC'].includes(j.mode))publicStore.save('final',observed);
      return observed;
    });
    await source('RETURN');return {status:result.status==='FINAL'?'BOTH_CHAINS_VERIFIED':'PENDING',fabric:receipt,public:result,scope:'APPLICATION_PROMOTIONS_PREFIX_ONLY',independent_witness_deployment_verified:false};
  }finally{fabric.close();fabricStore.close();if(publicStore)publicStore.close();key.fill(0);rl.close();}
}
if(require.main===module)main(process.argv[2]).then(result=>process.stdout.write(JSON.stringify({result})+'\n')).catch(()=>{process.stdout.write(JSON.stringify({error:'APPLICATION_PROMOTIONS_CHAIN_OPERATION_STOPPED',outcome:'UNCERTAIN_RECONCILE_ORIGINAL_PLANS'})+'\n');rl.close();process.exitCode=1;});
else rl.close();
module.exports={main,coordinate};
