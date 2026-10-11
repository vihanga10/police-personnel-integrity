'use strict';
// Fixed trusted-backend worker. stdin/stdout are private pipes, never HTTP APIs.
const readline=require('node:readline');
const {canonical,sha}=require('../findings-chaincode/lib/findings');
const R=require('./witnessed-findings-gateway');
const {POLICY:RETENTION}=require('./findings-retention');
const {createConfiguredClient}=require('./recovery-witness-client-config');
const {privateFile,connectFindings}=require('./findings-gateway');
const check=(v,m)=>{if(!v)throw new Error(m);};
const LIMIT=1048576;
function exact(v,keys){check(v&&Object.getPrototypeOf(v)===Object.prototype&&
    Reflect.ownKeys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k)),'Backend worker schema differs');}
async function runJob(job,checkLoaded){
    exact(job,['selection','approval','trustedKeys','mode','repo','gatewayConfigFile','witnessConfigFile',
        'witnessConfigSha256','directory','recoveryKeyFile']);
    check(['EXECUTE','RECONCILE'].includes(job.mode),'Backend worker mode differs');
    const s=R.selection(job.selection);R.approval(job.approval,job.trustedKeys,s,job.mode);
    check(canonical(await checkLoaded('ENTRY',structuredClone(s),job.mode))===canonical(s),'Backend entry verification differs');
    const key=privateFile(job.recoveryKeyFile,job.repo);
    check(key.length===32,'Dedicated raw 32-byte recovery key required');
    const binding={policy:RETENTION,operation:sha({policy:R.POLICY,selection:s}),selection_sha256:sha(s)};
    const witness=createConfiguredClient({file:job.witnessConfigFile,sha256:job.witnessConfigSha256,
        binding,repository:job.repo});
    check(witness.secure_witness===true&&witness.fixture_witness!==true,'Backend requires mTLS recovery witness');
    // Dependencies are pinned by the integration lockfile; no download/global lookup.
    const sdk=require('../integration/node_modules/@hyperledger/fabric-gateway');
    const grpc=require('../integration/node_modules/@grpc/grpc-js');
    return R.runProtectedLoaded({verifiedSelection:s,approval:job.approval,trustedKeys:job.trustedKeys,
        directory:job.directory,repo:job.repo,key,mode:job.mode,checkLoaded,recoveryProtection:witness,
        adapterFactory:options=>connectFindings({...options,configFile:job.gatewayConfigFile,repo:job.repo},
            {sdk,grpc})});
}
async function main(){
    check(!process.stdin.isTTY&&!process.stdout.isTTY,'Backend private pipes required');
    const input=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
    let started=false,sequence=0,pending;
    const emit=value=>{const line=canonical(value)+'\n';check(Buffer.byteLength(line)<=LIMIT,'Backend output bound');process.stdout.write(line);};
    function guard(action,selection,mode){
        check(!pending,'Concurrent backend guard refused');const id=++sequence;
        return new Promise((resolve,reject)=>{pending={id,resolve,reject};emit({kind:'guard',id,action,selection,mode});});
    }
    input.on('line',line=>{
        try{
            check(Buffer.byteLength(line)<=LIMIT,'Backend input bound');const message=JSON.parse(line);
            check(canonical(message)===line,'Canonical backend frame required');
            if(!started){exact(message,['kind','job']);check(message.kind==='start','Backend start required');started=true;
                runJob(message.job,guard).then(result=>{emit({kind:'result',result});input.close();process.stdin.destroy();},
                    ()=>{emit({kind:'error'});input.close();process.stdin.destroy();process.exitCode=1;});
            }else{
                exact(message,['kind','id','selection']);check(message.kind==='approved'&&pending&&message.id===pending.id,'Backend response order differs');
                const wait=pending;pending=null;wait.resolve(message.selection);
            }
        }catch(_){if(pending){pending.reject(new Error('Backend pipe rejected'));pending=null;}
            input.close();process.stdin.destroy();process.exitCode=1;}
    });
    input.on('close',()=>{if(pending){pending.reject(new Error('Backend pipe closed'));pending=null;}});
}
if(require.main===module)main().catch(()=>{process.exitCode=1;});
module.exports={runJob};
