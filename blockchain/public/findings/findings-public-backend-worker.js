'use strict';
// Trusted public backend library. The private-pipe entry has no provisioned runtime.
const readline=require('node:readline');
const crypto=require('node:crypto');
const N=require('./network'),R=require('./witnessed-public-runner');
const {privateFile}=require('../../fabric/client/findings-gateway');
const {createConfiguredClient}=require('../../fabric/client/recovery-witness-client-config');
const {loadConfiguredTransport}=require('./findings-public-backend-runtime');
const canonical=N.canonical,check=N.check,LIMIT=1048576;
function exact(v,keys){N.exact(v,keys);}
async function runJob(job,checkLoaded,loadTransport=loadConfiguredTransport){
    exact(job,['selection','approval','trustedKeys','mode','repo','networkConfigFile',
        'witnessConfigFile','witnessConfigSha256','directory','recoveryKeyFile']);
    check(['EXECUTE','RECONCILE'].includes(job.mode),'Public worker mode differs');
    const s=R.selection(job.selection);R.approval(job.approval,job.trustedKeys,s,job.mode);
    check(canonical(await checkLoaded('ENTRY',structuredClone(s),job.mode))===canonical(s),'Public backend entry differs');
    // Default always refuses. Tests pass backend-selected capabilities explicitly;
    // these cannot be specified in a pipe message or HTTP request.
    const transport=await loadTransport();
    check(transport?.fixture_transport===true&&Array.isArray(transport.rpcs)&&transport.rpcs.length===2&&
        transport.rpcs.every(r=>r.fixture_transport===true),'Only isolated public runtime capabilities allowed');
    const raw=privateFile(job.networkConfigFile,job.repo),config=JSON.parse(raw.toString('utf8'));
    check(raw.toString('utf8')===canonical(config)&&N.configuration(config).sha256===s.network_config_sha256,
        'Pinned canonical public network configuration required');
    const key=privateFile(job.recoveryKeyFile,job.repo);check(key.length===32,'Raw dedicated public recovery key required');
    const binding={policy:'FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1',operation:N.sha({policy:R.POLICY,selection:s}),selection_sha256:N.sha(s)};
    const witness=createConfiguredClient({file:job.witnessConfigFile,sha256:job.witnessConfigSha256,binding,repository:job.repo});
    check(witness.secure_witness===true&&witness.fixture_witness!==true,'Public backend requires mTLS recovery witness');
    try{
        const result=await R.runProtectedLoaded({verifiedSelection:s,approval:job.approval,trustedKeys:job.trustedKeys,
            config,rpcs:transport.rpcs,wallet:transport.wallet,directory:job.directory,repo:job.repo,key,
            checkLoaded,recoveryProtection:witness,mode:job.mode});
        return {...result,backend_public_runtime:'FIXTURE_ONLY',public_transport_enabled:false};
    }finally{key.fill(0);}
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
                if(message.kind==='denied'){
                    exact(message,['kind','id']);check(pending&&message.id===pending.id,'Backend denial order differs');
                    const wait=pending;pending=null;wait.reject(new Error('Backend guard denied'));
                }else{
                    exact(message,['kind','id','selection']);check(message.kind==='approved'&&pending&&message.id===pending.id,'Backend response order differs');
                    const wait=pending;pending=null;wait.resolve(message.selection);
                }
            }
        }catch(_){if(pending){pending.reject(new Error('Backend pipe rejected'));pending=null;}
            input.close();process.stdin.destroy();process.exitCode=1;}
    });
    input.on('close',()=>{if(pending){pending.reject(new Error('Backend pipe closed'));pending=null;}});
}
if(require.main===module)main().catch(()=>{process.exitCode=1;});
module.exports={runJob,main};
