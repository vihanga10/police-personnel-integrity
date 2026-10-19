'use strict';
const fs=require('node:fs');const path=require('node:path');
const {connections}=require('./gateway');const {execute,save,read,privatePath}=require('./journal');
const {authorize,recent}=require('./research-authorization');const {canonical,sha}=require('../chaincode/lib/evidence');
function check(v,m){if(!v)throw new Error(m);}
function absent(e){return [e.message,...(e.details||[]).map(d=>d.message)].some(m=>/Batch absent/.test(m));}
async function run(connection,p,directory) {
    await connection.verifyNetwork();const network=connection.network;
    check(canonical(network)===canonical(p.network),'Research network binding differs');
    privatePath(directory,true);const batch=p.publication.batch_publication_id,base=connection.driver;
    if(p.mode==='VALIDATE') {
        let missing=0;try{await base.observe('ReadBatch',[batch]);}catch(e){if(!absent(e))throw e;missing++;}
        const summary={status:'PASSED',mode:p.mode,public_payload_sha256:p.public_payload_sha256,officers:6596,network,delivery_state:missing?'PLANNED':'EXISTING_REQUIRES_RECONCILIATION',research_transactions_submitted:0};
        console.log('Research anchoring validation: PASSED');return summary;
    }
    const driver={...base,endorse:async(...args)=>{check(p.mode==='EXECUTE','Read-only reconciliation cannot endorse');recent(p);return base.endorse(...args);},
        submit:async(...args)=>{check(p.mode==='EXECUTE','Read-only reconciliation cannot submit');recent(p);return base.submit(...args);}};
    const jobs=[{name:'batch',method:'CreateBatch',args:[canonical(p.plan.metadata)],read_method:'ReadBatch',read_args:[batch]}];
    for(const chunk of p.plan.chunks)jobs.push({name:'chunk-'+String(chunk.index).padStart(3,'0'),method:'AppendOfficers',args:[batch,String(chunk.index),canonical(chunk.records)],read_method:'ReadChunk',read_args:[batch,String(chunk.index)]});
    jobs.push({name:'seal',method:'SealBatch',args:[batch],read_method:'ReadSeal',read_args:[batch]});
    for(let i=0;i<jobs.length;i++){
        if(p.mode==='RECONCILE')check(fs.existsSync(path.join(directory,jobs[i].name+'.valid.json')),'Original transaction receipt missing');
        await execute({driver,directory,network,job:jobs[i]});console.log('Research transaction verified:',i+1,'/ 68');
    }
    for(let i=0;i<p.publication.officers.length;i++){
        const row=p.publication.officers[i],values=await base.observe('ReadOfficer',[batch,row.publication_id]);
        check(Object.keys(values).sort().join(',')==='Org1MSP,Org2MSP','Both organizations required');
        check(canonical(values.Org1MSP)===canonical(values.Org2MSP),'Officer peer records differ');
        for(const v of Object.values(values))check(v.publication_id===row.publication_id&&v.commitment===row.commitment&&v.commitment_version===row.commitment_version&&v.batch_publication_id===batch,'Officer commitment readback differs');
        if((i+1)%500===0||i===6595)console.log('Research officer readback:',i+1,'/ 6596');
    }
    const summary={status:'PASSED',mode:p.mode,public_payload_sha256:p.public_payload_sha256,officers:6596,original_valid_transactions:68,two_organization_readback:true,network,
        merkle_root:p.publication.merkle_root,batch_publication_id:batch,classification:'UNASSESSED'};
    console.log('Research Fabric anchoring/reconciliation: PASSED');return summary;
}
async function main(){const [config,authorizationFile,journal,resultFile,mode]=process.argv.slice(2);let connection;
    try{check(process.argv.length===7,'Expected research runner arguments');const secret=Buffer.from(fs.readFileSync(0,'utf8').trim(),'hex');
        const p=authorize(read(authorizationFile),secret,mode);connection=connections(config,false,'officer-evidence-v1');
        const summary=await run(connection,p,journal);save(resultFile,summary);console.log(JSON.stringify(summary));return 0;
    }catch(e){console.log('Research Fabric runner stopped:',e.constructor.name);
        for(const line of String(e.stack||'').split('\n').slice(1)){const m=line.match(/([^/\\():]+\.js):(\d+):(\d+)/);if(m)console.log('Location:',m[1],'line='+m[2]);}
        if(Number.isInteger(e.code))console.log('Numeric error code:',e.code);
        console.log('Original transactions and private journals preserved. No deletion or replacement commitment requested.');return 1;
    }finally{if(connection)connection.close();}}
if(require.main===module)main().then(c=>process.exitCode=c);
module.exports={run};
