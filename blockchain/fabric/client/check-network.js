'use strict';
// No input publication file: every commitment below is random test material, never research data.
const fs=require('node:fs');const path=require('node:path');const crypto=require('node:crypto');
const {canonical,sha,tree,POLICY}=require('../chaincode/lib/evidence');
const {execute,save,read,privatePath}=require('./journal');
const {connections}=require('./gateway');
function check(value,message){if(!value)throw new Error(message);}
function errorText(error){return [error.message,...(error.details||[]).map(d=>d.message)].join(' ');}
function makeData() {
    const records=Array.from({length:6596},()=>({publication_id:crypto.randomBytes(32).toString('hex'),commitment_version:1,commitment:crypto.randomBytes(32).toString('hex')})).sort((a,b)=>a.publication_id.localeCompare(b.publication_id));
    const publication={policy:POLICY,commitment_version:1,key_version:'commit-v1',batch_publication_id:crypto.randomBytes(32).toString('hex'),
        officers:records,shared_commitment:crypto.randomBytes(32).toString('hex'),coverage_commitment:crypto.randomBytes(32).toString('hex'),batch_commitment:crypto.randomBytes(32).toString('hex')};
    publication.merkle_root=tree([...records.map(r=>({kind:'OFFICER',...r})),{kind:'BATCH',publication_id:publication.batch_publication_id,commitment:publication.batch_commitment}]);
    const {officers,...metadata}=publication;metadata.officer_count=6596;metadata.public_payload_sha256=sha(publication);
    return {publication,metadata};
}
async function main() {
    const [configFile,directory]=process.argv.slice(2);let connection,reader;
    try {check(configFile&&directory&&process.argv.length===4,'Supply configuration and private journal paths');
        privatePath(directory,true);connection=connections(configFile);await connection.verifyNetwork();const {driver,network}=connection;
        const fixtureFile=path.join(directory,'fixture.json');if(!fs.existsSync(fixtureFile))save(fixtureFile,{network,...makeData()});
        const fixture=read(fixtureFile);check(canonical(fixture.network)===canonical(network),'Fixture network differs');
        const batch=fixture.metadata.batch_publication_id;
        const jobs=[{name:'batch',method:'CreateBatch',args:[canonical(fixture.metadata)],read_method:'ReadBatch',read_args:[batch]}];
        for(let i=0;i<66;i++)jobs.push({name:'chunk-'+String(i).padStart(3,'0'),method:'AppendOfficers',args:[batch,String(i),canonical(fixture.publication.officers.slice(i*100,(i+1)*100))],read_method:'ReadChunk',read_args:[batch,String(i)]});
        jobs.push({name:'seal',method:'SealBatch',args:[batch],read_method:'ReadSeal',read_args:[batch]});
        const stages=['AFTER_PREPARE','AFTER_SUBMIT','AFTER_STATUS','AFTER_RECEIPT'];
        for(let i=0;i<jobs.length;i++) {
            if(i<stages.length && !fs.existsSync(path.join(directory,'injection-'+i+'.json'))) {
                try{await execute({driver,directory,network,job:jobs[i],interrupt:stages[i]});throw new Error('Expected interruption absent');}
                catch(error){check(error.message==='INJECTED_'+stages[i],'Unexpected network failure during injection');}
                save(path.join(directory,'injection-'+i+'.json'),{stage:stages[i],status:'OBSERVED'});
            }
            await execute({driver,directory,network,job:jobs[i]});console.log('Fabric test transaction verified:',i+1,'/',jobs.length);
        }
        // Replay rechecks VALID status and both peers; it never creates another transaction.
        for(const job of jobs)await execute({driver,directory,network,job});
        for(let i=0;i<fixture.publication.officers.length;i++) {
            const row=fixture.publication.officers[i];const observed=await driver.observe('ReadOfficer',[batch,row.publication_id]);
            for(const stored of Object.values(observed))check(stored.publication_id===row.publication_id&&stored.commitment===row.commitment&&stored.commitment_version===1&&stored.batch_publication_id===batch,'Officer readback differs');
            check(canonical(observed.Org1MSP)===canonical(observed.Org2MSP),'Officer peers differ');
            if((i+1)%500===0||i===6595)console.log('Fabric test officer readback:',i+1,'/ 6596');
        }
        let rejected=false;
        try{const altered=fixture.publication.officers.slice(0,100).map(r=>({...r}));altered[0].commitment='f'.repeat(64);await driver.endorse('AppendOfficers',[batch,'0',canonical(altered)]);}
        catch(error){check(/Conflicting immutable chunk/.test(errorText(error)),'Unexpected conflict test failure');rejected=true;}
        check(rejected,'Conflicting overwrite accepted');
        reader=connections(configFile,true);await reader.verifyNetwork();rejected=false;
        try{await reader.driver.endorse('CreateBatch',[canonical(fixture.metadata)]);}
        catch(error){check(/Anchoring identity not authorized/.test(errorText(error)),'Unexpected authorization test failure');rejected=true;}
        check(rejected,'Unprivileged identity could anchor');
        const summary={status:'PASSED',test_officers:6596,valid_transactions:68,interruption_cases:4,two_peer_readback:true,network,
            research_commitments_submitted:0,fixture_payload_sha256:sha(fixture.publication)};
        const resultFile=path.join(directory,'PASSED.json');if(fs.existsSync(resultFile))check(canonical(read(resultFile))===canonical(summary),'Prior summary differs');else save(resultFile,summary);
        console.log('Real Fabric deployment/recovery checks: PASSED');console.log(JSON.stringify(summary));
        console.log('Test commitments remain in the ledger. No research evidence, database connections, source keys, public-chain submissions or audit results used.');
        return 0;
    }catch(error){console.log('Fabric checks stopped:',error.constructor.name);console.log('Private journals and existing ledger preserved; no deletion/reset.');return 1;}
    finally{if(reader)reader.close();if(connection)connection.close();}
}
if(require.main===module)main().then(code=>process.exitCode=code);
module.exports={makeData};
