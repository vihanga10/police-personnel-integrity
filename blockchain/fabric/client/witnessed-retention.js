'use strict';
const path=require('node:path');
const {createRetention}=require('./findings-retention'),{STAGES,extendsOne,isWitnessClient}=require('./recovery-witness');
const {canonical,sha}=require('../findings-chaincode/lib/findings');
const check=(v,m)=>{if(!v)throw new Error(m);};
function createWitnessedRetention(options){
    const {recoveryProtection:witness,authorizeRecovery=()=>{},readOnly=false,binding,directory,repo}=options;
    check(witness?.fixture_witness===true&&canonical(witness.binding)===canonical(binding)&&typeof witness.read==='function'&&typeof witness.advance==='function','Mandatory bound recovery witness required');
    const outside=(a,b)=>{const rel=path.relative(path.resolve(a),path.resolve(b));return rel==='..'||rel.startsWith('..'+path.sep);};
    check(typeof witness.authority_directory==='string'&&path.isAbsolute(witness.authority_directory)&&outside(directory,witness.authority_directory)&&outside(witness.authority_directory,directory)&&outside(repo,witness.authority_directory)&&outside(witness.authority_directory,repo),'Separate witness authority storage required');
    check(isWitnessClient(witness),'Authenticated witness client instance required');
    check(typeof authorizeRecovery==='function','Trusted recovery authorization required');
    const read=witness.read.bind(witness),advance=witness.advance.bind(witness),local=createRetention(options);let active=false,broken=false;
    const snapshot=()=>({stages:STAGES.map(stage=>({stage,value:local.read(stage)})).filter(x=>x.value!==null).map(x=>({stage:x.stage,sha256:sha(x.value)}))});
    async function confirm({repair=false}={}){
        check(!broken,'Witnessed retention stopped; reopen for controlled recovery');local.check();const before=snapshot(),remote=await read();local.check();check(canonical(snapshot())===canonical(before),'Local recovery changed during witness query');
        if(canonical(before)!==canonical(remote.snapshot)){
            check(repair&&!readOnly&&extendsOne(remote.snapshot,before),'Recovery rollback, divergence or unconfirmed local checkpoint');
            await authorizeRecovery();await advance(remote,before);await authorizeRecovery();const again=await read();check(canonical(again.snapshot)===canonical(before)&&canonical(snapshot())===canonical(before),'Recovery witness confirmation differs');
        }
        return remote;
    }
    async function save(stage,value){check(active&&!readOnly&&!broken,'Exclusive witnessed retention session required');const previous=await confirm();await authorizeRecovery();local.save(stage,value);const next=snapshot();
        if(canonical(previous.snapshot)!==canonical(next)){
            try{await authorizeRecovery();await advance(previous,next);await authorizeRecovery();await confirm();}catch(e){broken=true;throw e;}
        }
    }
    return {read:local.read,async check(){await confirm();},async save(stage,value){await save(stage,value);},
        async session(fn){check(!active,'Witnessed session already active');return local.session(async()=>{active=true;try{await confirm({repair:!readOnly});return await fn();}finally{active=false;}});},
        callbacks:{load:async op=>{check(op===binding.operation,'Witnessed operation differs');await confirm();return local.read('plan');},save:async(op,plan)=>{check(op===binding.operation,'Witnessed operation differs');await save('plan',plan);}},
        inventoryDigest:local.inventoryDigest,close:local.close};
}
module.exports={createWitnessedRetention};
