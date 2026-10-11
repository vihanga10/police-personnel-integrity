'use strict';
// Mandatory witnessed retention, local witness fixture only.
// Internal loaded-runner fixture boundary only. No request endpoint or deployment CLI.
const crypto=require('node:crypto');
const N=require('./network'),{argumentsFor}=require('./payload'),{destination,PublicFindingsAdapter}=require('./public-adapter');
const {createWitnessedRetention}=require('../../fabric/client/witnessed-retention');
const {POLICY:RETENTION}=require('../../fabric/client/findings-retention');
const {destination:fabricDestination}=require('../../fabric/client/findings-adapter');
const {validate:validateFabric}=require('../../fabric/findings-chaincode/lib/findings');
const POLICY='PROTECTED_FINDINGS_PUBLIC_FIXTURE_V1';
function selection(s){
    N.exact(s,['private_sha256','public_sha256','history_sha256','code_revision','network_config_sha256','destination','payload','fabric_receipt']);
    for(const k of ['private_sha256','public_sha256','history_sha256','network_config_sha256'])N.check(typeof s[k]==='string'&&/^[0-9a-f]{64}$/.test(s[k]),'Approved selection digest differs');
    N.check(typeof s.code_revision==='string'&&/^[0-9a-f]{40}$/.test(s.code_revision),'Committed source revision required');
    destination(s.destination);argumentsFor(s.payload);N.check(s.public_sha256===s.payload.public_sha256,'Public artifact/payload binding differs');
    const r=s.fabric_receipt;N.exact(r,['status','destination','payload','transaction_id','verification']);
    fabricDestination(r.destination);validateFabric(r.payload);N.exact(r.verification,['validation_code','organizations','block_sha256']);
    N.check(r.status==='FINAL'&&r.verification.validation_code==='VALID'&&N.canonical(r.verification.organizations)===N.canonical(['Org1MSP','Org2MSP'])&&/^[0-9a-f]{64}$/.test(r.verification.block_sha256)&&/^[0-9a-f]{64}$/.test(r.transaction_id),'Two organization VALID Fabric receipt required');
    N.check(r.payload.publication_id===s.payload.publication_id&&r.payload.public_sha256===s.payload.public_sha256&&r.payload.merkle_root===s.payload.merkle_root&&N.sha(r.destination)===s.payload.fabric_destination_sha256&&r.transaction_id===s.payload.fabric_transaction_id&&N.sha(r)===s.payload.fabric_receipt_sha256,'Original Fabric/public selection binding differs');return s;
}
function approval(a,keys,s,mode,fresh=true){
    N.exact(a,['body','signature']);const b=a.body;N.exact(b,['policy','key_id','mode','issued_at','expires_at','selection']);
    N.check(b.policy===POLICY&&b.mode===mode&&N.canonical(b.selection)===N.canonical(s),'Signed public approval selection differs');
    N.check(typeof b.key_id==='string'&&Object.hasOwn(keys,b.key_id),'Public approver not trusted');const key=crypto.createPublicKey(keys[b.key_id]);
    N.check(key.asymmetricKeyType==='ed25519'&&typeof a.signature==='string','Ed25519 public approval required');
    const sig=Buffer.from(a.signature,'base64');N.check(sig.length===64&&sig.toString('base64')===a.signature&&crypto.verify(null,Buffer.from(N.canonical(b)),key,sig),'Public approval signature invalid');
    const parse=t=>{N.check(typeof t==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(t)&&new Date(t).toISOString()===t,'Canonical UTC approval required');return Date.parse(t);};
    const issued=parse(b.issued_at),expires=parse(b.expires_at);N.check(expires>issued&&expires-issued<=600000,'Bounded public approval required');
    if(fresh)N.check(issued<=Date.now()&&Date.now()<expires,'Fresh public approval required');
}
function receipt(r,plan,s){
    N.exact(r,['status','destination','payload','transaction_id','verification']);N.exact(r.verification,['execution_status','finalized','independent_readback','block_sha256']);
    N.check(r.status==='FINAL'&&r.transaction_id===plan.transaction_id&&N.canonical(r.destination)===N.canonical(s.destination)&&N.canonical(r.payload)===N.canonical(s.payload)&&r.verification.execution_status===1&&r.verification.finalized===true&&r.verification.independent_readback===true&&/^[0-9a-f]{64}$/.test(r.verification.block_sha256),'Final public receipt binding differs');
}
async function runProtectedLoaded({verifiedSelection,approval:grant,trustedKeys,config,rpcs,wallet,directory,repo,key,checkLoaded,recoveryProtection,mode='RECONCILE',interrupt=async()=>{}}){
    N.check(['EXECUTE','RECONCILE'].includes(mode)&&typeof checkLoaded==='function'&&typeof interrupt==='function','Trusted public runner capabilities required');
    const s=structuredClone(selection(verifiedSelection)),a=structuredClone(grant),c=structuredClone(config);
    const keys=Object.freeze(Object.fromEntries(Object.entries(trustedKeys).map(([id,k])=>[id,crypto.createPublicKey(k).export({type:'spki',format:'pem'})])));
    N.check(N.configuration(c).sha256===s.network_config_sha256,'Approved network config differs');approval(a,keys,s,mode);
    const operation=N.sha({policy:POLICY,selection:s}),binding={policy:RETENTION,operation,selection_sha256:N.sha(s)};
    const store=createWitnessedRetention({directory,repo,key,binding,recoveryProtection,authorizeRecovery:()=>approval(a,keys,s,mode),readOnly:mode==='RECONCILE'});
    async function guard(action){
        await store.check();approval(a,keys,s,mode);
        // MUST replay the source, verify permit/commitments/history/witness and re-observe
        // the original Fabric receipt. Equality alone is not source authentication.
        N.check(N.canonical(await checkLoaded(action,structuredClone(s),mode))===N.canonical(s),'Full evidence/Fabric verification differs');
        approval(a,keys,s,mode);await store.check();
    }
    try{return await store.session(async()=>{
        await guard('ENTRY');const adapter=new PublicFindingsAdapter({rpcs,config:c,destination:s.destination,authorize:guard});
        let intent=store.read('intent');
        if(intent){N.exact(intent,['policy','operation','selection','initial_approval']);N.check(intent.policy===POLICY&&intent.operation===operation&&N.canonical(intent.selection)===N.canonical(s),'Original public intent differs');approval(intent.initial_approval,keys,s,'EXECUTE',false);}
        else{N.check(mode==='EXECUTE','Original public intent required');await guard('INTENT');await store.save('intent',{policy:POLICY,operation,selection:s,initial_approval:a});await interrupt('AFTER_INTENT');}
        let plan=store.read('plan');
        if(!plan){N.check(mode==='EXECUTE','Original signed public plan required');plan=await adapter.prepare(operation,s.payload,wallet);await guard('PLAN');await store.save('plan',plan);await interrupt('AFTER_PLAN');}
        adapter.validatePlan(plan,operation,s.payload);
        let attempt=store.read('attempt'),ack=store.read('ack'),saved=store.read('final');
        const marker={policy:POLICY,operation,plan_sha256:N.sha(plan),transaction_id:plan.transaction_id};
        if(attempt)N.check(N.canonical(attempt)===N.canonical(marker),'Original submission marker differs');
        N.check((!ack&&!saved)||attempt,'Submission lineage missing');
        if(ack)N.check(N.canonical(ack)===N.canonical({transaction_id:plan.transaction_id}),'Original acknowledgement differs');
        if(saved)receipt(saved,plan,s);
        if(!attempt){N.check(mode==='EXECUTE','Original public attempt required');await guard('ATTEMPT');await store.save('attempt',marker);await interrupt('AFTER_ATTEMPT');
            const result=await adapter.submit(plan,operation,s.payload);await interrupt('AFTER_SUBMIT');await guard('ACK');await store.save('ack',result);await interrupt('AFTER_ACK');}
        const observed=await adapter.observe(plan,operation,s.payload);
        if(saved){N.check(observed.status==='FINAL'&&N.canonical(saved)===N.canonical(observed),'Saved public finality no longer reconciles');}
        if(observed.status==='FINAL'){receipt(observed,plan,s);await guard('FINAL');if(mode==='EXECUTE')await store.save('final',observed);await interrupt('AFTER_FINAL');}
        await guard('RETURN');return {policy:POLICY,status:observed.status==='FINAL'?'ISOLATED_PUBLIC_VERIFIED':'PENDING',mode,operation,receipt:observed,
            recovery_sha256:store.inventoryDigest(),recovery_witness_fixture:true,both_chains_anchored:false,live_chain_verification:false};
    });}finally{store.close();}
}
module.exports={POLICY,runProtectedLoaded,selection,approval};
