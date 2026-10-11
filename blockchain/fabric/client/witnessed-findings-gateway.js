'use strict';
// Mandatory witnessed retention, local witness fixture only.
// Internal loaded-runner boundary. No request route, CLI or live provisioning.
const crypto=require('node:crypto');
const {canonical,sha,validate}=require('../findings-chaincode/lib/findings');
const {destination}=require('./findings-adapter');
const {createWitnessedRetention}=require('./witnessed-retention');
const {POLICY:RETENTION}=require('./findings-retention');
const POLICY='PROTECTED_FINDINGS_GATEWAY_BRIDGE_V1';
const check=(v,m)=>{if(!v)throw new Error(m);};
function exact(v,k){check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...k].sort().join(','),'Protected bridge schema differs');}
function selection(v){exact(v,['private_sha256','public_sha256','history_sha256','code_revision','gateway_config_sha256','destination','payload']);
    for(const k of ['private_sha256','public_sha256','history_sha256','gateway_config_sha256'])check(typeof v[k]==='string'&&/^[0-9a-f]{64}$/.test(v[k]),'Approved selection digest differs');
    check(typeof v.code_revision==='string'&&/^[0-9a-f]{40}$/.test(v.code_revision),'Committed source revision required');
    destination(v.destination);validate(v.payload);check(v.public_sha256===v.payload.public_sha256,'Public artifact/payload binding differs');return v;
}
function approval(a,keys,s,mode,fresh=true){exact(a,['body','signature']);const b=a.body;
    exact(b,['policy','key_id','mode','issued_at','expires_at','selection']);check(b.policy===POLICY&&b.mode===mode&&canonical(b.selection)===canonical(s),'Signed bridge approval selection differs');
    check(Object.hasOwn(keys,b.key_id),'Bridge approver not trusted');const key=crypto.createPublicKey(keys[b.key_id]);check(key.asymmetricKeyType==='ed25519','Ed25519 approval key required');
    check(typeof a.signature==='string','Approval signature differs');const sig=Buffer.from(a.signature,'base64');
    check(sig.length===64&&sig.toString('base64')===a.signature&&crypto.verify(null,Buffer.from(canonical(b)),key,sig),'Bridge signature invalid');
    const parse=t=>{check(typeof t==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(t)&&new Date(t).toISOString()===t,'UTC approval timestamp required');return Date.parse(t);};
    const issued=parse(b.issued_at),expires=parse(b.expires_at);check(expires>issued&&expires-issued<=600000,'Bounded approval required');
    if(fresh)check(issued<=Date.now()&&Date.now()<expires,'Fresh bridge approval required');
}
function receipt(r,p,s){exact(r,['status','destination','payload','transaction_id','verification']);exact(r.verification,['validation_code','organizations','block_sha256']);
    check(r.status==='FINAL'&&r.transaction_id===p.transaction_id&&canonical(r.destination)===canonical(s.destination)&&canonical(r.payload)===canonical(s.payload)&&
        r.verification.validation_code==='VALID'&&canonical(r.verification.organizations)===canonical(['Org1MSP','Org2MSP'])&&/^[0-9a-f]{64}$/.test(r.verification.block_sha256),'Verified Fabric receipt differs');}
async function runProtectedLoaded({verifiedSelection,approval:grant,trustedKeys,directory,repo,key,checkLoaded,adapterFactory,recoveryProtection,mode='RECONCILE'}){
    // MUST be composed by a trusted backend, never with request-chosen callbacks/keys.
    // checkLoaded must re-run permit, full artifact verification and witnessed history.
    check(['EXECUTE','RECONCILE'].includes(mode)&&typeof checkLoaded==='function'&&typeof adapterFactory==='function','Trusted protected-runner capabilities required');
    const s=structuredClone(selection(verifiedSelection)),a=structuredClone(grant),keys=Object.freeze(Object.fromEntries(Object.entries(trustedKeys).map(([id,k])=>[id,crypto.createPublicKey(k).export({type:'spki',format:'pem'})])));
    const operation=sha({policy:POLICY,selection:s}),binding={policy:RETENTION,operation,selection_sha256:sha(s)};
    approval(a,keys,s,mode);
    const store=createWitnessedRetention({directory,repo,key,binding,recoveryProtection,authorizeRecovery:()=>approval(a,keys,s,mode),readOnly:mode==='RECONCILE'});let adapter;
    async function guard(action){await store.check();approval(a,keys,s,mode);
        check(canonical(await checkLoaded(action,structuredClone(s),mode))===canonical(s),'Full loaded evidence/permit/witness check differs');
        approval(a,keys,s,mode);await store.check();}
    try{return await store.session(async()=>{
        await guard('ENTRY');
        adapter=await adapterFactory({retention:store.callbacks,authorize:guard,mode:mode==='EXECUTE'?'EXECUTE':'READ_ONLY',
            expectedConfigSha256:s.gateway_config_sha256,destination:structuredClone(s.destination)});
        check(adapter&&typeof adapter.prepare==='function'&&typeof adapter.submit==='function'&&typeof adapter.observeCommitted==='function'&&
            typeof adapter.validatePlan==='function','Verified findings adapter required');
        let intent=store.read('intent');
        if(intent){exact(intent,['policy','operation','selection','initial_approval']);check(intent.policy===POLICY&&intent.operation===operation&&canonical(intent.selection)===canonical(s),'Original bridge intent differs');approval(intent.initial_approval,keys,s,'EXECUTE',false);}
        else{check(mode==='EXECUTE','Original bridge intent required for reconciliation');await guard('INTENT');await store.save('intent',{policy:POLICY,operation,selection:s,initial_approval:a});}
        let plan=store.read('plan');
        if(!plan){check(mode==='EXECUTE','Original retained plan required for reconciliation');await guard('PREPARE');plan=await adapter.prepare(operation,s.payload,s.destination);}
        adapter.validatePlan(plan,s.payload,s.destination);check(plan.operation===operation&&canonical(store.read('plan'))===canonical(plan),'Original durable transaction differs');
        let attempt=store.read('attempt'),ack=store.read('ack'),saved=store.read('final');
        const marker={policy:POLICY,operation,plan_sha256:sha(plan),transaction_id:plan.transaction_id};
        if(attempt)check(canonical(attempt)===canonical(marker),'Submission marker differs');
        check((!ack&&!saved)||attempt,'Submission lineage missing');
        if(ack)check(canonical(ack)===canonical({transaction_id:plan.transaction_id}),'Submission acknowledgement differs');
        if(saved)receipt(saved,plan,s);
        if(!attempt){check(mode==='EXECUTE','Original submission attempt required for reconciliation');await guard('BEFORE_ATTEMPT');await store.save('attempt',marker);
            // The marker is durable BEFORE entering the transport. Never auto-resubmit.
            await guard('BEFORE_SUBMIT');const result=await adapter.submit(plan,s.payload,s.destination);
            check(canonical(result)===canonical({transaction_id:plan.transaction_id}),'Submission acknowledgement differs');
            await guard('ACK');await store.save('ack',result);
        }
        await guard('OBSERVE');const observed=await adapter.observeCommitted(plan,s.payload,s.destination);receipt(observed,plan,s);
        if(saved)check(canonical(saved)===canonical(observed),'Original final receipt differs');
        await guard('FINAL');if(mode==='EXECUTE')await store.save('final',observed);
        await guard('RETURN');
        return {policy:POLICY,status:'FABRIC_COMMIT_VERIFIED',mode,operation,receipt:observed,
            recovery_sha256:store.inventoryDigest(),recovery_witness_fixture:true,both_chains_anchored:false};
    });}finally{try{if(adapter&&typeof adapter.close==='function')await adapter.close();}finally{store.close();}}
}
module.exports={runProtectedLoaded,POLICY,approval,selection};
