'use strict';
// Isolation-only composition. No production loader, HTTP provider or research keys.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const N=require('../network'),P=require('../protected-public-runner'),{localEvm}=require('./local-evm');
const random=()=>crypto.randomBytes(32).toString('hex');
const POLICY='PPI_ISOLATED_FINDINGS_DUAL_CHAIN_V1';
function publicPayload(r){
    return {policy:'FINDINGS_PUBLIC_ANCHOR_V1',namespace:'findings-anchor-v1',publication_id:r.payload.publication_id,public_sha256:r.payload.public_sha256,merkle_root:r.payload.merkle_root,fabric_destination_sha256:N.sha(r.destination),fabric_transaction_id:r.transaction_id,fabric_receipt_sha256:N.sha(r)};
}
function signed(policy,selection,mode,approver){const now=Date.now(),body={policy,key_id:'fixture',mode,issued_at:new Date(now-1000).toISOString(),expires_at:new Date(now+599000).toISOString(),selection};return {body,signature:crypto.sign(null,Buffer.from(N.canonical(body)),approver.privateKey).toString('base64')};}
function inventory(dir){return fs.readdirSync(dir).sort().map(n=>[n,crypto.createHash('sha256').update(fs.readFileSync(path.join(dir,n))).digest('hex')]);}
async function checks({root,fabric,repo,done=()=>{}}){
    const completed=[];let index=0;
    async function scenario(name,fn){await fn();completed.push(name);done(name);}
    async function session(fn,{lostFabric=false,stopBetween=false}={}){
        const number=++index,dir=path.join(root,'dual-'+number);fs.mkdirSync(dir,{mode:0o700});
        const fdir=path.join(dir,'fabric'),pdir=path.join(dir,'public');for(const d of [fdir,pdir])fs.mkdirSync(d,{mode:0o700});
        const fp={policy:'FINDINGS_FABRIC_ANCHOR_V1',namespace:'findings-anchor-v1',publication_id:random(),public_sha256:random(),merkle_root:random(),publication_commitment:random()};
        const fkey=crypto.randomBytes(32),pkey=crypto.randomBytes(32),approver=crypto.generateKeyPairSync('ed25519');
        const fspec=fabric.scope(fp),frun=mode=>fabric.run({selection:fspec,mode,directory:fdir,key:fkey,lost:lostFabric&&mode==='EXECUTE'});
        let initial;
        if(lostFabric){await assert.rejects(frun('EXECUTE'),/INJECTED_ACK_LOSS/);initial=await fabric.eventually(()=>frun('RECONCILE'));}
        else initial=await frun('EXECUTE');
        assert.equal(initial.status,'FABRIC_COMMIT_VERIFIED');
        // A fresh public selection is built ONLY from the original verified receipt.
        const receipt=initial.receipt,payload=publicPayload(receipt);
        if(stopBetween){assert.deepEqual(inventory(pdir),[]);initial=await frun('RECONCILE');assert.deepEqual(initial.receipt,receipt);}
        const evm=await localEvm();
        try{
            const selection={private_sha256:fspec.private_sha256,public_sha256:fp.public_sha256,history_sha256:fspec.history_sha256,code_revision:fspec.code_revision,network_config_sha256:N.sha(evm.config),destination:evm.destination,payload,fabric_receipt:receipt};
            let rechecks=0,deny=false;
            const run=(mode='EXECUTE',interrupt=async()=>{})=>P.runProtectedLoaded({verifiedSelection:selection,approval:signed(P.POLICY,selection,mode,approver),trustedKeys:{fixture:approver.publicKey.export({type:'spki',format:'pem'})},config:evm.config,rpcs:evm.rpcs,wallet:mode==='EXECUTE'?evm.wallet:undefined,directory:pdir,repo,key:pkey,mode,interrupt,
                checkLoaded:async(_action,s)=>{assert.equal(deny,false,'Injected Fabric authorization/readback failure');const again=await frun('RECONCILE');rechecks++;assert.deepEqual(again.receipt,receipt);assert.deepEqual(s,selection);return selection;}});
            await fn({evm,run,selection,pdir,fdir,frun,receipt,deny:()=>{deny=true;},rechecks:()=>rechecks});
        }finally{await evm.close();}
    }
    await scenario('Uncertain Fabric attempt before delivery blocks public execution and automatic replay',async()=>{
        const directory=path.join(root,'dual-fabric-before');fs.mkdirSync(directory,{mode:0o700});
        const payload={policy:'FINDINGS_FABRIC_ANCHOR_V1',namespace:'findings-anchor-v1',publication_id:random(),public_sha256:random(),merkle_root:random(),publication_commitment:random()};
        const selection=fabric.scope(payload),key=crypto.randomBytes(32);
        await assert.rejects(fabric.run({selection,mode:'EXECUTE',directory,key,lost:'before'}),/INJECTED_BEFORE_DELIVERY/);
        // Reconcile only once: unknown transaction is a stop, never permission to issue another plan.
        await assert.rejects(fabric.run({selection,mode:'RECONCILE',directory,key,lost:false}));
        assert.equal(fs.existsSync(path.join(directory,'public')),false);
    });
    await scenario('Fabric VALID receipt binds exact real EVM event/storage and both retained transaction IDs',()=>session(async s=>{
        const r=await s.run();assert.equal(r.status,'ISOLATED_PUBLIC_VERIFIED');assert.equal(r.both_chains_anchored,false);assert.equal(r.live_chain_verification,false);assert.match(r.receipt.transaction_id,/^0x[0-9a-f]{64}$/);assert.match(s.receipt.transaction_id,/^[0-9a-f]{64}$/);
        assert.equal(r.receipt.payload.fabric_receipt_sha256,N.sha(s.receipt));assert.ok(s.rechecks()>0);assert.equal(s.evm.state.broadcasts,1);assert.equal(s.evm.state.signs,1);
        const before=inventory(s.pdir),again=await s.run('RECONCILE');assert.deepEqual(again.receipt,r.receipt);assert.deepEqual(inventory(s.pdir),before);assert.equal(s.evm.state.broadcasts,1);
    }));
    await scenario('Interruption between chains resumes from original Fabric lineage',()=>session(async s=>{assert.equal((await s.run()).status,'ISOLATED_PUBLIC_VERIFIED');},{stopBetween:true}));
    await scenario('Fabric acknowledgement loss recovers before public signing',()=>session(async s=>{assert.equal((await s.run()).status,'ISOLATED_PUBLIC_VERIFIED');assert.equal(s.evm.state.broadcasts,1);},{lostFabric:true}));
    for(const phase of ['AFTER_INTENT','AFTER_PLAN','AFTER_ATTEMPT','AFTER_SUBMIT','AFTER_ACK','AFTER_FINAL'])await scenario('Restart after '+phase,()=>session(async s=>{
        await assert.rejects(s.run('EXECUTE',async p=>{if(p===phase)throw new Error('INJECTED_STOP');}),/INJECTED_STOP/);
        const signs=s.evm.state.signs,broadcasts=s.evm.state.broadcasts;
        if(['AFTER_INTENT','AFTER_PLAN'].includes(phase)){assert.equal(broadcasts,0);assert.equal((await s.run()).status,'ISOLATED_PUBLIC_VERIFIED');}
        else{const before=inventory(s.pdir),r=await s.run('RECONCILE');assert.equal(r.status,phase==='AFTER_ATTEMPT'?'PENDING':'ISOLATED_PUBLIC_VERIFIED');assert.deepEqual(inventory(s.pdir),before);assert.equal(s.evm.state.broadcasts,broadcasts);}
        assert.equal(s.evm.state.signs,phase==='AFTER_INTENT'?signs+1:signs);
    }));
    for(const delivered of [false,true])await scenario('Uncertain public submission '+(delivered?'after':'before')+' delivery',()=>session(async s=>{
        s.evm.state[delivered?'throwAfter':'throwBefore']=true;await assert.rejects(s.run(),/Uncertain original submission/);
        const before=inventory(s.pdir),r=await s.run('RECONCILE');assert.equal(r.status,delivered?'ISOLATED_PUBLIC_VERIFIED':'PENDING');assert.deepEqual(inventory(s.pdir),before);assert.equal(s.evm.state.broadcasts,1);assert.equal(s.evm.state.signs,1);
    }));
    await scenario('Missing receipt/finality remain pending then read-only recover without rebroadcast',()=>session(async s=>{
        s.evm.state.finalized=false; // deployment preflight requires a finalized fixture state
        await assert.rejects(s.run(),/Finalized deployment/);assert.equal(s.evm.state.broadcasts,0);
        s.evm.state.finalized=true;s.evm.state.mine=false;
        const pending=await s.run();assert.equal(pending.status,'PENDING');await s.evm.mine();s.evm.state.hide[1]=true;assert.equal((await s.run('RECONCILE')).status,'PENDING');s.evm.state.hide[1]=false;
        const before=inventory(s.pdir);assert.equal((await s.run('RECONCILE')).status,'ISOLATED_PUBLIC_VERIFIED');assert.deepEqual(inventory(s.pdir),before);assert.equal(s.evm.state.broadcasts,1);
    }));
    await scenario('Provider disagreement, saved-final regression and changed Fabric gate fail closed',()=>session(async s=>{
        await s.run();s.evm.state.mutate=(method,_p,v,i)=>{if(method==='eth_getTransactionReceipt'&&i===1&&v)v.blockHash='0x'+'ab'.repeat(32);return v;};await assert.rejects(s.run('RECONCILE'),/receipts disagree/);
        s.evm.state.mutate=null;s.evm.state.hide[0]=true;await assert.rejects(s.run('RECONCILE'),/no longer reconciles/);s.evm.state.hide[0]=false;s.deny();await assert.rejects(s.run('RECONCILE'),/Fabric authorization/);assert.equal(s.evm.state.broadcasts,1);
    }));
    await scenario('Encrypted retained plan corruption rejected without another signature/submission',()=>session(async s=>{
        await s.run();const file=path.join(s.pdir,'plan.encrypted.json'),envelope=JSON.parse(fs.readFileSync(file));const data=Buffer.from(envelope.ciphertext,'base64');data[0]^=1;envelope.ciphertext=data.toString('base64');fs.writeFileSync(file,JSON.stringify(envelope),{mode:0o600});await assert.rejects(s.run('RECONCILE'));assert.equal(s.evm.state.broadcasts,1);assert.equal(s.evm.state.signs,1);
    }));
    return {policy:POLICY,checks:completed.length,checks_completed:completed,research_records_used:0,public_evm:'Ganache 7.9.2',public_finality_simulated:true,public_provider_independence:false,live_research_ready:false};
}
module.exports={checks,publicPayload,signed,inventory,POLICY};
