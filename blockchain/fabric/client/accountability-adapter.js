'use strict';
const {validate,canonical,sha,RECORD_POLICY}=require('../accountability-chaincode/lib/accountability');
const B=require('./accountability-block');
const check=(v,m)=>{if(!v)throw new Error(m);};
const exact=(v,k)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...k].sort().join(','),'Accountability adapter schema differs');
const POLICY='ACCOUNTABILITY_GATEWAY_PLAN_V1';
function destination(d){
    exact(d,['genesis_sha256','channel','chaincode','namespace','organizations']);
    check(typeof d.genesis_sha256==='string'&&/^[0-9a-f]{64}$/.test(d.genesis_sha256)&&d.channel==='personnel'&&d.chaincode==='accountability-anchor-v1'&&
        d.namespace==='accountability-anchor-v1'&&canonical(d.organizations)===canonical(['Org1MSP','Org2MSP']),'Dedicated accountability destination required');return d;
}
class AccountabilityAdapter {
    constructor({transport,destination:dest,retention,authorize,mode='READ_ONLY'}) {
        destination(dest);check(['READ_ONLY','EXECUTE'].includes(mode)&&typeof authorize==='function'&&
            retention&&typeof retention.load==='function'&&typeof retention.save==='function','Trusted retention/authorization callbacks required');
        this.dest=canonical(dest);this.transport=transport;this.retention=retention;this.authorize=authorize;this.mode=mode;
    }
    async inspect(d){
        check(canonical(destination(d))===this.dest,'Approved destination differs');
        await this.authorize('READ',structuredClone(d));
        check(canonical(await this.transport.inspect())===this.dest,'Authenticated network identity differs');return structuredClone(d);
    }
    validatePlan(plan,payload,d){
        validate(payload);destination(d);exact(plan,['operation','payload_sha256','destination','transaction_id','transaction']);
        check(typeof plan.operation==='string'&&typeof plan.transaction_id==='string'&&/^[0-9a-f]{64}$/.test(plan.operation)&&/^[0-9a-f]{64}$/.test(plan.transaction_id)&&
            plan.payload_sha256===sha(payload)&&canonical(plan.destination)===canonical(d)&&canonical(d)===this.dest,
            'Transaction plan scope differs');
        check(typeof plan.transaction==='string'&&Buffer.byteLength(plan.transaction)<=200000,'Bounded transaction plan required');
        const wire=JSON.parse(plan.transaction);exact(wire,['policy','bytes','expected']);
        check(wire.policy===POLICY&&typeof wire.bytes==='string','Gateway transaction encoding differs');
        const bytes=Buffer.from(wire.bytes,'base64');check(bytes.length>0&&bytes.toString('base64')===wire.bytes,'Canonical serialized transaction required');
        exact(wire.expected,['policy','payload','transaction_id']);
        const t=B.prepared(bytes,payload,d,this.transport.certificate);
        check(t.id===plan.transaction_id&&wire.expected.policy===RECORD_POLICY&&wire.expected.transaction_id===t.id&&
            canonical(wire.expected.payload)===canonical(payload),'Endorsed record binding differs');
        return {wire,bytes,raw:t.payload};
    }
    async prepare(operation,payload,d){
        check(this.mode==='EXECUTE','Read-only adapter cannot endorse');validate(payload);await this.inspect(d);
        check(typeof operation==='string'&&/^[0-9a-f]{64}$/.test(operation),'Bounded operation identity required');
        const saved=await this.retention.load(operation);
        if(saved){this.validatePlan(saved,payload,d);check(saved.operation===operation,'Saved operation differs');return structuredClone(saved);}
        await this.authorize('ENDORSE',structuredClone(d),structuredClone(payload));
        const tx=await this.transport.endorse(canonical(payload));
        const plan={operation,payload_sha256:sha(payload),destination:structuredClone(d),transaction_id:tx.id,
            transaction:canonical({policy:POLICY,bytes:tx.bytes,expected:tx.expected})};
        this.validatePlan(plan,payload,d);await this.inspect(d);
        await this.authorize('RETAIN',structuredClone(d),structuredClone(payload));
        await this.retention.save(operation,structuredClone(plan));
        check(canonical(await this.retention.load(operation))===canonical(plan),'Durable transaction retention differs');
        return plan;
    }
    async submit(plan,payload,d){
        check(this.mode==='EXECUTE','Read-only adapter cannot submit');const parsed=this.validatePlan(plan,payload,d);
        await this.inspect(d);
        check(canonical(await this.retention.load(plan.operation))===canonical(plan),'Saved transaction required before submission');
        await this.authorize('SUBMIT',structuredClone(d),structuredClone(payload));
        // Only the retained endorsed transaction is submitted. No new endorsement on retry.
        const id=await this.transport.submit(parsed.bytes,plan.transaction_id,parsed.wire.expected);check(id===plan.transaction_id,'Submitted identity differs');
        return {transaction_id:id};
    }
    async observeCommitted(plan,payload,d){
        const parsed=this.validatePlan(plan,payload,d);await this.inspect(d);
        check(canonical(await this.retention.load(plan.operation))===canonical(plan),'Original retained plan required');
        await this.authorize('RECONCILE',structuredClone(d),structuredClone(payload));
        const observations=await this.transport.observe(plan.transaction_id,payload.publication_id);
        exact(observations,['Org1MSP','Org2MSP']);let proof;
        for(const org of d.organizations){
            const o=observations[org];exact(o,['block','record']);
            const p=B.committed(o.block,parsed.raw,plan.transaction_id,d.channel);
            check(canonical(o.record)===canonical(parsed.wire.expected),'Exact organization accountability readback differs');
            if(proof)check(canonical(p)===canonical(proof),'Organization commit block differs');else proof=p;
        }
        await this.inspect(d);await this.authorize('RECONCILE',structuredClone(d),structuredClone(payload));
        return {status:'FINAL',destination:structuredClone(d),payload:structuredClone(payload),transaction_id:plan.transaction_id,
            verification:{validation_code:'VALID',organizations:[...d.organizations],block_sha256:proof.block_sha256}};
    }
}
module.exports={AccountabilityAdapter,POLICY,destination};
