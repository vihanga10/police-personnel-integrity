'use strict';
const crypto=require('node:crypto');
const {canonical,sha,tree,POLICY}=require('../chaincode/lib/evidence');
function check(v,m){if(!v)throw new Error(m);}
function recent(payload,now=Date.now()) {
    const date=Date.parse(payload.checked_at);check(Number.isFinite(date)&&now-date>=0&&now-date<=600000,'Live evidence gate expired or future');
}
function authorize(envelope,secret,mode,now=Date.now()) {
    check(Buffer.isBuffer(secret)&&secret.length===32,'Private session authorization required');
    check(envelope&&Object.keys(envelope).sort().join(',')==='mac,payload','Authorization shape differs');
    const p=envelope.payload;
    const signature=crypto.createHmac('sha256',secret).update(canonical(p)).digest('hex');
    check(typeof envelope.mac==='string'&&/^[0-9a-f]{64}$/.test(envelope.mac)&&crypto.timingSafeEqual(Buffer.from(signature,'hex'),Buffer.from(envelope.mac,'hex')),'Session authorization differs');
    check(p.policy==='FABRIC_RESEARCH_SUBMISSION_V1'&&p.mode===mode&&['VALIDATE','EXECUTE','RECONCILE'].includes(mode),'Submission mode differs');
    check(Object.keys(p).sort().join(',')==='checked_at,mode,network,plan,policy,public_payload_sha256,publication','Authorization fields differ');
    recent(p,now);const publication=p.publication,plan=p.plan;
    check(publication.policy===POLICY&&publication.commitment_version===1&&publication.key_version==='commit-v1'&&publication.officers.length===6596,'Publication policy/count differs');
    check(sha(publication)===p.public_payload_sha256&&plan.metadata.public_payload_sha256===p.public_payload_sha256,'Publication digest differs');
    const rows=publication.officers;check(rows.every((r,i)=>Object.keys(r).sort().join(',')==='commitment,commitment_version,publication_id'&&r.commitment_version===1&&/^[0-9a-f]{64}$/.test(r.commitment)&&/^[0-9a-f]{64}$/.test(r.publication_id)&&(!i||rows[i-1].publication_id<r.publication_id)),'Officer records differ');
    check(new Set(rows.map(r=>r.commitment)).size===6596,'Repeated commitment');
    check(tree([...rows.map(r=>({kind:'OFFICER',...r})),{kind:'BATCH',publication_id:publication.batch_publication_id,commitment:publication.batch_commitment}])===publication.merkle_root,'Merkle root differs');
    const {officers,...metadata}=publication;metadata.officer_count=6596;metadata.public_payload_sha256=p.public_payload_sha256;
    check(canonical(metadata)===canonical(plan.metadata)&&plan.policy==='LIVE_EVIDENCE_ANCHOR_GATE_V1'&&plan.officer_count===6596&&plan.chunk_count===66&&plan.transaction_count===68&&plan.chunks.length===66,'Publication plan differs');
    for(let i=0;i<66;i++){const records=rows.slice(i*100,(i+1)*100),chunk=plan.chunks[i];check(chunk.index===i&&canonical(chunk.records)===canonical(records)&&chunk.records_sha256===sha(records),'Chunk plan differs');}
    check(p.network.channel==='personnel'&&p.network.chaincode==='officer-evidence-v1','Research namespace differs');
    return p;
}
module.exports={authorize,recent};
