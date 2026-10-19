'use strict';
const {canonical, sha, tree, POLICY} = require('../fabric/chaincode/lib/evidence');
const crypto = require('node:crypto');
const digest = bytes => crypto.createHash('sha256').update(bytes).digest();
const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value) && !/^0+$/.test(value);
function check(value, message) { if (!value) throw new Error(message); }
function plan(publication, expectedDigest) {
    check(Object.keys(publication).sort().join(',') === 'batch_commitment,batch_publication_id,commitment_version,coverage_commitment,key_version,merkle_root,officers,policy,shared_commitment', 'Publication fields differ');
    check(publication.policy === POLICY && publication.commitment_version === 1 && publication.key_version === 'commit-v1', 'Publication version differs');
    check(hex(expectedDigest) && sha(publication) === expectedDigest, 'Expected original publication differs');
    for (const key of ['batch_publication_id','batch_commitment','shared_commitment','coverage_commitment','merkle_root']) check(hex(publication[key]), 'Metadata shape differs');
    const rows = publication.officers;
    check(Array.isArray(rows) && rows.length === 6596, 'All 6596 officers required');
    for (let i=0;i<rows.length;i++) {
        const row=rows[i];
        check(Object.keys(row).sort().join(',') === 'commitment,commitment_version,publication_id' && row.commitment_version === 1 && hex(row.publication_id) && hex(row.commitment), 'Officer fields differ');
        check(!i || rows[i-1].publication_id < row.publication_id, 'Officer order or uniqueness differs');
    }
    check(new Set(rows.map(r=>r.commitment)).size === 6596, 'Repeated commitment');
    const leaves=[...rows.map(r=>({kind:'OFFICER',...r})),{kind:'BATCH',publication_id:publication.batch_publication_id,commitment:publication.batch_commitment}];
    check(tree(leaves) === publication.merkle_root, 'Merkle root differs');
    const levels=[leaves.map(leaf=>digest(Buffer.concat([Buffer.from([0]),Buffer.from(canonical(leaf))])))];
    while (levels.at(-1).length > 1) {
        const nodes=levels.at(-1), next=[];
        for (let i=0;i<nodes.length;i+=2) next.push(digest(Buffer.concat([Buffer.from([1]), nodes[i], nodes[i+1] || nodes[i]])));
        levels.push(next);
    }
    const proofFor=index=>{
        const proof=[];
        for (const level of levels.slice(0,-1)) { proof.push('0x'+(level[index^1] || level[index]).toString('hex')); index=Math.floor(index/2); }
        return proof;
    };
    const chunks=[];
    for(let start=0; start<6596; start+=100) {
        const part=rows.slice(start,start+100);
        chunks.push({start,handles:part.map(r=>'0x'+r.publication_id),commitments:part.map(r=>'0x'+r.commitment),proofs:part.map((_,i)=>proofFor(start+i))});
    }
    return {policy:'SEPOLIA_OFFICER_ANCHOR_PLAN_V1',chain_id:11155111,commitment_version:1,
        batch:'0x'+publication.batch_publication_id,
        metadata:[expectedDigest,publication.merkle_root,publication.shared_commitment,publication.coverage_commitment,publication.batch_commitment].map(h=>'0x'+h),
        batch_proof:proofFor(6596),chunks,officer_count:6596,chunk_count:66,expected_write_calls:68};
}
module.exports={plan};
