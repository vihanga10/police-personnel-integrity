'use strict';
const {sha,tree,POLICY}=require('../../fabric/chaincode/lib/evidence');
const hex=n=>BigInt(n).toString(16).padStart(64,'0');
function fixture() {
    // Test-only generated values: no research payload, keys or personnel data.
    const officers=Array.from({length:6596},(_,i)=>({publication_id:hex(i+1),commitment_version:1,commitment:hex(i+10000)}));
    const publicPayload={policy:POLICY,commitment_version:1,key_version:'commit-v1',batch_publication_id:hex(80000),officers,shared_commitment:hex(80001),coverage_commitment:hex(80002),batch_commitment:hex(80003)};
    publicPayload.merkle_root=tree([...officers.map(r=>({kind:'OFFICER',...r})),{kind:'BATCH',publication_id:publicPayload.batch_publication_id,commitment:publicPayload.batch_commitment}]);
    return {publicPayload,digest:sha(publicPayload)};
}
module.exports={fixture,hex};
