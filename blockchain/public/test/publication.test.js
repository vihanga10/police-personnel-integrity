'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {plan}=require('../publication'),{fixture}=require('./fixture');
const {sha}=require('../../fabric/chaincode/lib/evidence');
test('original Fabric publication becomes 66 exact chunks and 6597-leaf proofs',()=>{
    const f=fixture(),p=plan(f.publicPayload,f.digest);
    assert.equal(p.chunks.length,66);assert.equal(p.chunks.at(-1).handles.length,96);
    assert.equal(p.chunks.flatMap(c=>c.handles).length,6596);
    assert.equal(p.metadata[0],'0x'+f.digest);assert.equal(p.metadata[1],'0x'+f.publicPayload.merkle_root);
    assert.equal(p.batch_proof.length,13);
    assert.deepEqual(p.chunks.flatMap(c=>c.commitments),f.publicPayload.officers.map(r=>'0x'+r.commitment));
});
for(const kind of ['extra_personal_field','missing_officer','wrong_version','wrong_policy','changed_root','duplicate_handle','duplicate_commitment','unsorted','bad_handle']) {
    test('publication rejects '+kind,()=>{
        const f=fixture(),p=f.publicPayload;
        if(kind==='extra_personal_field')p.nic='prohibited';
        if(kind==='missing_officer')p.officers.pop();
        if(kind==='wrong_version')p.officers[0].commitment_version=2;
        if(kind==='wrong_policy')p.policy='OTHER';
        if(kind==='changed_root')p.merkle_root='1'.repeat(64);
        if(kind==='duplicate_handle')p.officers[1].publication_id=p.officers[0].publication_id;
        if(kind==='duplicate_commitment')p.officers[1].commitment=p.officers[0].commitment;
        if(kind==='unsorted')p.officers.reverse();
        if(kind==='bad_handle')p.officers[0].publication_id='123456789V';
        assert.throws(()=>plan(p,sha(p)));
    });
}
test('expected SHA binds exact original file contents despite otherwise valid publication',()=>{
    const f=fixture(); assert.throws(()=>plan(f.publicPayload,'a'.repeat(64)),/original publication/);
});
