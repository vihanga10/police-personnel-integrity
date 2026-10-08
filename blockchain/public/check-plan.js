'use strict';
// Offline compatibility check only: this cannot authorize deployment or submission.
const fs=require('node:fs'),path=require('node:path');
const {plan}=require('./publication'),{bindCapturedReceipt}=require('./fabric-binding');
function readPrivate(filename){
    const absolute=path.resolve(filename);
    let current=path.parse(absolute).root;
    for(const part of absolute.slice(current.length).split(path.sep)){
        current=path.join(current,part);
        if(fs.lstatSync(current).isSymbolicLink())throw new Error('Symlink input refused');
    }
    const s=fs.statSync(absolute);
    if(!s.isFile() || (s.mode&0o077) || s.uid!==process.getuid())throw new Error('Private owner-only input required');
    return JSON.parse(fs.readFileSync(absolute,'utf8'));
}
function main(argv){
    if(argv.length!==3)throw new Error('Use: node check-plan.js PUBLICATION EXPECTED_SHA FABRIC_RECONCILE_PASSED_JSON');
    const publication=readPrivate(argv[0]);
    const p=plan(publication,argv[1]);
    bindCapturedReceipt(readPrivate(argv[2]),publication,argv[1]);
    console.log('Offline public anchor plan: PASSED');
    console.log(JSON.stringify({scope:'CAPTURED_PLAN_ONLY',chain_id:p.chain_id,officers:p.officer_count,chunks:p.chunk_count,expected_write_calls:p.expected_write_calls,public_payload_sha256:argv[1],merkle_root:publication.merkle_root}));
    console.log('Saved receipt comparison only; no fresh live gate, Fabric queries, wallet access, RPC connection, database writes or public transactions.');
}
if(require.main===module){try{main(process.argv.slice(2));}catch(error){console.error('Offline public plan stopped: '+error.name);process.exitCode=1;}}
module.exports={main,readPrivate};
