'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{getAddress}=require('ethers');
const {compile}=require('./compile');
const byteSha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function artifact(writer){
    writer=getAddress(writer);if(writer==='0x'+'00'.repeat(20))throw new Error('Nonzero findings writer required');
    const a=compile(),ids=Object.keys(a.immutableReferences);
    if(ids.length!==1||!a.immutableReferences[ids[0]].length)throw new Error('Single writer immutable required');
    const bytes=Buffer.from(a.runtimeTemplate.slice(2),'hex'),address=Buffer.from(writer.slice(2).padStart(64,'0'),'hex');
    for(const r of a.immutableReferences[ids[0]]){
        if(r.length!==32||!Number.isSafeInteger(r.start)||r.start<0||r.start+32>bytes.length)throw new Error('Writer reference differs');
        address.copy(bytes,r.start);
    }
    return {...a,writer:writer.toLowerCase(),runtime:'0x'+bytes.toString('hex'),runtime_sha256:byteSha(bytes),
        source_sha256:byteSha(fs.readFileSync(path.join(__dirname,'contracts/FindingsAnchor.sol')))};
}
module.exports={artifact,byteSha};
