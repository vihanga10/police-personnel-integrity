'use strict';
const crypto=require('node:crypto');
const POLICY='FABRIC_GENESIS_HEADER_DATA_V1';
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
function check(value){if(!value)throw new Error('Invalid genesis block structure');}
// Decode the small, known common.Block framing. No source/configuration values are exported.
function fields(bytes) {
    const b=Buffer.from(bytes);let offset=0;const result=[];
    function integer(){let n=0n,shift=0n;for(let i=0;i<10;i++){
        check(offset<b.length);const x=b[offset++];if(i===9)check(x<2);
        n|=BigInt(x&127)<<shift;if(!(x&128)){check(i===0||x!==0);return n;}shift+=7n;
    }throw new Error('Invalid genesis varint');}
    while(offset<b.length){const tag=integer();check(tag>0n&&tag<=0xffffffffn);const field=Number(tag>>3n),wire=Number(tag&7n);check(field>0);
        if(wire===0)result.push({field,wire,value:integer()});
        else {check(wire===2);const length=integer();check(length<=BigInt(b.length-offset));const end=offset+Number(length);
            result.push({field,wire,value:b.subarray(offset,end)});offset=end;}}
    return result;
}
function identity(bytes) {
    const outer=fields(bytes);check(outer.length===3&&outer.every(f=>f.wire===2&&[1,2,3].includes(f.field))&&new Set(outer.map(f=>f.field)).size===3);
    const header=outer.find(f=>f.field===1).value,data=outer.find(f=>f.field===2).value,metadata=outer.find(f=>f.field===3).value;
    const h=fields(header);check(new Set(h.map(f=>f.field)).size===h.length);
    check(h.every(f=>(f.field===1&&f.wire===0&&f.value===0n)||(f.field===2&&f.wire===2&&f.value.length===0)||(f.field===3&&f.wire===2&&f.value.length===32)));
    check(h.some(f=>f.field===3));
    const entries=fields(data);check(entries.length>0&&entries.every(f=>f.field===1&&f.wire===2&&f.value.length>0));
    check(fields(metadata).every(f=>f.field===1&&f.wire===2));
    return {policy:POLICY,header_sha256:digest(header),data_sha256:digest(data)};
}
function verifyPeer(expected,bytes){const actual=identity(bytes);if(JSON.stringify(actual)!==JSON.stringify(expected))throw new Error('Peer genesis identity differs');return actual;}
module.exports={identity,verifyPeer,POLICY};
