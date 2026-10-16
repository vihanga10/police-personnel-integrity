'use strict';
// V2 pin: preserve every known field's bytes; sort only the approvals map entries.
const crypto=require('node:crypto');
const POLICY='PROMOTIONS_DEFINITION_APPROVAL_ORDER_V2';
const check=v=>{if(!v)throw new Error('Malformed or unsupported promotions definition');};
function fields(input){
    const b=Buffer.from(input);check(b.length>0&&b.length<=1048576);let offset=0;const out=[];
    function integer(){let value=0n;for(let i=0;i<10;i++){
        check(offset<b.length);const x=b[offset++];if(i===9)check(x<2);
        value|=BigInt(x&127)<<BigInt(i*7);if(!(x&128)){check(i===0||x!==0);return value;}
    }throw new Error('Malformed or unsupported promotions definition');}
    while(offset<b.length){const start=offset,tag=integer(),number=Number(tag>>3n),wire=Number(tag&7n);check(number>0&&tag<=0xffffffffn);
        let value;if(wire===0)value=integer();else{check(wire===2);const length=integer();check(length<=BigInt(b.length-offset));value=b.subarray(offset,offset+Number(length));offset+=Number(length);}
        out.push({number,wire,value,raw:b.subarray(start,offset)});check(out.length<=80);
    }return out;
}
function normalized(input){
    const rows=fields(input),seen=new Set(),keys=new Set(),ordinary=[],approvals=[];
    for(const row of rows){
        const n=row.number;check(n>=1&&n<=8&&row.wire===([1,7].includes(n)?0:2));
        if(n!==8){check(!seen.has(n));seen.add(n);if(n===1)check(row.value>0n&&row.value<=0x7fffffffffffffffn);if(n===7)check(row.value<=1n);ordinary.push(row);continue;}
        const entry=fields(row.value);check(entry.length>=1&&entry.length<=2);
        const key=entry.find(f=>f.number===1);check(key&&key.wire===2&&key.value.length>0&&key.value.length<=128);
        const text=new TextDecoder('utf-8',{fatal:true}).decode(key.value);check(!keys.has(text));keys.add(text);
        check(entry.filter(f=>f.number===1).length===1);
        const values=entry.filter(f=>f.number===2);check(values.length<=1&&values.every(f=>f.wire===0&&f.value<=1n));
        check(entry.every(f=>[1,2].includes(f.number)));check(keys.size<=64);
        // Reject alternate entry field orders rather than silently dropping bytes.
        check(entry[0].number===1);approvals.push({key:Buffer.from(key.value),raw:row.raw});
    }
    check([1,2,3,4,5].every(n=>seen.has(n)));
    ordinary.sort((a,b)=>a.number-b.number);approvals.sort((a,b)=>Buffer.compare(a.key,b.key));
    return Buffer.concat([...ordinary.map(f=>f.raw),...approvals.map(f=>f.raw)]);
}
function definitionHash(input){return crypto.createHash('sha256').update(POLICY+'\0').update(normalized(input)).digest('hex');}
module.exports={POLICY,normalized,definitionHash};
