'use strict';
const crypto=require('node:crypto');
const {canonical}=require('../promotions-chaincode/lib/promotions');
const check=(v,m)=>{if(!v)throw new Error(m);};
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
// Bounded protobuf framing for the known Fabric common/peer/gateway messages.
function fields(bytes) {
    const b=Buffer.from(bytes);check(b.length<=16777216,'Protobuf input too large');let pos=0;const out=[];
    function integer(){let n=0n,s=0n;for(let i=0;i<10;i++){
        check(pos<b.length,'Truncated protobuf');const x=b[pos++];if(i===9)check(x<2,'Oversized varint');
        n|=BigInt(x&127)<<s;if(!(x&128)){check(i===0||x!==0,'Noncanonical varint');return n;}s+=7n;
    }throw new Error('Oversized protobuf integer');}
    while(pos<b.length){check(out.length<100000,'Too many protobuf fields');const tag=integer();
        check(tag>0n&&tag<=0xffffffffn,'Invalid protobuf tag');const field=Number(tag>>3n),wire=Number(tag&7n);check(field>0,'Invalid field');
        if(wire===0)out.push({field,wire,value:integer()});
        else {check(wire===2,'Unsupported protobuf wire');const n=integer();check(n<=BigInt(b.length-pos),'Truncated field');
            const end=pos+Number(n);out.push({field,wire,value:b.subarray(pos,end)});pos=end;}
    }return out;
}
function one(list,n,wire=2,optional=false) {
    const found=list.filter(x=>x.field===n);check(found.length<2,'Duplicate singular field');
    if(!found.length){check(optional,'Required protobuf field absent');return wire===0?0n:Buffer.alloc(0);}
    check(found[0].wire===wire,'Protobuf field type differs');return found[0].value;
}
function transaction(payload) {
    const p=fields(payload),header=fields(one(p,1)),channel=fields(one(header,1)),signature=fields(one(header,2));
    const creator=one(signature,1),nonce=one(signature,2);const identity=fields(creator);
    const id=one(channel,5).toString('utf8');
    check(/^[0-9a-f]{64}$/.test(id)&&hash(Buffer.concat([nonce,creator]))===id,'Transaction nonce/creator identity differs');
    const actions=fields(one(p,2));check(actions.length===1&&actions[0].field===1&&actions[0].wire===2,'Single transaction action required');
    const action=fields(actions[0].value),cap=fields(one(action,2)),cpp=fields(one(cap,1));
    const invocation=fields(one(cpp,1)),spec=fields(one(invocation,1)),cc=fields(one(spec,2)),input=fields(one(spec,3));
    check(input.every(x=>x.field===1&&x.wire===2),'Unexpected chaincode arguments');
    return {id,channel:one(channel,4).toString('utf8'),type:one(channel,1,0),msp:one(identity,1).toString('utf8'),
        certificate:one(identity,2),chaincode:one(cc,2).toString('utf8'),args:input.map(x=>x.value.toString('utf8'))};
}
function prepared(bytes,payload,destination,certificate,invocation='PromotionsAnchor:AnchorPromotions') {
    const f=fields(bytes),id=one(f,1).toString('utf8'),envelope=fields(one(f,2)),raw=one(envelope,1),t=transaction(raw);
    check(id===t.id&&t.type===3n&&t.channel===destination.channel&&t.msp==='Org1MSP'&&
        t.chaincode===destination.chaincode&&canonical(t.args)===canonical([invocation,canonical(payload)]),
        'Prepared promotions invocation differs');
    if(certificate)check(t.certificate.equals(certificate),'Prepared signer certificate differs');
    return {id,payload:raw};
}
function committed(bytes,expected,id,channel) {
    const block=fields(bytes),header=one(block,1),h=fields(header),data=fields(one(block,2)),metadata=fields(one(block,3));
    check(data.length>0&&data.every(x=>x.field===1&&x.wire===2),'Block data differs');
    check(metadata.every(x=>x.field===1&&x.wire===2)&&metadata.length>=3,'Transaction validation flags missing');
    const flags=metadata[2].value;check(flags.length===data.length,'Validation flag count differs');
    const dh=one(h,3);check(dh.length===32&&hash(Buffer.concat(data.map(x=>x.value)))===dh.toString('hex'),'Block data hash differs');
    let matches=0;
    for(let i=0;i<data.length;i++){
        const envelope=fields(data[i].value),raw=one(envelope,1),p=fields(raw),ch=fields(one(fields(one(p,1)),1));
        if(one(ch,5,2,true).toString('utf8')!==id)continue;
        matches++;check(one(ch,4).toString('utf8')===channel&&raw.equals(expected),'Committed transaction bytes/channel differ');
        check(one(envelope,2).length>0,'Committed signature missing');check(flags[i]===0,'Transaction is not VALID');
    }
    check(matches===1,'Exact committed transaction missing or repeated');
    const number=one(h,1,0,true),previous=one(h,2,2,true);
    check(number>0n&&previous.length===32,'Non-genesis commit header required');
    // Stable cross-peer header/data identity; NOT Fabric's ASN.1 block-header hash.
    return {block_number:number.toString(),block_sha256:hash(Buffer.from(canonical({
        header_sha256:hash(header),data_sha256:dh.toString('hex')})))};
}
module.exports={fields,one,hash,prepared,committed};
