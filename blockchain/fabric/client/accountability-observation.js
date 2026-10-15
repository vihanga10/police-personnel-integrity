'use strict';
// Retry READS only. Never changes a transaction, submits, endorses, or asserts ABSENT.
function transient(error,id){
    if([4,14].includes(error?.code))return true;
    const message=String(error?.message??'');
    return error?.code===2&&message.includes('no such transaction ID ['+id+']')&&message.includes('in index');
}
async function observeRead(fn,id,{attempts=30,delay=500,sleep=ms=>new Promise(r=>setTimeout(r,ms)),now=Date.now,budget=30000}={}){
    if(typeof fn!=='function'||!/^[0-9a-f]{64}$/.test(id)||!Number.isInteger(attempts)||attempts<1||attempts>30||!Number.isFinite(delay)||delay<0||!Number.isFinite(budget)||budget<0||typeof sleep!=='function'||typeof now!=='function')throw new Error('Bounded observation required');
    const start=now();let last;
    for(let i=0;i<attempts;i++){
        try{return await fn();}catch(e){last=e;if(!transient(e,id)||i===attempts-1||now()-start>=budget)throw e;await sleep(delay);}
    }throw last;
}
module.exports={observeRead,transient};
