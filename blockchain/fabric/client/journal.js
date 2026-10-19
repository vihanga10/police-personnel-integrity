'use strict';
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {canonical,sha}=require('../chaincode/lib/evidence');
function check(value,message) {if(!value)throw new Error(message);}
function privatePath(file,directory=false) {
    const full=path.resolve(file);
    for(let current=full;;current=path.dirname(current)) {
        check(!fs.lstatSync(current).isSymbolicLink(),'Private path contains a symlink');
        if(current===path.dirname(current))break;
    }
    const stat=fs.statSync(full);check(directory?stat.isDirectory():stat.isFile(),'Private path type differs');
    check((stat.mode&0o077)===0,'Private path permissions differ');return full;
}
function save(file,value) {
    privatePath(path.dirname(file),true);const bytes=Buffer.from(canonical(value)+'\n');
    const tmp=file+'.'+crypto.randomBytes(8).toString('hex')+'.tmp';let fd;
    try {fd=fs.openSync(tmp,'wx',0o600);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
        fs.linkSync(tmp,file);const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}
    finally {if(fd!==undefined)fs.closeSync(fd);if(fs.existsSync(tmp))fs.unlinkSync(tmp);}
}
function read(file) {return JSON.parse(fs.readFileSync(privatePath(file),'utf8'));}
async function execute({driver,directory,network,job,interrupt}) {
    check(/^[a-z][a-z0-9-]{0,63}$/.test(job.name),'Unsafe journal operation name');
    privatePath(directory,true);const prefix=path.join(directory,job.name);
    const binding={network,method:job.method,args:job.args,read_method:job.read_method,read_args:job.read_args};
    const preparedFile=prefix+'.prepared.json',submittedFile=prefix+'.submitted.json',validFile=prefix+'.valid.json';
    let prepared;
    if(fs.existsSync(preparedFile)) {prepared=read(preparedFile);check(sha(prepared.binding)===sha(binding),'Recovery operation/network differs');}
    else {const tx=await driver.endorse(job.method,job.args);prepared={binding,transaction_id:tx.id,transaction_bytes:tx.bytes,expected:tx.expected};
        check(prepared.expected.transaction_id===tx.id,'Existing write requires its original receipt; no replacement transaction');save(preparedFile,prepared);}
    if(interrupt==='AFTER_PREPARE')throw new Error('INJECTED_AFTER_PREPARE');
    let submitted;
    if(fs.existsSync(submittedFile))submitted=read(submittedFile);
    else {submitted=await driver.submit(prepared.transaction_bytes);check(submitted.id===prepared.transaction_id,'Submission transaction differs');save(submittedFile,submitted);}
    check(submitted.id===prepared.transaction_id,'Saved transaction differs');
    if(interrupt==='AFTER_SUBMIT')throw new Error('INJECTED_AFTER_SUBMIT');
    const status=await driver.status(submitted.commit_bytes);
    check(status.transactionId===prepared.transaction_id&&status.successful===true&&status.code===0,'Transaction is not VALID');
    check(/^[0-9]+$/.test(String(status.blockNumber)),'Invalid commit block');
    if(interrupt==='AFTER_STATUS')throw new Error('INJECTED_AFTER_STATUS');
    const observed=await driver.observe(job.read_method,job.read_args);
    check(Object.keys(observed).sort().join(',')==='Org1MSP,Org2MSP'&&Object.values(observed).every(v=>canonical(v)===canonical(prepared.expected)), 'Two-peer readback differs');
    const receipt={network,transaction_id:prepared.transaction_id,validation_code:0,successful:true,
        block_number:String(status.blockNumber),payload_sha256:sha(prepared.expected),operation_sha256:sha(binding)};
    if(fs.existsSync(validFile))check(canonical(read(validFile))===canonical(receipt),'Saved receipt differs');
    else save(validFile,receipt);
    if(interrupt==='AFTER_RECEIPT')throw new Error('INJECTED_AFTER_RECEIPT');
    return receipt;
}
module.exports={execute,save,read,privatePath};
