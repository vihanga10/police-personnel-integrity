'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {run}=require('../deployment-engine'),F=require('../deployment-files'),{fake}=require('./sepolia-test-support');
const options=f=>({wallet:f.wallet,artifact:f.artifact,config:f.config,rpcs:f.rpcs,directory:f.directory});
async function deployed(){const f=fake();await run({...options(f),mode:'EXECUTE'});return f;}
test('pruned deployment-height state reconciles through a common finalized block without a write',async()=>{
    const f=await deployed(),before=fs.readFileSync(path.join(f.directory,'PASSED.json')),raw=F.read(path.join(f.directory,'PREPARED.json')).raw_transaction,writes=f.state.broadcasts.length,tags=[];
    f.state.tamper=(m,p,v)=>{if(m==='eth_call'||m==='eth_getCode'){tags.push(p[1]);if(p[1]==='0x60')throw new Error('fixture pruned state');}return v;};
    for(const mode of ['VALIDATE','RECONCILE'])assert.equal((await run({...options(f),mode})).status,'PASSED');
    assert.ok(tags.length>0);assert.ok(tags.every(t=>t==='0x70'));assert.equal(f.state.broadcasts.length,writes);
    assert.equal(F.read(path.join(f.directory,'PREPARED.json')).raw_transaction,raw);assert.deepEqual(fs.readFileSync(path.join(f.directory,'PASSED.json')),before);
});
test('different finalized heads use the lower finalized height on both peers',async()=>{
    const f=await deployed(),tags=[];
    f.state.tamper=(m,p,v,peer)=>{if(m==='eth_getBlockByNumber'&&p[0]==='finalized'&&peer===1)return {number:'0x71',hash:'0x'+'ee'.repeat(32)};
        if(m==='eth_call'||m==='eth_getCode')tags.push(p[1]);return v;};
    assert.equal((await run({...options(f),mode:'RECONCILE'})).status,'PASSED');assert.ok(tags.every(t=>t==='0x70'));
});
test('missing finalized head stays pending without requesting contract state',async()=>{
    const f=await deployed();fs.unlinkSync(path.join(f.directory,'PASSED.json'));
    f.state.tamper=(m,p,v,peer)=>{if(m==='eth_getBlockByNumber'&&p[0]==='finalized'&&peer===1)return null;if(m==='eth_call'||m==='eth_getCode')throw new Error('state should not be read');return v;};
    assert.equal((await run({...options(f),mode:'RECONCILE'})).reason,'FINALIZED_BLOCK_AND_CONFIRMATIONS_REQUIRED');
});
for(const fault of ['hash_disagreement','height_disagreement','changed_state_block','changed_original_block'])test('reject '+fault+' during finalized verification',async()=>{
    const f=await deployed();let stateReads=0,originalReads=0;
    f.state.tamper=(m,p,v,peer)=>{if(m==='eth_getBlockByNumber'&&p[0]==='0x70'){
        if(peer===0)stateReads++;
        if(fault==='hash_disagreement'&&peer===1)return {...v,hash:'0x'+'aa'.repeat(32)};
        if(fault==='height_disagreement')return {...v,number:'0x6f'};
        if(fault==='changed_state_block'&&stateReads>1)return {...v,hash:'0x'+'aa'.repeat(32)};
    }if(m==='eth_getBlockByNumber'&&p[0]==='0x60'&&peer===0){originalReads++;if(fault==='changed_original_block'&&originalReads>1)return {...v,hash:'0x'+'aa'.repeat(32)};}return v;};
    await assert.rejects(run({...options(f),mode:'RECONCILE'}));
});
test('rejection of finalized contract state remains a hard stop',async()=>{
    const f=await deployed();f.state.tamper=(m,p,v)=>{if(m==='eth_getCode')throw new Error('fixture provider rejected finalized state');return v;};
    await assert.rejects(run({...options(f),mode:'RECONCILE'}));
});
