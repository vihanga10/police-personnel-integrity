'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const E=require('../publication-engine'),F=require('../deployment-files'),{fake}=require('./public-publisher-support');
async function q(estimate,blockCap=200000000n){const f=fake();f.state.tamper=(m,p,v)=>m==='eth_estimateGas'?'0x'+estimate.toString(16):m==='eth_getBlockByNumber'&&p[0]==='latest'?{...v,gasLimit:'0x'+blockCap.toString(16)}:v;const id=E.identity(f.artifact,f.config,f.deployment,f.plan,f.digest);return E.quote(f.rpcs,f.artifact,id,E.operations(f.plan,f.artifact.abi)[1],f.config);}
test('reported 15633360 estimate fits bounded headroom with unchanged 2 gwei fee cap',async()=>{const v=await q(15633360n);assert.equal(v.gas,16777216n);assert.equal(v.estimate,15633360n);assert.equal(v.cost,33554432000000000n);assert.ok(v.gas*100n>=v.estimate*105n);});
test('ordinary operations retain 20 percent headroom',async()=>assert.equal((await q(2000000n)).gas,2400000n));
test('lower observed block cap binds the headroom',async()=>assert.equal((await q(15633360n,16500000n)).gas,16500000n));
test('minimum headroom boundary accepted',async()=>{const v=await q(15978300n);assert.equal(v.gas,16777216n);});
for(const [name,estimate,cap] of [['minimum headroom exceeded',15978302n,200000000n],['raw transaction cap exceeded',16777217n,200000000n],['lower block cap insufficient',15633360n,16415027n],['zero estimate',0n,200000000n]])test(name+' stops before signing',async()=>assert.rejects(q(estimate,cap),/Publication operation exceeds gas cap/));
async function created(){const f=fake();await assert.rejects(E.run({...f,mode:'EXECUTE',interrupt:(point,index)=>{if(point==='AFTER_RECEIPT'&&index===0)throw new Error('fixture stop after create');}}));return f;}
for(const [budget,status] of [['0.025','FUNDING_OR_BUDGET_REQUIRED'],['0.04','READY']])test('partial batch read-only quote preserves original create with budget '+budget,async()=>{
 const f=await created(),file=path.join(f.directory,'00-PREPARED.json'),before=fs.readFileSync(file),writes=f.state.broadcasts.length;
 f.state.tamper=(m,p,v)=>m==='eth_estimateGas'?'0x'+(15633360n).toString(16):v;
 const result=await E.run({...f,mode:'VALIDATE',publicationBudget:budget});assert.equal(result.status,status);assert.equal(result.next_operation,1);assert.equal(result.raw_gas_estimate,'15633360');assert.equal(result.effective_gas_cap,'16777216');
 assert.equal(f.state.broadcasts.length,writes);assert.deepEqual(fs.readFileSync(file),before);assert.equal(fs.existsSync(path.join(f.directory,'01-PREPARED.json')),false);
});
test('insufficient wallet still stops execution before preparing officer transaction',async()=>{
 const f=await created(),writes=f.state.broadcasts.length;f.state.balance=1n;f.state.tamper=(m,p,v)=>m==='eth_estimateGas'?'0x'+(15633360n).toString(16):v;
 const result=await E.run({...f,mode:'EXECUTE',publicationBudget:'0.04'});assert.equal(result.status,'FUNDING_OR_BUDGET_REQUIRED');assert.equal(f.state.broadcasts.length,writes);assert.equal(fs.existsSync(path.join(f.directory,'01-PREPARED.json')),false);
});
