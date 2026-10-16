'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {Transaction}=require('ethers');
const {using}=require('./public-adapter-fixture');
const {LivePublicPromotionsAdapter,MAX_GAS}=require('../live-public-adapter');
const N=require('../network'),L=require('../live-network');
function adapter(f,budget='0.005'){
  const config={...f.config,policy:L.POLICY,max_total_fee_eth:budget,rpc_urls:['https://one.quiknode.pro/unit-test','https://eth-sepolia.g.alchemy.com/v2/unit-test']};
  const file=path.join(f.parent,'gas-live-network.json'),raw=Buffer.from(JSON.stringify(config));fs.writeFileSync(file,raw,{mode:0o600});
  return new LivePublicPromotionsAdapter({configFile:file,expectedConfigSha256:crypto.createHash('sha256').update(raw).digest('hex'),repo:f.repo,destination:f.destination,authorize:async()=>{}},{sleep:async()=>{},fetchImpl:async(url,options)=>{
    const q=JSON.parse(options.body),i=url.includes('alchemy')?1:0;let value;
    try{value={jsonrpc:'2.0',id:q.id,result:await f.rpcs[i].call(q.method,q.params)};}
    catch(e){value={jsonrpc:'2.0',id:q.id,error:{code:e.code||-32000,message:'Fixture response',data:e.data||null}};}
    return {ok:true,headers:{get:()=> 'application/json'},body:[Buffer.from(JSON.stringify(value))]};
  }});
}
test('observed 689113 estimate signs 826936 gas and verifies exact original publication',()=>using(async f=>{
  assert.equal(MAX_GAS,1000000n);f.state.mutation=(m,p,v)=>m==='eth_estimateGas'?N.hex(689113n):v;
  const a=adapter(f),op='e'.repeat(64),plan=await a.prepare(op,f.selection.payload,f.wallet);
  assert.equal(Transaction.from(plan.raw_transaction).gasLimit,826936n);
  await a.submit(plan,op,f.selection.payload);
  assert.equal((await a.observe(plan,op,f.selection.payload)).status,'FINAL');assert.equal(f.state.broadcasts.length,1);
}));
test('rounded gas exactly at one million is accepted',()=>using(async f=>{
  f.state.mutation=(m,p,v)=>m==='eth_estimateGas'?N.hex(833333n):v;
  const a=adapter(f),p=await a.prepare('a'.repeat(64),f.selection.payload,f.wallet);
  assert.equal(Transaction.from(p.raw_transaction).gasLimit,1000000n);assert.equal(f.state.broadcasts.length,0);
}));
test('rounded gas one above one million is rejected before signing',()=>using(async f=>{
  f.state.mutation=(m,p,v)=>m==='eth_estimateGas'?N.hex(833334n):v;
  await assert.rejects(adapter(f).prepare('a'.repeat(64),f.selection.payload,f.wallet),/Gas\/balance\/budget/);
  assert.equal(f.state.signs,0);assert.equal(f.state.broadcasts.length,0);
}));
test('larger cap does not bypass insufficient balance',()=>using(async f=>{
  f.state.mutation=(m,p,v)=>m==='eth_estimateGas'?N.hex(689113n):m==='eth_getBalance'?'0x0':v;
  await assert.rejects(adapter(f).prepare('a'.repeat(64),f.selection.payload,f.wallet),/Gas\/balance\/budget/);
  assert.equal(f.state.signs,0);assert.equal(f.state.broadcasts.length,0);
}));
test('larger cap does not bypass the configured fee budget',()=>using(async f=>{
  f.state.mutation=(m,p,v)=>m==='eth_estimateGas'?N.hex(689113n):v;
  await assert.rejects(adapter(f,'0.001').prepare('a'.repeat(64),f.selection.payload,f.wallet),/Gas\/balance\/budget/);
  assert.equal(f.state.signs,0);assert.equal(f.state.broadcasts.length,0);
}));
test('larger cap does not bypass the observed block gas limit',()=>using(async f=>{
  f.state.mutation=(m,p,v)=>m==='eth_estimateGas'?N.hex(689113n):m==='eth_getBlockByNumber'&&p[0]==='latest'?{...v,gasLimit:N.hex(800000n)}:v;
  await assert.rejects(adapter(f).prepare('a'.repeat(64),f.selection.payload,f.wallet),/Gas\/balance\/budget/);
  assert.equal(f.state.signs,0);assert.equal(f.state.broadcasts.length,0);
}));
test('an originally signed plan exceeding the cap still fails validation',()=>using(async f=>{
  const a=adapter(f),op='a'.repeat(64),p=await a.prepare(op,f.selection.payload,f.wallet);
  const tx=Transaction.from(p.raw_transaction);tx.signature=null;tx.gasLimit=1000001n;
  p.raw_transaction=await f.wallet.signTransaction(tx);p.transaction_id=Transaction.from(p.raw_transaction).hash;
  assert.throws(()=>a.validatePlan(p,op,f.selection.payload),/Original signed public transaction differs/);
  assert.equal(f.state.broadcasts.length,0);
}));
