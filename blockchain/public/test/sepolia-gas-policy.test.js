
'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {run}=require('../deployment-engine'),R=require('../sepolia-rpc');
const {fake}=require('./sepolia-test-support');
function fixture(estimate=8804119n){const f=fake();f.config=R.configuration({policy:'SEPOLIA_DEPLOYMENT_NETWORK_V1',rpc_urls:['https://one.example.invalid','https://two.example.invalid'],max_fee_gwei:'2',priority_fee_gwei:'1',max_total_fee_eth:'0.025',confirmations:12});f.state.tamper=(m,p,v)=>m==='eth_estimateGas'?R.hex(estimate):m==='eth_getBalance'?R.hex(50000000000000000n):v;return f;}
const opt=f=>({wallet:f.wallet,artifact:f.artifact,config:f.config,rpcs:f.rpcs,directory:f.directory});
test('reported Sepolia gas estimate fits bounded 2 gwei policy without signing',async()=>{const f=fixture();f.wallet.signTransaction=()=>assert.fail('validation signed');const r=await run({...opt(f),mode:'VALIDATE'});assert.equal(r.estimated_gas_limit,'10564943');assert.equal(r.maximum_fee_wei,'21129886000000000');assert.equal(f.state.broadcasts.length,0);});
test('reported estimate still rejects original 5 gwei fee budget',async()=>{const f=fixture();f.config={...f.config,maxFee:5000000000n};await assert.rejects(run({...opt(f),mode:'VALIDATE'}),/configured fee budget/);});
test('maximum gas boundary accepted with 20 percent margin',async()=>{const f=fixture(10000000n);assert.equal((await run({...opt(f),mode:'VALIDATE'})).estimated_gas_limit,'12000000');});
test('one unit above gas boundary stops before signing',async()=>{const f=fixture(10000001n);await assert.rejects(run({...opt(f),mode:'EXECUTE'}),/local gas limit/);assert.equal(f.state.broadcasts.length,0);});
test('insufficient balance still rejected',async()=>{const f=fixture(),prior=f.state.tamper;f.state.tamper=(m,p,v)=>m==='eth_getBalance'?R.hex(20000000000000000n):prior(m,p,v);await assert.rejects(run({...opt(f),mode:'VALIDATE'}),/balance below/);});
test('lower block limit on either provider still rejected',async()=>{for(const peer of [0,1]){const f=fixture(),prior=f.state.tamper;f.state.tamper=(m,p,v,i)=>m==='eth_getBlockByNumber'&&p[0]==='latest'&&i===peer?{...v,gasLimit:R.hex(10000000n)}:prior(m,p,v);await assert.rejects(run({...opt(f),mode:'VALIDATE'}),/observed block gas limit/);}});
test('fee cap below live base plus tip still rejected',async()=>{const f=fixture(),prior=f.state.tamper;f.state.tamper=(m,p,v)=>m==='eth_getBlockByNumber'&&p[0]==='latest'?{...v,baseFeePerGas:R.hex(1500000000n)}:prior(m,p,v);await assert.rejects(run({...opt(f),mode:'VALIDATE'}),/base fee and tip/);});
test('signed transaction cannot exceed new gas bound',async()=>{const f=fixture();const sign=f.wallet.signTransaction.bind(f.wallet);f.wallet.signTransaction=t=>sign({...t,gasLimit:12000001n});await assert.rejects(run({...opt(f),mode:'EXECUTE'}),/Original signed transaction differs/);assert.equal(f.state.broadcasts.length,0);});
