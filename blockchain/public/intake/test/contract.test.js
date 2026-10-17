'use strict';
const {test,before,after}=require('node:test'),assert=require('node:assert/strict');
const crypto=require('node:crypto');
const ganache=require('ganache'),{BrowserProvider,ContractFactory,encodeBytes32String}=require('ethers');
const {compile}=require('../compile'),{argumentsFor,METADATA,POLICY,NAMESPACE}=require('../payload');
const payload=(changes={})=>({policy:POLICY,namespace:NAMESPACE,dataset:'TRANSFER_HISTORY',publication_id:'1'.repeat(64),
    public_sha256:'2'.repeat(64),merkle_root:'3'.repeat(64),fabric_destination_sha256:'4'.repeat(64),fabric_transaction_id:'5'.repeat(64),
    fabric_receipt_sha256:'6'.repeat(64),...changes});
const artifact=compile(),args=argumentsFor(payload()),zero='0x'+'00'.repeat(32);
let rpc,provider,writer,other;
const plain=x=>Array.isArray(x)?Array.from(x,plain):x;
async function environment(chainId=11155111){
    const r=ganache.provider({chain:{chainId,hardfork:'shanghai'},logging:{quiet:true},wallet:{totalAccounts:3},miner:{blockGasLimit:30000000}});
    const p=new BrowserProvider(r);p.pollingInterval=10;return {rpc:r,provider:p,writer:await p.getSigner(0),other:await p.getSigner(1)};
}
before(async()=>{({rpc,provider,writer,other}=await environment());});
after(async()=>{provider.destroy();await rpc.disconnect();});
async function deploy(){const c=await new ContractFactory(artifact.abi,artifact.bytecode,writer).deploy(await writer.getAddress());await c.waitForDeployment();return c;}
const h=n=>'0x'+crypto.createHash('sha256').update(String(n)).digest('hex');
async function publish(c,a=args){return (await c.publish(...a)).wait();}
async function revertedTransaction(fn){await assert.rejects(async()=>{const tx=await fn();await tx.wait();},e=>e.receipt?.status===0);}

test('pinned compiler and ABI expose only intended functions; no upgrade, delete or payment entry',()=>{
    assert.match(artifact.compiler,/^0\.8\.30\+commit\.73712a01\./);
    assert.deepEqual(artifact.abi.filter(x=>x.type==='function').map(x=>x.name).sort(),['CHAIN_ID','NAMESPACE','POLICY','publish','readPublication','writer'].sort());
    assert.equal(artifact.abi.some(x=>['fallback','receive'].includes(x.type)||x.stateMutability==='payable'),false);
});
test('constructor pins Sepolia, writer and dedicated intake constants',async()=>{
    const e=await environment(31337);
    try{await assert.rejects(new ContractFactory(artifact.abi,artifact.bytecode,e.writer).deploy(await e.writer.getAddress()),e=>e.info?.error?.data?.reason==='Sepolia chain required');}
    finally{e.provider.destroy();await e.rpc.disconnect();}
    const c=await deploy();assert.equal(await c.writer(),await writer.getAddress());
    assert.equal(await c.POLICY(),'PERSONNEL_INTAKE_PUBLIC_ANCHOR_V1');assert.equal(await c.NAMESPACE(),'personnel-intake-anchor-v1');
});
test('publication emits the dataset code and opaque metadata; public read returns exact values',async()=>{
    const c=await deploy(),r=await publish(c);assert.equal(r.status,1);assert.equal(r.logs.length,1);
    const event=c.interface.parseLog(r.logs[0]);assert.equal(event.name,'Published');
    assert.deepEqual(Array.from(event.args),[args[0],encodeBytes32String('TRANSFER_HISTORY'),...args[2]]);
    const stored=await c.connect(other).readPublication(args[0]);
    assert.equal(stored[0],encodeBytes32String('TRANSFER_HISTORY'));assert.deepEqual(Array.from(stored[1]),args[2]);assert.equal(stored[2],BigInt(r.blockNumber));
    assert.equal(c.interface.encodeFunctionData('publish',args).length,2+228*2);
});
test('non-writer cannot publish; zero values fail without state',async()=>{
    const c=await deploy();await assert.rejects(c.connect(other).publish.staticCall(...args),/writer required/);
    await revertedTransaction(()=>c.connect(other).publish(...args,{gasLimit:500000}));
    await assert.rejects(c.publish.staticCall(zero,args[1],args[2]),/zero publication/);
    await assert.rejects(c.publish.staticCall(args[0],zero,args[2]),/zero publication/);
    for(let i=0;i<5;i++){const m=[...args[2]];m[i]=zero;await assert.rejects(c.publish.staticCall(args[0],args[1],m),/zero metadata/);}
    await assert.rejects(c.readPublication(args[0]),/publication absent/);
});
test('a changed dataset or commitment under the same publication ID is refused and the first is preserved',async()=>{
    const c=await deploy();await publish(c);const before=await c.readPublication(args[0]);
    await assert.rejects(c.publish.staticCall(args[0],encodeBytes32String('EDUCATION'),args[2]),/publication conflict/);
    for(let i=0;i<5;i++){const m=[...args[2]];m[i]=h('conflict '+i);await assert.rejects(c.publish.staticCall(args[0],args[1],m),/publication conflict/);}
    assert.deepEqual(plain(await c.readPublication(args[0])),plain(before));
});
test('exact retry is a no-op: no storage write and no event',async()=>{
    const c=await deploy();await publish(c);const before=await c.readPublication(args[0]),retry=await publish(c);
    assert.equal(retry.logs.length,0);assert.deepEqual(plain(await c.readPublication(args[0])),plain(before));
    const trace=await rpc.request({method:'debug_traceTransaction',params:[retry.hash,{disableStorage:true,disableMemory:true,disableStack:true}]});
    assert.equal(trace.structLogs.some(x=>x.op==='SSTORE'||/^LOG[0-4]$/.test(x.op)),false);
});
test('trailing data, truncated calldata and native currency are refused at the EVM boundary',async()=>{
    const c=await deploy(),to=await c.getAddress(),data=c.interface.encodeFunctionData('publish',args);
    for(const raw of [data+'00',data.slice(0,-2),'0xdeadbeef'])await revertedTransaction(()=>writer.sendTransaction({to,data:raw,gasLimit:500000}));
    await revertedTransaction(()=>writer.sendTransaction({to,value:1n,data,gasLimit:500000}));
    assert.equal(await provider.getBalance(to),0n);await assert.rejects(c.readPublication(args[0]),/publication absent/);
});
test('payload schema refuses unregistered datasets and promotion policies before signing',()=>{
    for(const bad of [payload({dataset:'PROMOTION_HISTORY'}),payload({policy:'PROMOTIONS_PUBLIC_ANCHOR_V1'}),payload({merkle_root:'0'.repeat(64)}),{...payload(),officer_nic_no:'x'}])
        assert.throws(()=>argumentsFor(bad));
});
