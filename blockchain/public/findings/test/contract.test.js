'use strict';
const {test,before,after}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const ganache=require('ganache'),solc=require('solc'),{BrowserProvider,ContractFactory,Interface}=require('ethers');
const {compile}=require('../compile'),{argumentsFor,METADATA}=require('../payload'),vector=require('./public-vector.json');
const artifact=compile(),args=argumentsFor(vector.payload),zero='0x'+'00'.repeat(32);
let rpc,provider,writer,other;
const plain=x=>Array.isArray(x)?Array.from(x,plain):x;
async function environment(chainId=11155111){
    const r=ganache.provider({chain:{chainId,hardfork:'shanghai'},logging:{quiet:true},wallet:{totalAccounts:3},miner:{blockGasLimit:30000000}});
    const p=new BrowserProvider(r);p.pollingInterval=10;return {rpc:r,provider:p,writer:await p.getSigner(0),other:await p.getSigner(1)};
}
before(async()=>{({rpc,provider,writer,other}=await environment());});
after(async()=>{provider.destroy();await rpc.disconnect();});
async function deploy(){const c=await new ContractFactory(artifact.abi,artifact.bytecode,writer).deploy(await writer.getAddress());await c.waitForDeployment();return c;}
function h(n){return '0x'+crypto.createHash('sha256').update(String(n)).digest('hex');}
function values(n){return Array.from({length:5},(_,i)=>h(n+':'+i));}
async function publish(c,a=args){return (await c.publish(...a)).wait();}
async function revertedTransaction(fn){await assert.rejects(async()=>{const tx=await fn();await tx.wait();},e=>e.receipt?.status===0);}
test('pinned compiler and ABI expose only intended functions; no upgrade/delete/payment entry',()=>{
    assert.match(artifact.compiler,/^0\.8\.30\+commit\.73712a01\./);
    assert.deepEqual(artifact.abi.filter(x=>x.type==='function').map(x=>x.name).sort(),['CHAIN_ID','NAMESPACE','POLICY','publish','readPublication','writer'].sort());
    assert.equal(artifact.abi.filter(x=>x.type==='event').length,1);
    assert.equal(artifact.abi.some(x=>['fallback','receive'].includes(x.type)||x.stateMutability==='payable'),false);
    assert.ok(Object.keys(artifact.immutableReferences).length>0);
    assert.deepEqual(compile(),artifact);
});
test('constructor rejects wrong chain in actual EVM',async()=>{
    const e=await environment(31337);try{await assert.rejects(new ContractFactory(artifact.abi,artifact.bytecode,e.writer).deploy(await e.writer.getAddress()),e=>e.info?.error?.data?.reason==='Sepolia chain required');}finally{e.provider.destroy();await e.rpc.disconnect();}
});
test('constructor rejects zero writer and pins deployed constants',async()=>{
    await assert.rejects(new ContractFactory(artifact.abi,artifact.bytecode,writer).deploy('0x'+'00'.repeat(20)),e=>e.info?.error?.data?.reason==='zero writer');
    const c=await deploy();assert.equal(await c.writer(),await writer.getAddress());assert.equal(await c.CHAIN_ID(),11155111n);
    assert.equal(await c.POLICY(),'FINDINGS_PUBLIC_ANCHOR_V1');assert.equal(await c.NAMESPACE(),'findings-anchor-v1');
});
test('actual publication emits exact opaque Python payload and first block; public read is permissionless',async()=>{
    const c=await deploy(),r=await publish(c);assert.equal(r.status,1);assert.equal(r.logs.length,1);
    const event=c.interface.parseLog(r.logs[0]);assert.equal(event.name,'Published');assert.deepEqual(Array.from(event.args),[args[0],...args[1]]);
    const stored=await c.connect(other).readPublication(args[0]);assert.deepEqual(Array.from(stored[0]),args[1]);assert.equal(stored[1],BigInt(r.blockNumber));
    assert.equal(c.interface.encodeFunctionData('publish',args).length,2+196*2);
});
test('unknown and zero publication reads fail',async()=>{const c=await deploy();for(const id of [zero,h('absent')])await assert.rejects(c.readPublication(id),/publication absent/);});
test('non-writer cannot create or retry a publication, including mined reverted transactions',async()=>{
    const c=await deploy();await assert.rejects(c.connect(other).publish.staticCall(...args),/writer required/);
    await revertedTransaction(()=>c.connect(other).publish(...args,{gasLimit:500000}));
    await assert.rejects(c.readPublication(args[0]),/publication absent/);await publish(c);
    await assert.rejects(c.connect(other).publish.staticCall(...args),/writer required/);
    await revertedTransaction(()=>c.connect(other).publish(...args,{gasLimit:500000}));
    assert.deepEqual(Array.from((await c.readPublication(args[0]))[0]),args[1]);
});
test('zero publication ID fails without creating state',async()=>{const c=await deploy();await assert.rejects(c.publish.staticCall(zero,args[1]),/zero publication/);});
for(let i=0;i<5;i++)test('zero '+METADATA[i]+' fails without creating state',async()=>{
    const c=await deploy(),m=[...args[1]];m[i]=zero;await assert.rejects(c.publish.staticCall(args[0],m),/zero metadata/);await assert.rejects(c.readPublication(args[0]),/publication absent/);
});
for(let i=0;i<5;i++)test('conflicting '+METADATA[i]+' preserves the first publication',async()=>{
    const c=await deploy();await publish(c);const before=await c.readPublication(args[0]),m=[...args[1]];m[i]=h('conflict '+i);
    await assert.rejects(c.publish.staticCall(args[0],m),/publication conflict/);
    await revertedTransaction(()=>c.publish(args[0],m,{gasLimit:500000}));assert.deepEqual(plain(await c.readPublication(args[0])),plain(before));
});
test('exact retry preserves block/content and executes no SSTORE or event opcodes',async()=>{
    const c=await deploy();await publish(c);const before=await c.readPublication(args[0]),retry=await publish(c);
    assert.equal(retry.logs.length,0);assert.deepEqual(plain(await c.readPublication(args[0])),plain(before));
    const trace=await rpc.request({method:'debug_traceTransaction',params:[retry.hash,{disableStorage:true,disableMemory:true,disableStack:true}]});
    assert.ok(trace.structLogs.length>0);assert.equal(trace.structLogs.some(x=>x.op==='SSTORE'||/^LOG[0-4]$/.test(x.op)),false);
});
test('many later publications append independently and retain original historical/current values',async()=>{
    const c=await deploy(),first=await publish(c);
    for(let n=1;n<=20;n++){const m=values(n),r=await publish(c,[h(n),m]);assert.equal(r.status,1);assert.deepEqual(Array.from((await c.readPublication(h(n)))[0]),m);}
    const now=await c.readPublication(args[0]),then=await c.readPublication(args[0],{blockTag:first.blockNumber});assert.deepEqual(plain(now),plain(then));assert.deepEqual(Array.from(now[0]),args[1]);
});
test('trailing private data, truncated ABI and unknown selectors fail at the EVM boundary',async()=>{
    const c=await deploy(),to=await c.getAddress(),data=c.interface.encodeFunctionData('publish',args);
    for(const raw of [data+'00',data+'12'.repeat(32),data.slice(0,-2),'0xdeadbeef']){
        await assert.rejects(provider.call({to,from:await writer.getAddress(),data:raw}));
        await revertedTransaction(()=>writer.sendTransaction({to,data:raw,gasLimit:500000}));
    }
    await assert.rejects(c.readPublication(args[0]),/publication absent/);
    await publish(c);await assert.rejects(provider.call({to,data:c.interface.encodeFunctionData('readPublication',[args[0]])+'00'}),/exact read calldata required/);
});
test('native currency is rejected by publish and by direct transfers',async()=>{
    const c=await deploy(),to=await c.getAddress();
    await revertedTransaction(()=>writer.sendTransaction({to,value:1n,data:c.interface.encodeFunctionData('publish',args),gasLimit:500000}));
    await revertedTransaction(()=>writer.sendTransaction({to,value:1n,gasLimit:500000}));
    assert.equal(await provider.getBalance(to),0n);await assert.rejects(c.readPublication(args[0]),/publication absent/);
});
test('original OfficerEvidence batch and runtime remain intact after findings append/conflict/retry',async()=>{
    const source=fs.readFileSync(path.join(__dirname,'../../contracts/OfficerEvidence.sol'),'utf8');
    const input={language:'Solidity',sources:{'OfficerEvidence.sol':{content:source}},settings:{optimizer:{enabled:true,runs:200},evmVersion:'shanghai',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}};
    const out=JSON.parse(solc.compile(JSON.stringify(input)));assert.equal((out.errors||[]).some(e=>e.severity==='error'),false);
    const a=out.contracts['OfficerEvidence.sol'].OfficerEvidence,evidence=await new ContractFactory(a.abi,'0x'+a.evm.bytecode.object,writer).deploy(await writer.getAddress());await evidence.waitForDeployment();
    const batch=h('original evidence batch'),metadata=values('evidence'),proof=[];
    const leaf=Buffer.concat([Buffer.from([0]),Buffer.from(JSON.stringify({commitment:metadata[4].slice(2),kind:'BATCH',publication_id:batch.slice(2)}))]);
    let node=crypto.createHash('sha256').update(leaf).digest(),index=6596,width=6597;
    while(width>1){const other=index%2===0&&index+1===width?node:Buffer.from(h('proof '+width).slice(2),'hex');proof.push('0x'+other.toString('hex'));
        node=crypto.createHash('sha256').update(Buffer.concat([Buffer.from([1]),...(index%2?[other,node]:[node,other])])).digest();index=Math.floor(index/2);width=Math.ceil(width/2);}
    metadata[1]='0x'+node.toString('hex');await(await evidence.createBatch(batch,metadata,proof)).wait();
    const before=await evidence.readBatch(batch),address=await evidence.getAddress(),runtime=await provider.getCode(address),c=await deploy();
    assert.notEqual(await c.getAddress(),address);await publish(c);await publish(c,[h('correction/review publication'),values('later')]);await publish(c);
    await assert.rejects(c.publish.staticCall(args[0],values('conflict')),/publication conflict/);
    assert.deepEqual(plain(await evidence.readBatch(batch)),plain(before));assert.equal(await provider.getCode(address),runtime);assert.equal(await evidence.writer(),await writer.getAddress());
});
