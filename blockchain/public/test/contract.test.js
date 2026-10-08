'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const ganache=require('ganache'),{BrowserProvider,ContractFactory}=require('ethers');
const {compile}=require('../compile'),{plan}=require('../publication'),{fixture,hex}=require('./fixture');
const {canonical}=require('../../fabric/chaincode/lib/evidence');
const crypto=require('node:crypto');
const artifact=compile();
async function environment(chainId=11155111) {
    const rpc=ganache.provider({chain:{chainId,hardfork:'shanghai'},miner:{blockGasLimit:30000000},logging:{quiet:true},wallet:{totalAccounts:2}});
    const provider=new BrowserProvider(rpc);provider.pollingInterval=10;
    const writer=await provider.getSigner(0),other=await provider.getSigner(1);
    return {rpc,provider,writer,other,factory:new ContractFactory(artifact.abi,artifact.bytecode,writer)};
}
async function cleanup(e){e.provider.destroy();await e.rpc.disconnect();}
test('compiled contract rejects non-Sepolia chain and zero writer',async()=>{
    const e=await environment(31337);
    try {await assert.rejects(e.factory.deploy(await e.writer.getAddress()));}finally{await cleanup(e);}
    const f=await environment();
    try{await assert.rejects(f.factory.deploy('0x'+'0'.repeat(40)));}finally{await cleanup(f);}
});
test('compiled contract matches Python/Fabric leaf format and guards every mutation',async()=>{
    const e=await environment(),f=fixture(),p=plan(f.publicPayload,f.digest);
    try {
        const c=await e.factory.deploy(await e.writer.getAddress());await c.waitForDeployment();
        const first=f.publicPayload.officers[0];
        const expected='0x'+crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0]),Buffer.from(canonical({kind:'OFFICER',...first}))])).digest('hex');
        assert.equal(await c.officerLeaf(p.chunks[0].handles[0],p.chunks[0].commitments[0]),expected);
        assert.equal(await c.verify(expected,0,p.chunks[0].proofs[0],p.metadata[1]),true);
        assert.equal(await c.verify(expected,1,p.chunks[0].proofs[0],p.metadata[1]),false);
        assert.equal(await c.verify(expected,0,p.chunks[0].proofs[0].slice(1),p.metadata[1]),false);
        await assert.rejects(c.connect(e.other).createBatch.staticCall(p.batch,p.metadata,p.batch_proof),/writer required/);
        await assert.rejects(c.createBatch.staticCall(p.batch,p.metadata,p.batch_proof.map(()=> '0x'+hex(44))),/batch proof differs/);
        await (await c.createBatch(p.batch,p.metadata,p.batch_proof)).wait();
        await assert.rejects(c.sealBatch.staticCall(p.batch),/incomplete batch/);
        const changed=[...p.metadata];changed[0]='0x'+hex(4567);
        await assert.rejects(c.createBatch.staticCall(p.batch,changed,p.batch_proof),/batch conflict/);
        const ch=p.chunks[0],args=[p.batch,ch.start,ch.handles,ch.commitments,ch.proofs];
        await assert.rejects(c.connect(e.other).appendOfficers.staticCall(...args),/writer required/);
        await assert.rejects(c.connect(e.other).sealBatch.staticCall(p.batch),/writer required/);
        await assert.rejects(c.appendOfficers.staticCall(p.batch,100,p.chunks[1].handles,p.chunks[1].commitments,p.chunks[1].proofs),/chunk order differs/);
        await assert.rejects(c.appendOfficers.staticCall(p.batch,0,ch.handles.slice(1),ch.commitments,ch.proofs),/chunk size differs/);
        const bad=[...ch.commitments];bad[0]='0x'+hex(99999);
        await assert.rejects(c.appendOfficers.staticCall(p.batch,0,ch.handles,bad,ch.proofs),/officer proof differs/);
        assert.equal((await c.readBatch(p.batch))[1],0n);
        await assert.rejects(c.readOfficer(p.batch,ch.handles[0]),/officer absent/);
    } finally {await cleanup(e);}
});
test('local EVM stores and reads all 6596 commitments, seals and preserves exact retries', {timeout:2400000},async()=>{
    const e=await environment(),f=fixture(),p=plan(f.publicPayload,f.digest);
    try {
        const c=await e.factory.deploy(await e.writer.getAddress());await c.waitForDeployment();
        let maxGas=0n,totalGas=0n;
        await (await c.createBatch(p.batch,p.metadata,p.batch_proof)).wait();
        for(const ch of p.chunks) {
            const receipt=await (await c.appendOfficers(p.batch,ch.start,ch.handles,ch.commitments,ch.proofs,{gasLimit:30000000})).wait();
            assert.equal(receipt.status,1);totalGas+=receipt.gasUsed;if(receipt.gasUsed>maxGas)maxGas=receipt.gasUsed;
            if((ch.start/100+1)%10===0 || ch.start===6500) console.log('Local EVM fixture progress: '+(ch.start+ch.handles.length)+' / 6596');
        }
        await (await c.sealBatch(p.batch)).wait();
        const before=await c.readBatch(p.batch);
        assert.equal(before[1],6596n);assert.equal(before[2],true);assert.deepEqual(Array.from(before[0]),p.metadata);
        // Query actual EVM storage for every officer, in bounded parallel groups.
        for(const ch of p.chunks) {
            const values=await Promise.all(ch.handles.map(h=>c.readOfficer(p.batch,h)));
            assert.deepEqual(values,ch.commitments);
        }
        for(const ch of [p.chunks[0],p.chunks.at(-1)]) {
            const retry=await (await c.appendOfficers(p.batch,ch.start,ch.handles,ch.commitments,ch.proofs)).wait();
            assert.equal(retry.logs.length,0);
        }
        const again=await (await c.createBatch(p.batch,p.metadata,p.batch_proof)).wait();assert.equal(again.logs.length,0);
        assert.equal((await (await c.sealBatch(p.batch)).wait()).logs.length,0);
        const after=await c.readBatch(p.batch);
        assert.deepEqual([Array.from(after[0]),after[1],after[2]],[Array.from(before[0]),before[1],before[2]]);
        const ch=p.chunks[0],bad=[...ch.commitments];bad[0]='0x'+hex(444444);
        await assert.rejects(c.appendOfficers.staticCall(p.batch,0,ch.handles,bad,ch.proofs),/chunk conflict/);
        console.log('Local EVM gas (not a Sepolia fee quote): max chunk='+maxGas+' total chunks='+totalGas);
    }finally{await cleanup(e);}
});
