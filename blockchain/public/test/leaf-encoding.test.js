'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const ganache=require('ganache'),{BrowserProvider,ContractFactory}=require('ethers');
const {compile}=require('../compile'),{canonical}=require('../../fabric/chaincode/lib/evidence');
test('optimized leaf encoding agrees with independent SHA256 for every nibble and random bytes',async()=>{
    const rpc=ganache.provider({chain:{chainId:11155111,hardfork:'shanghai'},logging:{quiet:true}}),provider=new BrowserProvider(rpc);
    provider.pollingInterval=10;
    try{
        const signer=await provider.getSigner(),a=compile(),c=await new ContractFactory(a.abi,a.bytecode,signer).deploy(await signer.getAddress());await c.waitForDeployment();
        const values=[...'0123456789abcdef'].map(v=>v.repeat(64));
        for(let i=0;i<16;i++)values.push(crypto.randomBytes(32).toString('hex'));
        for(let i=0;i<values.length;i++){
            const row={publication_id:values[i],commitment_version:1,commitment:values[values.length-1-i]};
            const expected='0x'+crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0]),Buffer.from(canonical({kind:'OFFICER',...row}))])).digest('hex');
            assert.equal(await c.officerLeaf('0x'+row.publication_id,'0x'+row.commitment),expected);
        }
    }finally{provider.destroy();await rpc.disconnect();}
});
