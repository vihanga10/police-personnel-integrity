'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const ganache=require('ganache'),{Wallet}=require('ethers');
const {artifact}=require('../deployment-artifact'),{run}=require('../deployment-engine'),R=require('../sepolia-rpc'),{temp,config}=require('./sepolia-test-support');
test('actual compiled EVM deployment matches immutable runtime and original signed receipt',async()=>{const wallet=Wallet.createRandom(),a=artifact(wallet.address),evm=ganache.provider({chain:{chainId:11155111,hardfork:'shanghai'},wallet:{accounts:[{secretKey:wallet.privateKey,balance:'0x3635c9adc5dea00000'}]},logging:{quiet:true}});try{
    // Test-only adapter supplies Sepolia identity and finalized semantics; Ganache is NOT Sepolia.
    const fixtureRPC={async call(method,params){if(method==='eth_getBlockByNumber'&&params[0]==='0x0')return {number:'0x0',hash:R.GENESIS};if(method==='eth_getBlockByNumber'&&params[0]==='finalized')return evm.request({method,params:['latest',false]});return evm.request({method,params});}};
    const options={wallet,artifact:a,rpcs:[fixtureRPC,fixtureRPC],config:config(),directory:temp()};const first=await run({...options,mode:'EXECUTE',interrupt:async point=>{if(point==='AFTER_BROADCAST')for(let i=0;i<12;i++)await evm.request({method:'evm_mine',params:[]});}});assert.equal(first.status,'PASSED');assert.equal(first.research_commitments_submitted,0);const again=await run({...options,mode:'RECONCILE'});assert.equal(again.transaction_hash,first.transaction_hash);assert.equal(again.contract_address,first.contract_address);
}finally{await evm.disconnect();}});
