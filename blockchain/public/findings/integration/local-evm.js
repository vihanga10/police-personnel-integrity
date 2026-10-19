'use strict';
// Real in-process EVM. Two views share ONE engine; genesis/finality are fixtures.
const ganache=require('ganache'),crypto=require('node:crypto');
const {Wallet,BrowserProvider,ContractFactory,Transaction}=require('ethers');
const {artifact}=require('../artifact'),N=require('../network');
async function localEvm(){
    const wallet=Wallet.createRandom();
    const engine=ganache.provider({logging:{quiet:true},chain:{chainId:11155111,hardfork:'shanghai'},wallet:{accounts:[{secretKey:wallet.privateKey,balance:'0x'+(10n**20n).toString(16)}]}});
    const provider=new BrowserProvider(engine),signer=await provider.getSigner(wallet.address),a=artifact(wallet.address);
    const deployed=await new ContractFactory(a.abi,a.bytecode,signer).deploy(wallet.address);await deployed.waitForDeployment();
    const config={policy:N.POLICY,rpc_urls:['https://evm-one.example.invalid/','https://evm-two.example.invalid/'],max_fee_gwei:'3',priority_fee_gwei:'1',max_total_fee_eth:'0.005',confirmations:12};
    const destination={chain_id:11155111,contract:(await deployed.getAddress()).toLowerCase(),runtime_sha256:a.runtime_sha256,writer:wallet.address.toLowerCase(),namespace:'findings-anchor-v1',finality:'FINALIZED'};
    const state={broadcasts:0,signs:0,raw:null,throwBefore:false,throwAfter:false,mine:true,finalized:true,hide:[false,false],mutate:null};
    const sign=wallet.signTransaction.bind(wallet);wallet.signTransaction=async t=>{state.signs++;return sign(t);};
    async function mine(n=12){for(let i=0;i<n;i++)await engine.request({method:'evm_mine',params:[]});}
    const rpcs=[0,1].map(i=>({fixture_transport:true,endpoint:config.rpc_urls[i],async call(method,params){
        let value;
        if(method==='eth_getBlockByNumber'&&params[0]==='0x0')value={number:'0x0',hash:N.GENESIS}; // explicitly simulated Sepolia identity
        else if(method==='eth_getBlockByNumber'&&params[0]==='finalized')value=state.finalized?await engine.request({method,params:['latest',false]}):null; // NOT consensus finality
        else if(method==='eth_sendRawTransaction'){
            if(i!==0)throw new Error('Unexpected second-view broadcast');state.broadcasts++;
            if(state.throwBefore)throw new Error('Injected failure before delivery');
            state.raw=params[0];value=await engine.request({method,params});
            if(state.mine)await mine();if(state.throwAfter)throw new Error('Injected lost acknowledgement after real EVM delivery');
        }else if(method==='eth_getTransactionReceipt'&&state.hide[i])value=null;
        else{
            try{value=await engine.request({method,params});}
            catch(e){ // Ganache uses -32000 for EVM revert; retain actual revert bytes.
                if(method==='eth_call'&&typeof e.data==='string'){const error=new Error(e.message);error.code=3;error.data=e.data;throw error;}throw e;
            }
        }
        if(method==='eth_getTransactionReceipt'&&value){value=structuredClone(value);for(const log of value.logs)if(log.removed===undefined)log.removed=false;}
        // Ganache returns the signed chain id; never synthesize transaction identity.
        if(method==='eth_getTransactionByHash'&&value&&state.raw){if(Transaction.from(state.raw).hash!==value.hash)throw new Error('Real EVM transaction differs');}
        return state.mutate?state.mutate(method,params,structuredClone(value),i):value;
    }}));
    return {wallet,engine,provider,config,destination,state,rpcs,mine,async close(){provider.destroy();await engine.disconnect();}};
}
module.exports={localEvm};
