'use strict';
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {Wallet,Transaction,Interface,getCreateAddress}=require('ethers');
const F=require('../deployment-files'),R=require('../sepolia-rpc'),{artifact}=require('../deployment-artifact');
function temp(){const directory=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'sepolia-fixture-'));fs.chmodSync(directory,0o700);return directory;}
function config(){return R.configuration({policy:'SEPOLIA_DEPLOYMENT_NETWORK_V1',rpc_urls:['https://one.example.invalid','https://two.example.invalid'],max_fee_gwei:'5',priority_fee_gwei:'1',max_total_fee_eth:'0.025',confirmations:12});}
function fake(){const wallet=Wallet.createRandom(),a=artifact(wallet.address),state={raw:null,broadcasts:[],receipts:true,finality:true,tamper:null,failBroadcast:false};const iface=new Interface(a.abi),blockHash='0x'+'bc'.repeat(32);
    function rpc(peer){return {async call(m,p){const tx=state.raw?Transaction.from(state.raw):null,addr=tx?getCreateAddress({from:wallet.address,nonce:tx.nonce}):null;let v;
        switch(m){case 'eth_chainId':v='0xaa36a7';break;
        case 'eth_getBlockByNumber':if(p[0]==='0x0')v={number:'0x0',hash:R.GENESIS};else if(p[0]==='latest')v={number:'0x70',hash:'0x'+'dd'.repeat(32),timestamp:R.hex(Math.floor(Date.now()/1000)),gasLimit:'0x1c9c380',baseFeePerGas:R.hex(1000000000)};else if(p[0]==='0x70')v={number:'0x70',hash:'0x'+'dd'.repeat(32)};else if(p[0]==='finalized')v=state.finality?{number:'0x70',hash:'0x'+'dd'.repeat(32)}:{number:'0x1',hash:'0x'+'aa'.repeat(32)};else v={number:'0x60',hash:blockHash,transactions:tx?[tx.hash]:[]};break;
        case 'eth_getBalance':v=R.hex(10n**18n);break;
        case 'eth_getTransactionCount':v=tx?'0x1':'0x0';break;
        case 'eth_estimateGas':v='0x1e8480';break;
        case 'eth_sendRawTransaction':state.broadcasts.push(p[0]);state.raw=p[0];if(state.failBroadcast)throw new Error('ambiguous test transport');v=Transaction.from(p[0]).hash;break;
        case 'eth_getTransactionReceipt':v=tx&&state.receipts?{transactionHash:tx.hash,blockHash,blockNumber:'0x60',contractAddress:addr,from:wallet.address,to:null,status:'0x1',gasUsed:'0x1e8480',effectiveGasPrice:R.hex(2000000000),transactionIndex:'0x0',logs:[]}:null;break;
        case 'eth_getTransactionByHash':v=tx?{hash:tx.hash,blockHash,blockNumber:'0x60',from:wallet.address,to:null,input:tx.data,nonce:R.hex(tx.nonce),chainId:R.hex(tx.chainId),type:'0x2',value:'0x0',gas:R.hex(tx.gasLimit),maxFeePerGas:R.hex(tx.maxFeePerGas),maxPriorityFeePerGas:R.hex(tx.maxPriorityFeePerGas)}:null;break;
        case 'eth_getCode':v=a.runtime;break;
        case 'eth_call':{const selector=p[0].data;const name=['writer','OFFICERS','CHAIN_ID'].find(n=>iface.encodeFunctionData(n)===selector);v=iface.encodeFunctionResult(name,[name==='writer'?wallet.address:name==='OFFICERS'?6596n:11155111n]);break;}
        default:throw new Error('Unexpected fixture RPC '+m);}
        return state.tamper?state.tamper(m,p,v,peer):v;
    }};}
    return {wallet,artifact:a,config:config(),rpcs:[rpc(0),rpc(1)],directory:temp(),state};
}
module.exports={temp,config,fake};
