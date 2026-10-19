'use strict';
// Real signing/compiler artifacts; mocked chain responses, not live readiness.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {Wallet,Interface,Transaction,getCreateAddress}=require('ethers');
const {artifact}=require('../artifact'),{run}=require('../live-deployment-engine'),R=require('../live-network'),F=require('../../deployment-files');
const {temp}=require('../../test/sepolia-test-support');
function fake(){const wallet=Wallet.createRandom(),base=artifact(wallet.address),a={...base,writer:wallet.address,creation_sha256:F.digest(base.bytecode),settings_sha256:F.digest(base.settings)},iface=new Interface(a.abi),state={raw:null,writes:0,receipts:true,final:true,lost:false,fault:null},config=R.settings({policy:R.POLICY,rpc_urls:['https://one.quiknode.pro/test','https://eth-sepolia.g.alchemy.com/v2/test'],max_fee_gwei:'5',priority_fee_gwei:'1',max_total_fee_eth:'0.025',confirmations:12});
  const hash='0x'+'ab'.repeat(32),head='0x'+'cd'.repeat(32);
  const rpcs=[0,1].map(peer=>({call:async(m,p)=>{const t=state.raw?Transaction.from(state.raw):null;let v;switch(m){
    case 'eth_chainId':v='0xaa36a7';break;
    case 'eth_getBlockByNumber':v=p[0]==='0x0'?{number:'0x0',hash:R.GENESIS}:p[0]==='latest'?{number:'0x70',hash:head,timestamp:R.hex(Math.floor(Date.now()/1000)),gasLimit:'0x1c9c380',baseFeePerGas:R.hex(1000000000)}:p[0]==='finalized'?(state.final?{number:'0x70',hash:head}:{number:'0x1',hash:'0x'+'01'.repeat(32)}):p[0]==='0x70'?{number:'0x70',hash:head}:{number:'0x60',hash,transactions:t?[t.hash]:[]};break;
    case 'eth_getBalance':v=R.hex(10n**18n);break;
    case 'eth_getTransactionCount':v=t?'0x1':'0x0';break;
    case 'eth_estimateGas':v='0x1e8480';break;
    case 'eth_sendRawTransaction':state.writes++;state.raw=p[0];if(state.lost)throw Error('lost ack');v=Transaction.from(p[0]).hash;break;
    case 'eth_getTransactionReceipt':v=t&&state.receipts?{transactionHash:t.hash,blockHash:hash,blockNumber:'0x60',contractAddress:getCreateAddress({from:wallet.address,nonce:t.nonce}),from:wallet.address,to:null,status:'0x1',gasUsed:'0x1e8480',effectiveGasPrice:R.hex(2000000000),transactionIndex:'0x0',logs:[]}:null;break;
    case 'eth_getTransactionByHash':v=t?{hash:t.hash,blockHash:hash,blockNumber:'0x60',from:wallet.address,to:null,input:t.data,nonce:R.hex(t.nonce),chainId:R.hex(t.chainId),type:'0x2',value:'0x0',gas:R.hex(t.gasLimit),maxFeePerGas:R.hex(t.maxFeePerGas),maxPriorityFeePerGas:R.hex(t.maxPriorityFeePerGas)}:null;break;
    case 'eth_getCode':v=a.runtime;break;
    case 'eth_call':{const name=iface.parseTransaction({data:p[0].data}).name;v=iface.encodeFunctionResult(name,[name==='writer'?wallet.address:name==='CHAIN_ID'?11155111n:name==='POLICY'?'FINDINGS_PUBLIC_ANCHOR_V1':'findings-anchor-v1']);break;}
    default:throw Error('unexpected RPC');}return state.fault?state.fault(m,p,v,peer):v;}}));return {wallet,artifact:a,config,rpcs,directory:temp(),state};}
test('dedicated deployment preview does not sign or broadcast; final result verifies dedicated constants',async()=>{const f=fake();assert.equal((await run({...f,mode:'VALIDATE'})).status,'PASSED');assert.equal(f.state.writes,0);assert.equal(fs.existsSync(path.join(f.directory,'PREPARED.json')),false);const result=await run({...f,mode:'EXECUTE'});assert.equal(result.status,'PASSED');assert.equal(result.findings_publications_submitted,0);assert.equal((await run({...f,mode:'RECONCILE'})).status,'PASSED');assert.equal(f.state.writes,1);});
test('lost deployment acknowledgement has one broadcast and read-only recovery retains signed bytes',async()=>{const f=fake();f.state.lost=true;f.state.receipts=false;await assert.rejects(run({...f,mode:'EXECUTE'}));assert.equal(f.state.writes,1);const original=F.read(path.join(f.directory,'PREPARED.json'));f.state.receipts=true;assert.equal((await run({...f,mode:'RECONCILE'})).status,'PASSED');assert.equal(F.read(path.join(f.directory,'PREPARED.json')).raw_transaction,original.raw_transaction);assert.equal(f.state.writes,1);});
test('pending finality remains pending; mismatched runtime never completes',async()=>{const f=fake();f.state.final=false;assert.equal((await run({...f,mode:'EXECUTE'})).status,'PENDING');f.state.final=true;f.state.fault=(m,p,v)=>m==='eth_getCode'?'0x00':v;await assert.rejects(run({...f,mode:'RECONCILE'}));assert.equal(fs.existsSync(path.join(f.directory,'PASSED.json')),false);});
