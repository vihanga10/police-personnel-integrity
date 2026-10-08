'use strict';
const fs=require('node:fs'),path=require('node:path');
const {ContractFactory,Interface,Transaction,getCreateAddress,getAddress}=require('ethers');
const F=require('./deployment-files'),R=require('./sepolia-rpc');
const POLICY='SEPOLIA_CONTRACT_DEPLOYMENT_V1';
// Conservative local deployment bound below EIP-7825's 16,777,216 transaction cap.
const MAX_DEPLOYMENT_GAS=12000000n;
const fail=message=>{throw new Error(message);};
const lower=s=>typeof s==='string'?s.toLowerCase():s;
async function deploymentData(a){const factory=new ContractFactory(a.abi,a.bytecode);return (await factory.getDeployTransaction(a.writer)).data;}
function artifactIdentity(a){return {source_sha256:a.source_sha256,creation_sha256:a.creation_sha256,runtime_sha256:a.runtime_sha256,compiler:a.compiler,settings_sha256:a.settings_sha256,writer:a.writer};}
async function preflight(rpcs,config,a){const heads=await R.network(rpcs),data=await deploymentData(a);const views=await Promise.all(rpcs.map(async(r,i)=>{const [balance,latest,pending,estimate]=await Promise.all([r.call('eth_getBalance',[a.writer,'latest']),r.call('eth_getTransactionCount',[a.writer,'latest']),r.call('eth_getTransactionCount',[a.writer,'pending']),r.call('eth_estimateGas',[{from:a.writer,data,value:'0x0',maxFeePerGas:R.hex(config.maxFee),maxPriorityFeePerGas:R.hex(config.tip)}])]);if(R.quantity(heads[i].baseFeePerGas)+config.tip>config.maxFee)fail('Fee cap below current base fee and tip');return {balance:R.quantity(balance),latest:R.quantity(latest),pending:R.quantity(pending),estimate:R.quantity(estimate),gasCap:R.quantity(heads[i].gasLimit)};}));
    if(views[0].latest!==views[1].latest||views[0].pending!==views[1].pending||views[0].latest!==views[0].pending)fail('Wallet nonce not idle on both RPCs');
    const estimate=views.reduce((max,v)=>v.estimate>max?v.estimate:max,0n),gas=(estimate*120n+99n)/100n;
    if(gas<=0n||gas>MAX_DEPLOYMENT_GAS)fail('Deployment exceeds local gas limit');
    if(views.some(v=>gas>v.gasCap))fail('Deployment exceeds observed block gas limit');
    if(gas*config.maxFee>config.budget)fail('Deployment exceeds configured fee budget');
    if(views.some(v=>v.balance<gas*config.maxFee))fail('Wallet balance below maximum deployment cost');
    if(views[0].latest>BigInt(Number.MAX_SAFE_INTEGER))fail('Nonce exceeds safe range');
    return {data,nonce:Number(views[0].latest),gasLimit:gas};
}
async function verifyPrepared(p,a,config){if(p.policy!==POLICY||p.chain_id!==11155111||p.genesis!==R.GENESIS||p.config_sha256!==config.sha256||F.stable(p.artifact)!==F.stable(artifactIdentity(a)))fail('Prepared deployment binding differs');
    if(F.stable(Object.keys(p).sort())!==F.stable(['artifact','chain_id','config_sha256','contract_address','genesis','policy','raw_transaction','transaction_hash']))fail('Prepared fields differ');
    const t=Transaction.from(p.raw_transaction),data=await deploymentData(a);
    if(!t.isSigned()||t.hash!==p.transaction_hash||t.type!==2||t.chainId!==11155111n||getAddress(t.from)!==a.writer||t.to!==null||t.value!==0n||t.data!==data||t.maxFeePerGas!==config.maxFee||t.maxPriorityFeePerGas!==config.tip||t.accessList?.length!==0||t.gasLimit<=0n||t.gasLimit>MAX_DEPLOYMENT_GAS||t.gasLimit*config.maxFee>config.budget||getCreateAddress({from:t.from,nonce:t.nonce})!==p.contract_address)fail('Original signed transaction differs');return t;
}
async function observe(rpcs,p,a,config,t){const receipts=await Promise.all(rpcs.map(r=>r.call('eth_getTransactionReceipt',[p.transaction_hash])));if(receipts.every(v=>v===null))return {status:'PENDING',reason:'ORIGINAL_RECEIPT_NOT_YET_AVAILABLE'};if(receipts.some(v=>v===null))return {status:'PENDING',reason:'BOTH_RPC_RECEIPTS_REQUIRED'};
    const identity=receipt=>({transactionHash:receipt.transactionHash,blockHash:receipt.blockHash,blockNumber:receipt.blockNumber,contractAddress:lower(receipt.contractAddress),from:lower(receipt.from),to:receipt.to,status:receipt.status,gasUsed:receipt.gasUsed,effectiveGasPrice:receipt.effectiveGasPrice,transactionIndex:receipt.transactionIndex,logs:receipt.logs});
    if(F.stable(identity(receipts[0]))!==F.stable(identity(receipts[1])))fail('RPC deployment receipts disagree');
    const receipt=receipts[0],number=R.quantity(receipt.blockNumber);R.hash(receipt.blockHash);
    if(receipt.transactionHash!==p.transaction_hash||R.quantity(receipt.status)!==1n||lower(receipt.contractAddress)!==lower(p.contract_address)||lower(receipt.from)!==lower(a.writer)||receipt.to!==null||!Array.isArray(receipt.logs)||receipt.logs.length!==0||R.quantity(receipt.gasUsed)>t.gasLimit||R.quantity(receipt.effectiveGasPrice)>config.maxFee)fail('Original deployment receipt invalid');R.quantity(receipt.transactionIndex);
    const iface=new Interface(a.abi);
    const checks=await Promise.all(rpcs.map(async r=>{const [block,head,finalized,tx,code,writer,officers,chain]=await Promise.all([
        r.call('eth_getBlockByNumber',[receipt.blockNumber,false]),r.call('eth_getBlockByNumber',['latest',false]),r.call('eth_getBlockByNumber',['finalized',false]),r.call('eth_getTransactionByHash',[p.transaction_hash]),r.call('eth_getCode',[p.contract_address,receipt.blockNumber]),
        r.call('eth_call',[{to:p.contract_address,data:iface.encodeFunctionData('writer')},receipt.blockNumber]),r.call('eth_call',[{to:p.contract_address,data:iface.encodeFunctionData('OFFICERS')},receipt.blockNumber]),r.call('eth_call',[{to:p.contract_address,data:iface.encodeFunctionData('CHAIN_ID')},receipt.blockNumber])]);
        if(!block||block.hash!==receipt.blockHash||R.quantity(block.number)!==number||!block.transactions?.includes(p.transaction_hash)||!tx||tx.hash!==p.transaction_hash||tx.blockHash!==receipt.blockHash||R.quantity(tx.blockNumber)!==number||lower(tx.from)!==lower(a.writer)||tx.to!==null||tx.input!==t.data||R.quantity(tx.nonce)!==BigInt(t.nonce)||R.quantity(tx.chainId)!==t.chainId||R.quantity(tx.type)!==2n||R.quantity(tx.value)!==0n||R.quantity(tx.gas)!==t.gasLimit||R.quantity(tx.maxFeePerGas)!==t.maxFeePerGas||R.quantity(tx.maxPriorityFeePerGas)!==t.maxPriorityFeePerGas)fail('Original inclusion or transaction readback differs');
        if(code!==a.runtime||getAddress(iface.decodeFunctionResult('writer',writer)[0])!==a.writer||iface.decodeFunctionResult('OFFICERS',officers)[0]!==6596n||iface.decodeFunctionResult('CHAIN_ID',chain)[0]!==11155111n)fail('Deployed runtime or writer differs');
        const confirmed=R.quantity(head.number)>=number+BigInt(config.confirmations)-1n,final=finalized!==null&&R.quantity(finalized.number)>=number;
        // Check the inclusion block again after the finality query to catch a changed fork.
        const again=await r.call('eth_getBlockByNumber',[receipt.blockNumber,false]);if(again?.hash!==receipt.blockHash)fail('Deployment inclusion reorg detected');
        return confirmed&&final;
    }));
    if(checks.some(v=>!v))return {status:'PENDING',reason:'FINALIZED_BLOCK_AND_CONFIRMATIONS_REQUIRED',transaction_hash:p.transaction_hash,contract_address:p.contract_address};
    return {policy:POLICY,status:'PASSED',chain_id:11155111,genesis:R.GENESIS,transaction_hash:p.transaction_hash,contract_address:p.contract_address,writer:a.writer,block_number:Number(number),block_hash:receipt.blockHash,gas_used:receipt.gasUsed,effective_gas_price:receipt.effectiveGasPrice,artifact:artifactIdentity(a),config_sha256:config.sha256,two_rpc_readback:true,finalized:true,minimum_confirmations:config.confirmations,research_commitments_submitted:0};
}
async function run({mode,wallet,rpcs,config,artifact:a,directory,interrupt=()=>{}}){if(!['VALIDATE','EXECUTE','RECONCILE'].includes(mode))fail('Unknown deployment mode');if(wallet.address!==a.writer)fail('Writer wallet differs');let submitted=false;const prepared=path.join(directory,'PREPARED.json'),completed=path.join(directory,'PASSED.json');
    if(mode==='VALIDATE'&&!fs.existsSync(prepared)){const check=await preflight(rpcs,config,a);return {status:'PASSED',mode,chain_id:11155111,writer:a.writer,estimated_gas_limit:check.gasLimit.toString(),maximum_fee_wei:(check.gasLimit*config.maxFee).toString(),research_commitments_submitted:0,deployment_submitted:false};}
    if(!fs.existsSync(prepared)){if(mode!=='EXECUTE')fail('Reconciliation cannot create a deployment');const check=await preflight(rpcs,config,a);F.privateDir(directory,true);const raw=await wallet.signTransaction({type:2,chainId:11155111,nonce:check.nonce,data:check.data,value:0n,gasLimit:check.gasLimit,maxFeePerGas:config.maxFee,maxPriorityFeePerGas:config.tip,accessList:[]});const tx=Transaction.from(raw);F.write(prepared,{policy:POLICY,chain_id:11155111,genesis:R.GENESIS,config_sha256:config.sha256,artifact:artifactIdentity(a),raw_transaction:raw,transaction_hash:tx.hash,contract_address:getCreateAddress({from:wallet.address,nonce:tx.nonce})});await interrupt('AFTER_PREPARE');}
    const p=F.read(prepared),t=await verifyPrepared(p,a,config);await R.network(rpcs);
    let result=await observe(rpcs,p,a,config,t);
    if(result.status==='PENDING'&&result.reason==='ORIGINAL_RECEIPT_NOT_YET_AVAILABLE'&&mode==='EXECUTE'){
        // Never replace fees/nonce. Both RPCs may receive only the original signed bytes.
        await R.network(rpcs);const nonceViews=await Promise.all(rpcs.map(async r=>{const [latest,pending,known]=await Promise.all([r.call('eth_getTransactionCount',[wallet.address,'latest']),r.call('eth_getTransactionCount',[wallet.address,'pending']),r.call('eth_getTransactionByHash',[p.transaction_hash])]);return {latest:R.quantity(latest),pending:R.quantity(pending),known};}));
        if(nonceViews.some(v=>v.latest>BigInt(t.nonce)))fail('Nonce consumed without original receipt; manual review required');
        if(nonceViews.some(v=>v.latest<BigInt(t.nonce)||v.pending>BigInt(t.nonce)+1n||(v.pending>BigInt(t.nonce)&&v.known?.hash!==p.transaction_hash)))fail('Unrelated pending nonce requires review');
        let acknowledged=false;for(const r of rpcs){try{submitted=true;const hash=await r.call('eth_sendRawTransaction',[p.raw_transaction]);if(hash!==p.transaction_hash)fail('Broadcast hash differs');acknowledged=true;break;}catch(error){if(error.message==='Broadcast hash differs')throw error;}}
        await interrupt('AFTER_BROADCAST');result=await observe(rpcs,p,a,config,t);if(!acknowledged&&result.status==='PENDING')fail('Ambiguous broadcast; original signed transaction preserved');
    }
    await interrupt('AFTER_READBACK');
    if(fs.existsSync(completed)){if(result.status!=='PASSED'||F.stable(F.read(completed))!==F.stable(result))fail('Saved completion no longer reconciles');}
    else if(result.status==='PASSED'&&mode!=='VALIDATE'){F.write(completed,result);await interrupt('AFTER_RECEIPT');}
    return {...result,mode,deployment_submitted:submitted};
}
module.exports={run,preflight,verifyPrepared,observe,deploymentData,artifactIdentity};
