'use strict';
const {Interface,Transaction,AbiCoder}=require('ethers');
const N=require('./network'),L=require('./live-network'),{artifact}=require('./artifact'),{argumentsFor,POLICY,NAMESPACE}=require('./payload');
const PLAN='FINDINGS_LIVE_PUBLIC_SIGNED_PLAN_V1',MAX_GAS=500000n;
const address=v=>{N.check(typeof v==='string'&&/^0x[0-9a-f]{40}$/.test(v)&&v!=='0x'+'0'.repeat(40),'Nonzero lowercase address required');return v;};
function destination(d){
    N.exact(d,['chain_id','contract','runtime_sha256','writer','namespace','finality']);
    N.check(d.chain_id===11155111&&d.namespace===NAMESPACE&&d.finality==='FINALIZED','Dedicated finalized Sepolia findings destination required');
    address(d.contract);address(d.writer);N.check(/^[0-9a-f]{64}$/.test(d.runtime_sha256),'Runtime SHA-256 pin required');return d;
}
function absent(e){
    if(e?.code!==3||typeof e.data!=='string'||!e.data.startsWith('0x08c379a0'))return false;
    try{return AbiCoder.defaultAbiCoder().decode(['string'],'0x'+e.data.slice(10))[0]==='publication absent';}catch{return false;}
}
class LivePublicFindingsAdapter{
    constructor({configFile,expectedConfigSha256,repo,destination:d,authorize},dependencies={}) {
        const {privateFile}=require('../../fabric/client/findings-gateway');
        const {parseUnique}=require('./live-json');
        const bytes=privateFile(configFile,repo);N.check(bytes.length<=1048576&&require('node:fs').statSync(configFile).nlink===1,'Bounded unlinked private configuration required');
        N.check(require('./artifact').byteSha(bytes)===expectedConfigSha256,'Approved live configuration differs');
        const config=parseUnique(bytes.toString('utf8'));this.config=L.settings(config);this.destination=structuredClone(destination(d));
        N.check(typeof authorize==='function','Trusted source/publication authorization callback required');
        this.rpcs=config.rpc_urls.map(url=>L.endpoint(url,dependencies));
        this.authorize=async boundary=>{N.check(require('./artifact').byteSha(privateFile(configFile,repo))===expectedConfigSha256,'Live configuration changed');await authorize(boundary);};
        this.artifact=artifact(d.writer);N.check(this.artifact.runtime_sha256===d.runtime_sha256,'Compiled writer-bound runtime pin differs');
        this.iface=new Interface(this.artifact.abi);
    }
    validatePlan(p,operation,payload){
        N.exact(p,['policy','operation','payload_sha256','destination','network_config_sha256','transaction_id','raw_transaction']);
        N.check(p.policy===PLAN&&p.operation===operation&&p.payload_sha256===N.sha(payload)&&N.canonical(p.destination)===N.canonical(this.destination)&&p.network_config_sha256===this.config.sha256,'Original public plan binding differs');
        N.check(typeof p.raw_transaction==='string'&&/^0x[0-9a-f]+$/.test(p.raw_transaction)&&p.raw_transaction.length<20000,'Bounded signed transaction required');
        const t=Transaction.from(p.raw_transaction),data=this.iface.encodeFunctionData('publish',argumentsFor(payload));
        N.check(t.isSigned()&&t.serialized===p.raw_transaction&&t.hash===p.transaction_id&&t.type===2&&t.chainId===11155111n&&t.from.toLowerCase()===this.destination.writer&&t.to?.toLowerCase()===this.destination.contract&&t.value===0n&&t.data===data&&t.accessList?.length===0&&t.gasLimit>0n&&t.gasLimit<=MAX_GAS&&t.maxFeePerGas===this.config.maxFee&&t.maxPriorityFeePerGas===this.config.tip&&t.gasLimit*this.config.maxFee<=this.config.budget,'Original signed public transaction differs');
        N.hash(p.transaction_id);return t;
    }
    async state(block){
        await this.authorize('RUNTIME');
        for(const r of this.rpcs){
            const calls=['writer','CHAIN_ID','POLICY','NAMESPACE'];
            const [code,...answers]=await Promise.all([r.call('eth_getCode',[this.destination.contract,block.tag]),...calls.map(n=>r.call('eth_call',[{to:this.destination.contract,data:this.iface.encodeFunctionData(n)},block.tag]))]);
            N.check(code===this.artifact.runtime,'Findings runtime differs');
            for(let i=0;i<calls.length;i++){
                const value=this.iface.decodeFunctionResult(calls[i],answers[i])[0],expected=[this.destination.writer,11155111n,POLICY,NAMESPACE][i];
                N.check((typeof value==='string'&&calls[i]==='writer'?value.toLowerCase():value)===expected,'Findings runtime constants/writer differ');
                N.check(this.iface.encodeFunctionResult(calls[i],[value])===answers[i],'Canonical getter ABI required');
            }
        }
    }
    async unchanged(block,original){
        for(const r of this.rpcs){
            const again=await r.call('eth_getBlockByNumber',[block.tag,false]);
            N.check(again&&N.quantity(again.number)===block.height&&again.hash===block.hash,'Finalized verification block changed');
            if(original){const b=await r.call('eth_getBlockByNumber',[original.blockNumber,false]);N.check(b&&b.hash===original.blockHash&&N.quantity(b.number)===N.quantity(original.blockNumber),'Original inclusion changed');}
        }
    }
    async preflight(payload){
        await this.authorize('PREFLIGHT');const heads=await N.network(this.rpcs),block=await N.finalized(this.rpcs);
        N.check(block,'Finalized deployment state required');N.check(heads.every(h=>block.height<=N.quantity(h.number)),'Finalized state exceeds latest head');await this.state(block);
        const [id]=argumentsFor(payload),data=this.iface.encodeFunctionData('publish',argumentsFor(payload));
        for(const r of this.rpcs){
            let exists=true;try{await r.call('eth_call',[{to:this.destination.contract,data:this.iface.encodeFunctionData('readPublication',[id])},block.tag]);}catch(e){if(absent(e))exists=false;else throw e;}
            N.check(!exists,'Publication already exists; original transaction lineage required');
        }
        const views=await Promise.all(this.rpcs.map(async(r,i)=>{
            const [balance,latest,pending,estimate]=await Promise.all([r.call('eth_getBalance',[this.destination.writer,'latest']),r.call('eth_getTransactionCount',[this.destination.writer,'latest']),r.call('eth_getTransactionCount',[this.destination.writer,'pending']),r.call('eth_estimateGas',[{from:this.destination.writer,to:this.destination.contract,data,value:'0x0',maxFeePerGas:N.hex(this.config.maxFee),maxPriorityFeePerGas:N.hex(this.config.tip)}])]);
            N.check(N.quantity(heads[i].baseFeePerGas)+this.config.tip<=this.config.maxFee,'Fee cap below base fee plus tip');
            return {balance:N.quantity(balance),latest:N.quantity(latest),pending:N.quantity(pending),estimate:N.quantity(estimate),cap:N.quantity(heads[i].gasLimit)};
        }));
        N.check(views.every(v=>v.latest===views[0].latest&&v.pending===v.latest)&&views[0].latest<=BigInt(Number.MAX_SAFE_INTEGER),'Idle matching writer nonce required');
        const gas=(views.map(v=>v.estimate).reduce((a,b)=>a>b?a:b)*120n+99n)/100n;
        N.check(gas>0n&&gas<=MAX_GAS&&gas*this.config.maxFee<=this.config.budget&&views.every(v=>gas<=v.cap&&v.balance>=gas*this.config.maxFee),'Gas/balance/budget policy differs');
        await this.unchanged(block);return {type:2,chainId:11155111,nonce:Number(views[0].latest),to:this.destination.contract,data,value:0n,gasLimit:gas,maxFeePerGas:this.config.maxFee,maxPriorityFeePerGas:this.config.tip,accessList:[]};
    }
    async prepare(operation,payload,wallet){
        N.check(wallet?.address?.toLowerCase()===this.destination.writer&&typeof wallet.signTransaction==='function','Configured findings writer required');
        const unsigned=await this.preflight(payload);await this.authorize('SIGN');const raw=await wallet.signTransaction(unsigned);
        const p={policy:PLAN,operation,payload_sha256:N.sha(payload),destination:this.destination,network_config_sha256:this.config.sha256,transaction_id:Transaction.from(raw).hash,raw_transaction:raw};
        const t=this.validatePlan(p,operation,payload);N.check(t.unsignedSerialized===Transaction.from(unsigned).unsignedSerialized,'Signer changed prepared transaction');return p;
    }
    async submit(p,operation,payload){
        const t=this.validatePlan(p,operation,payload),unsigned=await this.preflight(payload);
        N.check(unsigned.nonce===t.nonce&&unsigned.gasLimit<=t.gasLimit,'Prepared nonce/gas no longer safe');
        await this.authorize('SUBMIT');
        // Exactly one transport invocation. No alternate provider or fee/nonce replacement.
        let hash;try{hash=await this.rpcs[0].call('eth_sendRawTransaction',[p.raw_transaction]);}catch{throw new Error('Uncertain original submission; reconcile retained transaction');}
        N.check(hash===p.transaction_id,'Submission hash differs; reconcile retained transaction');return {transaction_id:p.transaction_id};
    }
    async observe(p,operation,payload){
        const t=this.validatePlan(p,operation,payload);await this.authorize('OBSERVE');const heads=await N.network(this.rpcs);
        const receipts=await Promise.all(this.rpcs.map(r=>r.call('eth_getTransactionReceipt',[p.transaction_id])));
        if(receipts.some(r=>r===null))return {status:'PENDING',reason:'BOTH_ORIGINAL_RECEIPTS_REQUIRED',transaction_id:p.transaction_id};
        const fields=['transactionHash','blockHash','blockNumber','from','to','contractAddress','status','gasUsed','effectiveGasPrice','transactionIndex','logs'];
        N.check(N.canonical(fields.map(k=>receipts[0][k]))===N.canonical(fields.map(k=>receipts[1][k])),'Provider receipts disagree');
        const receipt=receipts[0],number=N.quantity(receipt.blockNumber),index=N.quantity(receipt.transactionIndex);
        N.hash(receipt.blockHash);
        N.check(receipt.transactionHash===p.transaction_id&&receipt.from?.toLowerCase()===this.destination.writer&&receipt.to?.toLowerCase()===this.destination.contract&&receipt.contractAddress===null&&N.quantity(receipt.status)===1n&&N.quantity(receipt.gasUsed)>0n&&N.quantity(receipt.gasUsed)<=t.gasLimit&&N.quantity(receipt.effectiveGasPrice)>0n&&N.quantity(receipt.effectiveGasPrice)<=t.maxFeePerGas&&Array.isArray(receipt.logs)&&receipt.logs.length===1,'Original publication receipt invalid');
        const log=receipt.logs[0];N.check(log.address?.toLowerCase()===this.destination.contract&&log.transactionHash===p.transaction_id&&log.blockHash===receipt.blockHash&&N.quantity(log.blockNumber)===number&&N.quantity(log.transactionIndex)===index&&log.removed===false,'Publication event inclusion differs');N.quantity(log.logIndex);
        const event=this.iface.parseLog(log),[id,metadata]=argumentsFor(payload),encoded=this.iface.encodeEventLog(this.iface.getEvent('Published'),[id,...metadata]);
        N.check(event?.name==='Published'&&N.canonical(Array.from(event.args))===N.canonical([id,...metadata])&&log.data===encoded.data&&N.canonical(log.topics)===N.canonical(encoded.topics),'Exact original publication event required');
        for(const r of this.rpcs){
            const [b,tx]=await Promise.all([r.call('eth_getBlockByNumber',[receipt.blockNumber,false]),r.call('eth_getTransactionByHash',[p.transaction_id])]);
            N.check(b&&b.hash===receipt.blockHash&&N.quantity(b.number)===number&&Array.isArray(b.transactions)&&index<BigInt(b.transactions.length)&&b.transactions[Number(index)]===p.transaction_id,'Original transaction inclusion differs');
            N.check(tx&&tx.hash===p.transaction_id&&tx.blockHash===receipt.blockHash&&N.quantity(tx.blockNumber)===number&&N.quantity(tx.transactionIndex)===index&&tx.from?.toLowerCase()===t.from.toLowerCase()&&tx.to?.toLowerCase()===this.destination.contract&&tx.input===t.data&&N.quantity(tx.nonce)===BigInt(t.nonce)&&N.quantity(tx.chainId)===t.chainId&&N.quantity(tx.type)===2n&&N.quantity(tx.value)===0n&&N.quantity(tx.gas)===t.gasLimit&&N.quantity(tx.maxFeePerGas)===t.maxFeePerGas&&N.quantity(tx.maxPriorityFeePerGas)===t.maxPriorityFeePerGas&&Array.isArray(tx.accessList)&&tx.accessList.length===0,'Original signed transaction readback differs');
            const base=N.quantity(b.baseFeePerGas),price=base+t.maxPriorityFeePerGas<t.maxFeePerGas?base+t.maxPriorityFeePerGas:t.maxFeePerGas;
            N.check(base<=t.maxFeePerGas&&N.quantity(receipt.effectiveGasPrice)===price,'Original execution fee differs');
        }
        const block=await N.finalized(this.rpcs);
        if(!block||block.height<number||heads.some(h=>N.quantity(h.number)<number+BigInt(this.config.confirmations)-1n))return {status:'PENDING',reason:'FINALITY_AND_CONFIRMATIONS_REQUIRED',transaction_id:p.transaction_id};
        N.check(heads.every(h=>block.height<=N.quantity(h.number)),'Finalized state exceeds latest head');
        await this.state(block);
        for(const r of this.rpcs){
            const raw=await r.call('eth_call',[{to:this.destination.contract,data:this.iface.encodeFunctionData('readPublication',[id])},block.tag]);
            const value=this.iface.decodeFunctionResult('readPublication',raw);
            N.check(N.canonical(Array.from(value[0]))===N.canonical(metadata)&&value[1]===number&&this.iface.encodeFunctionResult('readPublication',value)===raw,'Exact finalized publication readback differs');
        }
        await this.unchanged(block,receipt);await this.authorize('VERIFIED');
        return {status:'FINAL',destination:this.destination,payload,transaction_id:p.transaction_id,verification:{execution_status:1,finalized:true,independent_readback:true,block_sha256:receipt.blockHash.slice(2)}};
    }
}
module.exports={LivePublicFindingsAdapter,PLAN,MAX_GAS,destination,absent};

