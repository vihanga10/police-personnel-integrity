'use strict';
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {Wallet,Transaction,Interface,AbiCoder}=require('ethers');
const {artifact}=require('../artifact'),N=require('../network'),P=require('../protected-public-runner');
const {createRetention,POLICY:RETENTION}=require('../../../fabric/client/findings-retention');
const vector=require('./public-vector.json');
const h=x=>'0x'+crypto.createHash('sha256').update(String(x)).digest('hex');
function fixture(){
    const parent=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'findings-public-fixture-'));fs.chmodSync(parent,0o700);
    const directory=path.join(parent,'retention'),repo=path.join(parent,'repo');for(const d of [directory,repo])fs.mkdirSync(d,{mode:0o700});
    const wallet=Wallet.createRandom(),a=artifact(wallet.address),iface=new Interface(a.abi),key=crypto.randomBytes(32),approver=crypto.generateKeyPairSync('ed25519');
    const config={policy:N.POLICY,rpc_urls:['https://one.example.invalid/','https://two.example.invalid/'],max_fee_gwei:'2',priority_fee_gwei:'1',max_total_fee_eth:'0.005',confirmations:12};
    const destination={chain_id:11155111,contract:'0x'+'11'.repeat(20),runtime_sha256:a.runtime_sha256,writer:wallet.address.toLowerCase(),namespace:'findings-anchor-v1',finality:'FINALIZED'};
    const selection={private_sha256:h('private').slice(2),public_sha256:vector.payload.public_sha256,history_sha256:h('history').slice(2),code_revision:'1'.repeat(40),network_config_sha256:N.sha(config),destination,payload:structuredClone(vector.payload),fabric_receipt:structuredClone(vector.fabric_receipt)};
    const state={raw:null,broadcasts:[],signs:0,calls:[],receipts:[true,true],finalized:[true,true],finalHeights:[112n,112n],headHeights:[112n,112n],mutation:null,preexisting:false,throwBefore:false,throwAfter:false,loaded:null,interrupt:null};
    const unsignedSign=wallet.signTransaction.bind(wallet);wallet.signTransaction=async t=>{state.signs++;return unsignedSign(t);};
    function block(n){return {number:N.hex(n),hash:n===96n?h('original-block'):h('block-'+n),timestamp:N.hex(Math.floor(Date.now()/1000)),gasLimit:N.hex(30000000n),baseFeePerGas:N.hex(1000000000n),transactions:state.raw&&n===96n?[Transaction.from(state.raw).hash]:[]};}
    function transport(i){return {fixture_transport:true,endpoint:config.rpc_urls[i],async call(method,params){
        state.calls.push({method,params:structuredClone(params),provider:i});let v;const tx=state.raw?Transaction.from(state.raw):null;
        switch(method){
        case 'eth_chainId':v=N.hex(11155111);break;
        case 'eth_getBlockByNumber':v=params[0]==='0x0'?{number:'0x0',hash:N.GENESIS}:params[0]==='latest'?block(state.headHeights[i]):params[0]==='finalized'?(state.finalized[i]?block(state.finalHeights[i]):null):block(N.quantity(params[0]));break;
        case 'eth_getCode':v=a.runtime;break;
        case 'eth_getBalance':v=N.hex(10n**18n);break;
        case 'eth_getTransactionCount':v=tx?'0x1':'0x0';break;
        case 'eth_estimateGas':v=N.hex(150000n);break;
        case 'eth_call':{
            const parsed=iface.parseTransaction({data:params[0].data});
            if(parsed.name==='readPublication'){
                if(!state.raw&&!state.preexisting){const e=new Error('fixture absent');e.code=3;e.data='0x08c379a0'+AbiCoder.defaultAbiCoder().encode(['string'],['publication absent']).slice(2);throw e;}
                v=iface.encodeFunctionResult('readPublication',[require('../payload').argumentsFor(selection.payload)[1],state.preexisting?80n:96n]);
            }else{const values={writer:destination.writer,CHAIN_ID:11155111n,POLICY:'FINDINGS_PUBLIC_ANCHOR_V1',NAMESPACE:'findings-anchor-v1'};v=iface.encodeFunctionResult(parsed.name,[values[parsed.name]]);}break;
        }
        case 'eth_sendRawTransaction':
            state.broadcasts.push(params[0]);if(state.throwBefore)throw new Error('fixture transport failed before delivery');
            state.raw=params[0];if(state.throwAfter)throw new Error('fixture acknowledgement lost after delivery');v=Transaction.from(params[0]).hash;break;
        case 'eth_getTransactionReceipt':{
            if(!tx||!state.receipts[i]){v=null;break;}
            const encoded=iface.encodeEventLog(iface.getEvent('Published'),require('../payload').argumentsFor(selection.payload).flat());
            const log={address:destination.contract,...encoded,blockHash:h('original-block'),blockNumber:'0x60',transactionHash:tx.hash,transactionIndex:'0x0',logIndex:'0x0',removed:false};
            v={transactionHash:tx.hash,blockHash:h('original-block'),blockNumber:'0x60',from:destination.writer,to:destination.contract,contractAddress:null,status:'0x1',gasUsed:N.hex(150000n),effectiveGasPrice:N.hex(2000000000n),transactionIndex:'0x0',logs:[log]};break;
        }
        case 'eth_getTransactionByHash':v=tx?{hash:tx.hash,blockHash:h('original-block'),blockNumber:'0x60',transactionIndex:'0x0',from:destination.writer,to:destination.contract,input:tx.data,nonce:N.hex(tx.nonce),chainId:N.hex(tx.chainId),type:N.hex(tx.type),value:N.hex(tx.value),gas:N.hex(tx.gasLimit),maxFeePerGas:N.hex(tx.maxFeePerGas),maxPriorityFeePerGas:N.hex(tx.maxPriorityFeePerGas),accessList:[]}:null;break;
        default:throw new Error('Unexpected fixture RPC '+method);
        }
        return state.mutation?state.mutation(method,params,v,i):v;
    }};}
    const rpcs=[transport(0),transport(1)],trustedKeys={reviewer:approver.publicKey.export({format:'pem',type:'spki'})};
    function grant(mode='EXECUTE',changes={}){
        const now=Date.now();
        const body={policy:P.POLICY,key_id:'reviewer',mode,issued_at:new Date(now-1000).toISOString(),expires_at:new Date(now+599000).toISOString(),selection:structuredClone(selection),...changes};
        return {body,signature:crypto.sign(null,Buffer.from(N.canonical(body)),approver.privateKey).toString('base64')};
    }
    function options(mode='EXECUTE'){return {verifiedSelection:selection,approval:grant(mode),trustedKeys,config,rpcs,wallet,directory,repo,key,mode,
        checkLoaded:async(action,s,m)=>state.loaded?state.loaded(action,s,m):s,interrupt:async phase=>{if(state.interrupt)await state.interrupt(phase);}};}
    function store(readOnly=true){const operation=N.sha({policy:P.POLICY,selection});return createRetention({directory,repo,key,binding:{policy:RETENTION,operation,selection_sha256:N.sha(selection)},readOnly});}
    function read(stage){
        const file=path.join(directory,stage+'.encrypted.json');if(!fs.existsSync(file))return null;
        const e=JSON.parse(fs.readFileSync(file)),operation=N.sha({policy:P.POLICY,selection});
        const cipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(e.nonce,'base64'));
        cipher.setAAD(Buffer.from(N.canonical({binding:{policy:RETENTION,operation,selection_sha256:N.sha(selection)},stage})));
        cipher.setAuthTag(Buffer.from(e.tag,'base64'));return JSON.parse(Buffer.concat([cipher.update(Buffer.from(e.ciphertext,'base64')),cipher.final()]).toString());
    }
    function inventory(){return fs.readdirSync(directory).sort().map(n=>[n,fs.readFileSync(path.join(directory,n)).toString('hex')]);}
    function close(){fs.rmSync(parent,{recursive:true,force:true});}
    return {wallet,unsignedSign,a,iface,selection,config,destination,state,rpcs,key,repo,directory,parent,grant,options,store,read,inventory,close,trustedKeys};
}
async function using(fn){const f=fixture();try{await fn(f);}finally{f.close();}}
module.exports={fixture,using,h};
