'use strict';
// Fixture transport policy only. No HTTP client, CLI, environment or live RPC loading.
const {parseUnits,parseEther}=require('ethers');
const {canonical,sha}=require('../../fabric/findings-chaincode/lib/findings');
const GENESIS='0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9';
const POLICY='FINDINGS_PUBLIC_NETWORK_FIXTURE_V1';
const check=(v,m)=>{if(!v)throw new Error(m);};
function exact(v,fields){
    check(v&&Object.getPrototypeOf(v)===Object.prototype&&Reflect.ownKeys(v).length===fields.length&&fields.every(k=>Object.hasOwn(v,k)&&Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value')),'Exact plain schema required');
}
function configuration(c){
    exact(c,['policy','rpc_urls','max_fee_gwei','priority_fee_gwei','max_total_fee_eth','confirmations']);
    check(c.policy===POLICY&&Array.isArray(c.rpc_urls)&&c.rpc_urls.length===2,'Fixture network policy required');
    const urls=c.rpc_urls.map(s=>{
        check(typeof s==='string','Fixture endpoint required');const u=new URL(s);
        check(u.protocol==='https:'&&u.hostname.endsWith('.invalid')&&!u.username&&!u.password&&!u.hash&&!u.search,'Fixture-only HTTPS endpoint required');return u;
    });
    check(urls[0].hostname!==urls[1].hostname,'Two distinct fixture provider hosts required');
    check(Number.isSafeInteger(c.confirmations)&&c.confirmations>=12&&c.confirmations<=128,'Bounded confirmation policy required');
    for(const k of ['max_fee_gwei','priority_fee_gwei','max_total_fee_eth'])check(typeof c[k]==='string'&&/^\d+(\.\d{1,9})?$/.test(c[k]),'Bounded decimal fee required');
    const maxFee=parseUnits(c.max_fee_gwei,'gwei'),tip=parseUnits(c.priority_fee_gwei,'gwei'),budget=parseEther(c.max_total_fee_eth);
    check(maxFee>0n&&maxFee<=parseUnits('20','gwei')&&tip>0n&&tip<=maxFee&&budget>0n&&budget<=parseEther('0.1'),'Fee policy exceeds bounds');
    return {sha256:sha(c),maxFee,tip,budget,confirmations:c.confirmations,urls:[...c.rpc_urls]};
}
function quantity(v){check(typeof v==='string'&&/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(v),'Canonical RPC quantity required');return BigInt(v);}
function hex(v){check(BigInt(v)>=0n,'Nonnegative RPC quantity required');return '0x'+BigInt(v).toString(16);}
function hash(v){check(typeof v==='string'&&/^0x[0-9a-f]{64}$/.test(v),'RPC hash required');return v;}
async function network(rpcs,now=Date.now()){
    return Promise.all(rpcs.map(async r=>{
        const [id,genesis,head]=await Promise.all([r.call('eth_chainId',[]),r.call('eth_getBlockByNumber',['0x0',false]),r.call('eth_getBlockByNumber',['latest',false])]);
        check(quantity(id)===11155111n&&hash(genesis?.hash)===GENESIS&&quantity(genesis.number)===0n,'Sepolia fixture identity differs');
        check(head&&quantity(head.number)>0n&&quantity(head.timestamp)*1000n<=BigInt(now+30000)&&BigInt(now)-quantity(head.timestamp)*1000n<=120000n&&quantity(head.gasLimit)>0n,'Fresh provider head required');
        hash(head.hash);return head;
    }));
}
async function finalized(rpcs){
    const heads=await Promise.all(rpcs.map(r=>r.call('eth_getBlockByNumber',['finalized',false])));
    if(heads.some(h=>h===null))return null;
    for(const h of heads){quantity(h.number);hash(h.hash);}
    const height=heads.map(h=>quantity(h.number)).reduce((a,b)=>a<b?a:b),tag=hex(height);
    const blocks=await Promise.all(rpcs.map(r=>r.call('eth_getBlockByNumber',[tag,false])));
    check(blocks.every(b=>b&&quantity(b.number)===height&&hash(b.hash))&&blocks[0].hash===blocks[1].hash,'Common finalized block differs');
    for(let i=0;i<2;i++)if(quantity(heads[i].number)===height)check(heads[i].hash===blocks[i].hash,'Finalized head binding differs');
    return {height,tag,hash:blocks[0].hash};
}
module.exports={GENESIS,POLICY,check,exact,configuration,quantity,hex,hash,network,finalized,canonical,sha};
