'use strict';
const {parseUnits,parseEther}=require('ethers');
const F=require('./deployment-files');
const GENESIS='0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9';
function configuration(c){if(F.stable(Object.keys(c).sort())!==F.stable(['confirmations','max_fee_gwei','max_total_fee_eth','policy','priority_fee_gwei','rpc_urls']))throw new Error('Network fields differ');if(c.policy!=='SEPOLIA_DEPLOYMENT_NETWORK_V1'||!Array.isArray(c.rpc_urls)||c.rpc_urls.length!==2||!Number.isSafeInteger(c.confirmations)||c.confirmations<12||c.confirmations>128)throw new Error('Network policy differs');
    const urls=c.rpc_urls.map(s=>{const u=new URL(s);if(u.protocol!=='https:'||u.username||u.password||u.hash)throw new Error('HTTPS RPC required');return u;});
    if(urls[0].hostname===urls[1].hostname)throw new Error('Two distinct RPC hosts required');
    for(const s of [c.max_fee_gwei,c.priority_fee_gwei,c.max_total_fee_eth])if(typeof s!=='string'||!/^\d+(\.\d{1,9})?$/.test(s))throw new Error('Fee limits differ');
    const maxFee=parseUnits(c.max_fee_gwei,'gwei'),tip=parseUnits(c.priority_fee_gwei,'gwei'),budget=parseEther(c.max_total_fee_eth);
    if(maxFee<=0n||maxFee>parseUnits('20','gwei')||tip<=0n||tip>maxFee||budget<=0n||budget>parseEther('0.1'))throw new Error('Test fee caps exceed policy');
    return {sha256:F.digest(c),maxFee,tip,budget,confirmations:c.confirmations,urls:c.rpc_urls};
}
const { endpoint, safeFailure } = require('./rpc-read-recovery');
function quantity(v){if(typeof v!=='string'||!/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(v))throw new Error('Malformed RPC quantity');return BigInt(v);}
function hex(v){return '0x'+BigInt(v).toString(16);}
function hash(v){if(typeof v!=='string'||!/^0x[0-9a-f]{64}$/.test(v))throw new Error('Malformed RPC hash');return v;}
async function network(rpcs,now=Date.now()){if(rpcs.length!==2)throw new Error('Two RPCs required');const result=await Promise.all(rpcs.map(async r=>{const [id,genesis,latest]=await Promise.all([r.call('eth_chainId',[]),r.call('eth_getBlockByNumber',['0x0',false]),r.call('eth_getBlockByNumber',['latest',false])]);if(quantity(id)!==11155111n||hash(genesis?.hash)!==GENESIS||quantity(genesis.number)!==0n)throw new Error('Sepolia identity differs');if(!latest||quantity(latest.timestamp)*1000n>BigInt(now+30000)||BigInt(now)-quantity(latest.timestamp)*1000n>120000n||quantity(latest.gasLimit)<1n)throw new Error('RPC head stale');hash(latest.hash);return latest;}));return result;}
module.exports={GENESIS,configuration,endpoint,quantity,hex,hash,network,safeFailure};
