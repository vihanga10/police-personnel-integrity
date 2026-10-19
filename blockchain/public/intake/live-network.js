'use strict';
// A separate production transport. Fixture-only network configuration stays unchanged.
const {configuration,GENESIS,quantity,hex,hash}=require('../sepolia-rpc');
const N=require('../promotions/network');
const POLICY='PERSONNEL_INTAKE_LIVE_SEPOLIA_NETWORK_V1';
const METHODS=new Set(['eth_chainId','eth_getBlockByNumber','eth_getCode','eth_call','eth_getBalance','eth_getTransactionCount','eth_estimateGas','eth_getTransactionReceipt','eth_getTransactionByHash','eth_sendRawTransaction']);
function settings(c){
  N.exact(c,['policy','rpc_urls','max_fee_gwei','priority_fee_gwei','max_total_fee_eth','confirmations']);
  N.check(c.policy===POLICY,'Explicit live intake network required');
  const parsed=configuration({...c,policy:'SEPOLIA_DEPLOYMENT_NETWORK_V1'});
  for(const address of c.rpc_urls){const u=new URL(address);N.check(!u.search&&!u.hash&&!u.username&&!u.password&&u.hostname!=='localhost'&&!/^(?:\d+\.){3}\d+$/.test(u.hostname)&&!u.hostname.includes(':')&&!/\.(?:invalid|test|localhost)$/.test(u.hostname),'Public HTTPS provider required');}
  return {...parsed,sha256:N.sha(c)};
}
function endpoint(url,{fetchImpl=globalThis.fetch,sleep=ms=>new Promise(r=>setTimeout(r,ms))}={}){
  N.check(process.env.NODE_TLS_REJECT_UNAUTHORIZED!=='0','TLS verification required');
  let sequence=0,tail=Promise.resolve(),next=0;
  function failure(code=null,data=null){const e=new Error('INTAKE_RPC_FAILURE');e.code=code;if(typeof data==='string'&&/^0x[0-9a-f]*$/i.test(data)&&data.length<=4096)e.data=data;return e;}
  async function request(method,params){
    N.check(METHODS.has(method)&&Array.isArray(params),'Allowed intake RPC method required');
    const input=JSON.stringify({jsonrpc:'2.0',id:++sequence,method,params:structuredClone(params)});N.check(input.length<=1000000,'RPC request bound');
    const read=method!=='eth_sendRawTransaction';
    for(let attempt=1;attempt<=3;attempt++){
      try{
        // Weight and serialization bound free-provider traffic. A broadcast never retries.
        await sleep(Math.max(0,next-Date.now()));next=Date.now()+500;
        const r=await fetchImpl(url,{method:'POST',redirect:'error',headers:{'content-type':'application/json','accept':'application/json'},body:input,signal:AbortSignal.timeout(10000)});
        if(!r.ok){const e=failure();e.transient=[408,429,500,502,503,504].includes(r.status);throw e;}
        N.check(/^application\/json(?:;|$)/i.test(r.headers.get('content-type')||''),'JSON response required');
        let text='';const decoder=new TextDecoder();
        for await(const chunk of r.body){N.check(text.length+chunk.byteLength<=1000000,'RPC response bound');text+=decoder.decode(chunk,{stream:true});}text+=decoder.decode();
        const v=JSON.parse(text);N.check(v&&v.jsonrpc==='2.0'&&v.id===sequence&&Object.hasOwn(v,'result')!==Object.hasOwn(v,'error'),'Matched RPC response required');
        // Reject duplicate keys without requiring providers to use our JSON key order.
        const {parseUnique}=require('../promotions/live-json');const strict=parseUnique(text);N.check(N.canonical(strict)===N.canonical(v),'Unique RPC JSON required');
        if(v.error){const e=failure(v.error.code,v.error.data);e.transient=(v.error.code===429||v.error.code===-32007)&&/per.second|\/second|request limit|rate limit/i.test(v.error.message||'');throw e;}
        return v.result;
      }catch(e){if(!read||attempt===3||e.code===3||(!e.transient&&e.name!=='AbortError'&&e.name!=='TimeoutError'&&!(e instanceof TypeError)))throw failure(e.code,e.data);await sleep(attempt===1?1000:2000);}
    }
  }
  return Object.freeze({endpoint:url,call(method,params){const operation=tail.then(()=>request(method,params));tail=operation.catch(()=>{});return operation;}});
}
module.exports={POLICY,settings,endpoint,GENESIS,quantity,hex,hash,network:N.network,finalized:N.finalized};
