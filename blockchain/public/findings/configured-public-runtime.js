'use strict';
// Explicit local-runtime provisioning only. No public DNS, environment wallet,
// remote URL, automatic retries or provider fallback. Two local views are NOT
// evidence of independent providers or public consensus finality.
const fs=require('node:fs'),path=require('node:path'),https=require('node:https'),tls=require('node:tls'),crypto=require('node:crypto');
const {Wallet}=require('ethers'),N=require('./network');
const {privateFile}=require('../../fabric/client/findings-gateway');
const POLICY='FINDINGS_CONFIGURED_LOCAL_HTTPS_RUNTIME_V1',LIMIT=1048576;
const METHODS=new Set(['eth_chainId','eth_getBlockByNumber','eth_getCode','eth_call',
    'eth_getBalance','eth_getTransactionCount','eth_estimateGas','eth_sendRawTransaction',
    'eth_getTransactionReceipt','eth_getTransactionByHash']);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function read(file,repo){
    const b=privateFile(file,repo),s=fs.statSync(file);
    N.check(s.nlink===1&&b.length<=LIMIT,'Unlinked bounded private runtime file required');return b;
}
function config(file,pin,repo){
    N.check(typeof pin==='string'&&/^[0-9a-f]{64}$/.test(pin),'Approved runtime SHA-256 required');
    const b=read(file,repo);N.check(sha(b)===pin,'Approved runtime configuration differs');
    const c=JSON.parse(b);N.check(N.canonical(c)===b.toString(),'Canonical runtime configuration required');
    N.exact(c,['policy','network_config_sha256','writer','wallet_file','wallet_sha256','timeout_ms','providers']);
    N.check(c.policy===POLICY&&Number.isSafeInteger(c.timeout_ms)&&c.timeout_ms>=100&&c.timeout_ms<=10000,
        'Bounded configured local runtime required');
    N.check(/^[0-9a-f]{64}$/.test(c.network_config_sha256)&&/^[0-9a-f]{64}$/.test(c.wallet_sha256)&&
        /^0x[0-9a-f]{40}$/.test(c.writer),'Runtime network/wallet pins required');
    N.check(Array.isArray(c.providers)&&c.providers.length===2,'Two configured local views required');
    for(const p of c.providers){
        N.exact(p,['endpoint','connect_url','ca_file','ca_sha256','client_certificate_file',
            'client_certificate_sha256','client_key_file','client_key_sha256','server_certificate_sha256']);
        const u=new URL(p.connect_url);
        N.check(u.protocol==='https:'&&u.hostname==='127.0.0.1'&&u.port&&u.pathname==='/rpc'&&
            !u.username&&!u.password&&!u.search&&!u.hash&&u.href===p.connect_url,'Loopback-only exact HTTPS RPC required');
        for(const k of ['ca_sha256','client_certificate_sha256','client_key_sha256','server_certificate_sha256'])
            N.check(typeof p[k]==='string'&&/^[0-9a-f]{64}$/.test(p[k]),'Runtime certificate pin required');
    }
    N.check(c.providers[0].connect_url!==c.providers[1].connect_url,'Distinct local HTTPS listeners required');return c;
}
function loadLocalRuntime({file,sha256,job}){
    const c=config(file,sha256,job.repo),s=job.selection;
    N.check(c.network_config_sha256===s.network_config_sha256&&c.writer===s.destination.writer,'Runtime selection differs');
    const networkBytes=read(job.networkConfigFile,job.repo),network=JSON.parse(networkBytes);
    N.check(N.canonical(network)===networkBytes.toString()&&N.configuration(network).sha256===c.network_config_sha256,
        'Runtime network configuration differs');
    N.check(c.providers.every((p,i)=>p.endpoint===network.rpc_urls[i]),'Runtime provider order/binding differs');
    const pins=new Map([[file,sha256],[job.networkConfigFile,sha(networkBytes)]]);
    function pinned(file,pin){const b=read(file,job.repo);N.check(sha(b)===pin,'Pinned runtime credential differs');pins.set(file,pin);return b;}
    const secret=pinned(c.wallet_file,c.wallet_sha256);
    N.check(secret.length===32&&!secret.equals(read(job.recoveryKeyFile,job.repo)),'Separate raw local wallet/recovery key required');
    let wallet;
    try{wallet=new Wallet('0x'+secret.toString('hex'));}finally{secret.fill(0);}
    N.check(wallet.address.toLowerCase()===c.writer,'Configured wallet writer differs');
    const certificates=[];
    const materials=c.providers.map(p=>{
        const ca=pinned(p.ca_file,p.ca_sha256),cert=pinned(p.client_certificate_file,p.client_certificate_sha256),key=pinned(p.client_key_file,p.client_key_sha256);
        const certificate=new crypto.X509Certificate(cert);
        N.check(certificate.checkPrivateKey(crypto.createPrivateKey(key)),'RPC client key/certificate differ');certificates.push(certificate);
        return {ca,cert,key};
    });
    let closed=false,sequence=0;const active=new Set();
    function check(){
        N.check(!closed,'Local runtime closed');for(const [file,pin] of pins)N.check(sha(read(file,job.repo))===pin,'Pinned runtime files changed');
        for(const x of certificates)N.check(Date.parse(x.validFrom)<=Date.now()&&Date.now()<Date.parse(x.validTo),'RPC client certificate not current');
    }
    check();
    function call(i,method,params){
        check();N.check(METHODS.has(method)&&Array.isArray(params),'Allowed findings RPC method required');
        N.check(i===0||method!=='eth_sendRawTransaction','Second local view cannot broadcast');
        const id=++sequence,body=Buffer.from(N.canonical({jsonrpc:'2.0',id,method,params}));
        N.check(body.length<=LIMIT,'RPC request bound');const p=c.providers[i];
        return new Promise((resolve,reject)=>{
            let request,timer,done=false;
            const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);if(request){active.delete(request);request.destroy();}
                if(error)reject(error);else{try{check();resolve(value);}catch(e){reject(e);}}};
            try{
                request=https.request(p.connect_url,{...materials[i],method:'POST',agent:false,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true,
                    checkServerIdentity:(host,cert)=>{const error=tls.checkServerIdentity(host,cert);if(error)return error;
                        if(!cert.raw||sha(cert.raw)!==p.server_certificate_sha256)return new Error('Pinned RPC server differs');},
                    headers:{'content-type':'application/json','content-length':body.length,'accept':'application/json','accept-encoding':'identity'}},response=>{
                    try{N.check(response.statusCode===200&&/^application\/json(?:;|$)/i.test(response.headers['content-type']||'')&&
                        (!response.headers['content-encoding']||response.headers['content-encoding']==='identity'),'Exact JSON RPC response required');
                        const length=response.headers['content-length'];N.check(typeof length==='string'&&/^(0|[1-9][0-9]*)$/.test(length)&&Number(length)<=LIMIT,'Bounded RPC response length required');
                        const chunks=[];let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>LIMIT)finish(new Error('RPC response bound'));else chunks.push(chunk);});
                        response.on('aborted',()=>finish(new Error('RPC response interrupted')));response.on('error',e=>finish(e));
                        response.on('end',()=>{if(done)return;try{
                            N.check(size===Number(length),'RPC response length differs');const text=Buffer.concat(chunks).toString('utf8'),v=JSON.parse(text);
                            // Canonical encoding also rejects duplicate JSON keys and trailing data.
                            N.check(N.canonical(v)===text&&v.jsonrpc==='2.0'&&v.id===id,'Canonical matched RPC response required');
                            if(Object.hasOwn(v,'error')){N.exact(v,['jsonrpc','id','error']);N.exact(v.error,['code','message','data']);
                                N.check(Number.isSafeInteger(v.error.code)&&typeof v.error.message==='string'&&v.error.message.length<=2000&&
                                    (v.error.data===null||typeof v.error.data==='string'),'Bounded RPC error required');
                                const e=new Error('Configured local RPC error');e.code=v.error.code;e.data=v.error.data;finish(e);
                            }else{N.exact(v,['jsonrpc','id','result']);finish(null,v.result);}
                        }catch(e){finish(e);}});
                    }catch(e){response.destroy();finish(e);}
                });
                active.add(request);request.once('error',e=>finish(e));
                timer=setTimeout(()=>finish(new Error('RPC absolute deadline; no automatic retry')),c.timeout_ms);request.end(body);
            }catch(e){finish(e);}
        });
    }
    return Object.freeze({fixture_transport:true,runtime_policy:POLICY,
        rpcs:c.providers.map((p,i)=>Object.freeze({fixture_transport:true,endpoint:p.endpoint,call:(m,a)=>call(i,m,a)})),
        wallet:Object.freeze({address:wallet.address,async signTransaction(t){check();const result=await wallet.signTransaction(t);check();return result;}}),
        close(){closed=true;for(const r of active)r.destroy(new Error('Local runtime closed'));for(const m of materials)m.key.fill(0);wallet=null;}});
}
module.exports={POLICY,config,loadLocalRuntime};
