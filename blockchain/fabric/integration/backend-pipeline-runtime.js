'use strict';
// Genuine local HTTPS/mTLS, a real EVM and disposable local wallet. Source
// callbacks, Sepolia genesis and public finality remain explicit fixtures.
const fs=require('node:fs'),path=require('node:path'),https=require('node:https'),crypto=require('node:crypto');
const N=require('../../public/findings/network'),{POLICY}=require('../../public/findings/configured-public-runtime');
const {fixture:tlsFixture}=require('../client/test/recovery-witness-tls-fixture');
const {httpsAuthority}=require('./recovery-witness-https-fixture');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
async function setup(t,root){
    const parent=path.join(root,'pipeline-local');fs.mkdirSync(parent,{mode:0o700});
    const f={parent,repo:'/work/pipeline'},evm=await require('../../public/findings/integration/local-evm').localEvm(),tls=tlsFixture(t);
    const authority=await httpsAuthority(f.parent,'public-https-witness',f.repo);
    const state={fault:null,requests:[],httpRequests:0};const servers=[];
    const providers=[];
    for(let i=0;i<2;i++){
        const server=https.createServer({...tls.serverOptions,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',requestCert:true,rejectUnauthorized:true},async(req,res)=>{
            state.httpRequests++;let body='';req.on('data',b=>body+=b);req.on('end',async()=>{
                try{
                    if(!req.socket.authorized||sha(req.socket.getPeerCertificate().raw)!==tls.certPin('client.pem')){res.writeHead(403);res.end();return;}
                    const m=JSON.parse(body);state.requests.push({provider:i,method:m.method});
                    if(state.fault==='timeout')return;
                    let response;
                    try{response={jsonrpc:'2.0',id:m.id,result:await evm.rpcs[i].call(m.method,m.params)};}
                    catch(e){response={jsonrpc:'2.0',id:m.id,error:{code:e.code??-32000,message:String(e.message).slice(0,2000),data:typeof e.data==='string'?e.data:null}};}
                    let text=N.canonical(response),status=200,headers={'content-type':'application/json'};
                    if(state.fault==='id'){response.id++;text=N.canonical(response);}
                    if(state.fault==='duplicate')text='{"jsonrpc":"2.0",'+text.slice(1);
                    if(state.fault==='json')text='{';
                    if(state.fault==='extra'){response.private='forbidden';text=N.canonical(response);}
                    if(state.fault==='redirect'){status=302;headers.location='https://public.example/rpc';}
                    if(state.fault==='encoding')headers['content-encoding']='gzip';
                    if(state.fault==='oversize')text='x'.repeat(1048577);
                    headers['content-length']=Buffer.byteLength(text);res.writeHead(status,headers);res.end(text);
                }catch{res.writeHead(500,{'content-length':0});res.end();}
            });
        });servers.push(server);await new Promise(r=>server.listen(0,'127.0.0.1',r));
        providers.push({endpoint:evm.config.rpc_urls[i],connect_url:'https://127.0.0.1:'+server.address().port+'/rpc',
            ca_file:path.join(tls.root,'ca.pem'),ca_sha256:sha(tls.read('ca.pem')),
            client_certificate_file:path.join(tls.root,'client.pem'),client_certificate_sha256:sha(tls.read('client.pem')),
            client_key_file:path.join(tls.root,'client.key'),client_key_sha256:sha(tls.read('client.key')),
            server_certificate_sha256:tls.certPin('server.pem')});
    }
    t.after(async()=>{for(const s of servers){s.closeAllConnections();await new Promise(r=>s.close(r));}await authority.close();await evm.close();});
    const write=(name,b)=>{const p=path.join(f.parent,name);fs.writeFileSync(p,b,{mode:0o600});return p;};
    const networkFile=write('network.json',N.canonical(evm.config));
    const c={policy:POLICY,network_config_sha256:N.sha(evm.config),writer:evm.destination.writer,
        wallet_file:write('wallet.key',Buffer.from(evm.wallet.privateKey.slice(2),'hex')),wallet_sha256:sha(Buffer.from(evm.wallet.privateKey.slice(2),'hex')),
        timeout_ms:2000,providers};const file=write('runtime.json',N.canonical(c));
    function change(fn){fn(c);fs.writeFileSync(file,N.canonical(c));}
    return {f,evm,tls,authority,state,servers,c,file,networkFile,change};
}
module.exports={setup};
