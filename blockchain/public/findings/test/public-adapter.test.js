'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {Wallet,Transaction}=require('ethers'),{using,h}=require('./public-adapter-fixture'),{runProtectedLoaded:run,selection,approval}=require('../protected-public-runner');
const N=require('../network'),{artifact}=require('../artifact'),{PublicFindingsAdapter}=require('../public-adapter');
test('signed bytes retained before one submission and verified on both fixture providers',()=>using(async f=>{
    f.state.interrupt=phase=>{if(phase==='AFTER_PLAN'){assert.equal(f.state.broadcasts.length,0);assert.equal(f.read('plan').raw_transaction.slice(0,4),'0x02');}if(phase==='AFTER_ATTEMPT')assert.ok(f.read('attempt'));};
    const r=await run(f.options());assert.equal(r.status,'ISOLATED_PUBLIC_VERIFIED');assert.equal(r.both_chains_anchored,false);assert.equal(r.live_chain_verification,false);assert.equal(f.state.signs,1);assert.equal(f.state.broadcasts.length,1);
    const p=f.read('plan');assert.equal(Transaction.from(p.raw_transaction).hash,p.transaction_id);assert.equal(r.receipt.transaction_id,p.transaction_id);assert.deepEqual(f.state.broadcasts,[p.raw_transaction]);
    const encrypted=fs.readFileSync(path.join(f.directory,'plan.encrypted.json'),'utf8');assert.ok(!encrypted.includes(p.raw_transaction));assert.ok(!encrypted.includes(f.wallet.privateKey));
    for(const n of fs.readdirSync(f.directory))assert.equal(fs.statSync(path.join(f.directory,n)).mode&0o077,0);
}));
test('restarts and read-only reconciliation neither sign nor submit nor alter retained bytes',()=>using(async f=>{
    await run(f.options());const before=f.inventory();await run(f.options());assert.equal(f.state.signs,1);assert.equal(f.state.broadcasts.length,1);assert.deepEqual(f.inventory(),before);
    const o=f.options('RECONCILE');delete o.wallet;assert.equal((await run(o)).status,'ISOLATED_PUBLIC_VERIFIED');assert.deepEqual(f.inventory(),before);assert.equal(f.state.broadcasts.length,1);
}));
for(const phase of ['AFTER_INTENT','AFTER_PLAN','AFTER_ATTEMPT','AFTER_SUBMIT','AFTER_ACK','AFTER_FINAL'])test('interruption recovery at '+phase,()=>using(async f=>{
    f.state.interrupt=p=>{if(p===phase)throw new Error('fixture interruption');};await assert.rejects(run(f.options()),/fixture interruption/);f.state.interrupt=null;
    const previous=f.read('plan'),attempt=f.read('attempt');const result=await run(f.options());
    if(phase==='AFTER_ATTEMPT'){assert.equal(result.status,'PENDING');assert.equal(f.state.broadcasts.length,0);assert.equal(f.read('final'),null);}
    else{assert.equal(result.status,'ISOLATED_PUBLIC_VERIFIED');assert.equal(f.state.broadcasts.length,1);}
    if(previous)assert.deepEqual(f.read('plan'),previous);if(attempt)assert.deepEqual(f.read('attempt'),attempt);
}));
for(const after of [false,true])test('ambiguous transport '+(after?'after':'before')+' delivery never rebroadcasts',()=>using(async f=>{
    f.state[after?'throwAfter':'throwBefore']=true;await assert.rejects(run(f.options()),/Uncertain original submission/);
    const p=f.read('plan'),before=f.inventory();const r=await run(f.options('RECONCILE'));
    assert.equal(r.status,after?'ISOLATED_PUBLIC_VERIFIED':'PENDING');assert.equal(f.state.broadcasts.length,1);assert.equal(f.state.signs,1);assert.deepEqual(f.read('plan'),p);assert.deepEqual(f.inventory(),before);
}));
test('wrong acknowledgement hash stays uncertain with the original transaction',()=>using(async f=>{
    f.state.mutation=(m,p,v)=>m==='eth_sendRawTransaction'?h('wrong'):v;await assert.rejects(run(f.options()),/Submission hash differs/);
    f.state.mutation=null;assert.equal((await run(f.options('RECONCILE'))).status,'ISOLATED_PUBLIC_VERIFIED');assert.equal(f.state.broadcasts.length,1);
}));
for(const peers of [[false,false],[false,true],[true,false]])test('missing receipt remains pending '+peers,()=>using(async f=>{
    f.state.receipts=peers;const r=await run(f.options());assert.equal(r.status,'PENDING');assert.equal(f.read('final'),null);await run(f.options());assert.equal(f.state.broadcasts.length,1);
}));
for(const fault of ['missing','behind','confirmations'])test('finality prerequisite remains pending '+fault,()=>using(async f=>{
    f.state.interrupt=p=>{if(p==='AFTER_ACK'){if(fault==='missing')f.state.finalized[1]=false;if(fault==='behind')f.state.finalHeights=[95n,95n];if(fault==='confirmations')f.state.headHeights=[100n,100n];}};
    const r=await run(f.options());assert.equal(r.status,'PENDING');assert.equal(f.read('final'),null);assert.equal(f.state.broadcasts.length,1);
}));
test('provider head advancement and different finalized heights retain stable original receipt',()=>using(async f=>{
    const first=await run(f.options()),before=f.inventory();f.state.finalHeights=[120n,119n];f.state.headHeights=[122n,122n];f.state.calls=[];
    const later=await run(f.options('RECONCILE'));assert.deepEqual(later.receipt,first.receipt);assert.deepEqual(f.inventory(),before);
    const tags=f.state.calls.filter(x=>x.method==='eth_call'||x.method==='eth_getCode').map(x=>x.params[1]);assert.ok(tags.length>0);assert.ok(tags.every(t=>t==='0x77'));
}));
for(const fault of ['receipts','logs','status','gas','price','receipt-to','receipt-from','block-hash','tx-hash','tx-input','tx-chain','tx-nonce','tx-access','inclusion-index','runtime','writer','policy','namespace','metadata','recorded-block','removed-event','event-data','event-topics','final-block'])test('reject readback fault '+fault,()=>using(async f=>{
    await run(f.options());const before=f.inventory();f.state.mutation=(m,p,v,i)=>{
        if(m==='eth_getTransactionReceipt'&&v){const r=structuredClone(v);if(fault==='receipts'&&i===1)r.blockHash=h('other');if(fault==='logs')r.logs=[];if(fault==='status')r.status='0x0';if(fault==='gas')r.gasUsed=N.hex(900000n);if(fault==='price')r.effectiveGasPrice=N.hex(1n);if(fault==='receipt-to')r.to='0x'+'22'.repeat(20);if(fault==='receipt-from')r.from=r.to;if(fault==='block-hash')r.blockHash=h('wrong');if(fault==='tx-hash')r.transactionHash=h('wrong');if(fault==='removed-event')r.logs[0].removed=true;if(fault==='event-data')r.logs[0].data='0x';if(fault==='event-topics')r.logs[0].topics=[h('wrong')];return r;}
        if(m==='eth_getTransactionByHash'&&v){const t={...v};if(fault==='tx-input')t.input='0x';if(fault==='tx-chain')t.chainId='0x1';if(fault==='tx-nonce')t.nonce='0x1';if(fault==='tx-access')t.accessList=[{address:t.to,storageKeys:[]}];return t;}
        if(m==='eth_getBlockByNumber'&&p[0]==='0x60'&&fault==='inclusion-index')return {...v,transactions:[h('wrong')]};
        if(m==='eth_getBlockByNumber'&&p[0]==='0x70'&&fault==='final-block'&&i===1)return {...v,hash:h('fork')};
        if(m==='eth_getCode'&&fault==='runtime')return '0x00';
        if(m==='eth_call'){
            const method=f.iface.parseTransaction({data:p[0].data}).name;
            if(method==='writer'&&fault==='writer')return f.iface.encodeFunctionResult(method,['0x'+'22'.repeat(20)]);
            if(method==='POLICY'&&fault==='policy')return f.iface.encodeFunctionResult(method,['wrong']);
            if(method==='NAMESPACE'&&fault==='namespace')return f.iface.encodeFunctionResult(method,['wrong']);
            if(method==='readPublication'&&['metadata','recorded-block'].includes(fault)){const a=require('../payload').argumentsFor(f.selection.payload)[1];if(fault==='metadata')a[0]=h('wrong');return f.iface.encodeFunctionResult(method,[a,fault==='recorded-block'?95n:96n]);}
        }
        return v;
    };
    await assert.rejects(run(f.options('RECONCILE')));assert.deepEqual(f.inventory(),before);assert.equal(f.state.broadcasts.length,1);
}));
test('finality loss after saved completion is a hard stop',()=>using(async f=>{await run(f.options());f.state.receipts=[false,false];await assert.rejects(run(f.options('RECONCILE')),/no longer reconciles/);assert.equal(f.state.broadcasts.length,1);}));
test('reorg during repeated verification is detected',()=>using(async f=>{
    await run(f.options());let reads=0;f.state.mutation=(m,p,v,i)=>{if(m==='eth_getBlockByNumber'&&p[0]==='0x70'&&i===0&&++reads>1)return {...v,hash:h('changed')};return v;};await assert.rejects(run(f.options('RECONCILE')),/verification block changed/);
}));
for(const fault of ['chain','genesis','stale','future','nonce','pending','balance','gas','base-fee','budget'])test('preflight stops before signing '+fault,()=>using(async f=>{
    if(fault==='budget'){f.config.max_total_fee_eth='0.000001';f.selection.network_config_sha256=N.sha(f.config);}
    f.state.mutation=(m,p,v,i)=>{
        if(m==='eth_chainId'&&fault==='chain')return '0x1';if(m==='eth_getBlockByNumber'&&p[0]==='0x0'&&fault==='genesis')return {...v,hash:h('wrong')};
        if(m==='eth_getBlockByNumber'&&p[0]==='latest'&&['stale','future'].includes(fault))return {...v,timestamp:N.hex(Math.floor(Date.now()/1000)+(fault==='stale'?-200:100))};
        if(m==='eth_getTransactionCount'&&fault==='nonce'&&i===1)return '0x1';if(m==='eth_getTransactionCount'&&fault==='pending'&&p[1]==='pending')return '0x1';
        if(m==='eth_getBalance'&&fault==='balance')return '0x0';if(m==='eth_estimateGas'&&fault==='gas')return N.hex(500000n);
        if(m==='eth_getBlockByNumber'&&p[0]==='latest'&&fault==='base-fee')return {...v,baseFeePerGas:N.hex(2000000000n)};return v;
    };await assert.rejects(run(f.options()));assert.equal(f.state.signs,0);assert.equal(f.state.broadcasts.length,0);
}));
for(const fault of ['value','to','data','nonce','chain','gas','fee','tip','access','signer'])test('malicious signer cannot change '+fault,()=>using(async f=>{
    f.wallet.signTransaction=async t=>{const altered={...t};if(fault==='value')altered.value=1n;if(fault==='to')altered.to='0x'+'22'.repeat(20);if(fault==='data')altered.data='0x';if(fault==='nonce')altered.nonce=2;if(fault==='chain')altered.chainId=1;if(fault==='gas')altered.gasLimit=600000n;if(fault==='fee')altered.maxFeePerGas=3000000000n;if(fault==='tip')altered.maxPriorityFeePerGas=0n;if(fault==='access')altered.accessList=[{address:t.to,storageKeys:[]}];return fault==='signer'?Wallet.createRandom().signTransaction(altered):f.unsignedSign(altered);};
    await assert.rejects(run(f.options()));assert.equal(f.state.broadcasts.length,0);assert.equal(f.read('plan'),null);
}));
test('preexisting publication requires original lineage instead of a new transaction',()=>using(async f=>{f.state.preexisting=true;await assert.rejects(run(f.options()),/already exists/);assert.equal(f.state.signs,0);}));
test('read-only mode cannot create missing intent or plan',()=>using(async f=>{const before=f.inventory();await assert.rejects(run(f.options('RECONCILE')),/Original public intent/);assert.deepEqual(f.inventory(),before);assert.equal(f.state.signs,0);}));
for(const fault of ['signature','unknown-key','mode','expired','future','unbounded','selection'])test('approval rejects '+fault+' without side effects',()=>using(async f=>{
    const o=f.options();if(fault==='signature')o.approval.signature=Buffer.alloc(64).toString('base64');if(fault==='unknown-key')o.approval=f.grant('EXECUTE',{key_id:'other'});if(fault==='mode')o.approval=f.grant('RECONCILE');if(fault==='expired')o.approval=f.grant('EXECUTE',{issued_at:new Date(Date.now()-200000).toISOString(),expires_at:new Date(Date.now()-100000).toISOString()});if(fault==='future')o.approval=f.grant('EXECUTE',{issued_at:new Date(Date.now()+100000).toISOString(),expires_at:new Date(Date.now()+200000).toISOString()});if(fault==='unbounded')o.approval=f.grant('EXECUTE',{expires_at:new Date(Date.now()+1000000).toISOString()});if(fault==='selection')o.approval.body.selection.history_sha256='a'.repeat(64);
    await assert.rejects(run(o));assert.equal(f.state.signs,0);assert.equal(f.state.calls.length,0);assert.equal(f.inventory().length,0);
}));
test('full loaded verification can stop at every critical boundary',()=>using(async f=>{
    f.state.loaded=(action,s)=>{if(action==='SUBMIT')return {...s,history_sha256:'a'.repeat(64)};return s;};
    await assert.rejects(run(f.options()),/Full evidence/);assert.equal(f.state.broadcasts.length,0);assert.ok(f.read('attempt'));f.state.loaded=null;assert.equal((await run(f.options())).status,'PENDING');assert.equal(f.state.broadcasts.length,0);
}));
for(const fault of ['receipt','destination','transaction','root','status'])test('Fabric binding rejects '+fault,()=>using(async f=>{
    const s=structuredClone(f.selection);if(fault==='receipt')s.payload.fabric_receipt_sha256='a'.repeat(64);if(fault==='destination')s.payload.fabric_destination_sha256='a'.repeat(64);if(fault==='transaction')s.payload.fabric_transaction_id='a'.repeat(64);if(fault==='root')s.payload.merkle_root='a'.repeat(64);if(fault==='status')s.fabric_receipt.verification.validation_code='INVALID';assert.throws(()=>selection(s));
}));
test('fixture-only policy rejects live hosts and unbound transport descriptors',()=>using(async f=>{
    assert.throws(()=>N.configuration({...f.config,rpc_urls:['https://one.example.com/','https://two.example.com/']}),/Fixture-only/);
    for(const change of [{fixture_transport:false},{endpoint:'https://wrong.example.invalid/'}]){
        const o=f.options();o.rpcs=[{...f.rpcs[0],...change},f.rpcs[1]];await assert.rejects(run(o),/fixture transports/);assert.equal(f.state.broadcasts.length,0);
    }
}));
test('ciphertext tampering and wrong recovery key stop without resubmission',()=>using(async f=>{
    await run(f.options());const o=f.options('RECONCILE');o.key=crypto.randomBytes(32);await assert.rejects(run(o));
    const p=path.join(f.directory,'plan.encrypted.json'),e=JSON.parse(fs.readFileSync(p));e.tag=Buffer.alloc(16).toString('base64');fs.writeFileSync(p,N.canonical(e));await assert.rejects(run(f.options()));assert.equal(f.state.broadcasts.length,1);
}));
test('owner-only files, symlinks, hardlinks, unexpected artifacts and stale locks fail closed',()=>using(async f=>{
    await run(f.options());const p=path.join(f.directory,'plan.encrypted.json');fs.chmodSync(p,0o644);await assert.rejects(run(f.options()));fs.chmodSync(p,0o600);
    fs.linkSync(p,path.join(f.parent,'link'));await assert.rejects(run(f.options()));fs.unlinkSync(path.join(f.parent,'link'));
    const bytes=fs.readFileSync(p);fs.unlinkSync(p);fs.symlinkSync(path.join(f.parent,'target'),p);await assert.rejects(run(f.options()));fs.unlinkSync(p);fs.writeFileSync(p,bytes,{mode:0o600});
    fs.writeFileSync(path.join(f.directory,'unexpected'),'x');await assert.rejects(run(f.options()));fs.unlinkSync(path.join(f.directory,'unexpected'));
    fs.mkdirSync(path.join(f.directory,'.gateway-lock'),{mode:0o700});await assert.rejects(run(f.options()));assert.equal(f.state.broadcasts.length,1);
}));
test('writer-bound runtime differs for another writer; source template cannot be used as deployment pin',()=>using(async f=>{
    const a=artifact(Wallet.createRandom().address);assert.notEqual(a.runtime_sha256,f.a.runtime_sha256);assert.notEqual(f.a.runtime,f.a.runtimeTemplate);
    const bad={...f.destination,runtime_sha256:'a'.repeat(64)};assert.throws(()=>new PublicFindingsAdapter({rpcs:f.rpcs,config:f.config,destination:bad,authorize:async()=>{}}),/runtime pin/);
}));
test('writer-bound artifact matches actual deployed EVM runtime bytes',async()=>{
    const ganache=require('ganache'),{BrowserProvider,ContractFactory}=require('ethers');
    const rpc=ganache.provider({chain:{chainId:11155111,hardfork:'shanghai'},logging:{quiet:true}}),provider=new BrowserProvider(rpc);provider.pollingInterval=10;
    try{const writer=await provider.getSigner(),a=artifact(await writer.getAddress()),c=await new ContractFactory(a.abi,a.bytecode,writer).deploy(await writer.getAddress());await c.waitForDeployment();
        const runtime=await provider.getCode(await c.getAddress());assert.equal(runtime,a.runtime);assert.equal(crypto.createHash('sha256').update(Buffer.from(runtime.slice(2),'hex')).digest('hex'),a.runtime_sha256);
    }finally{provider.destroy();await rpc.disconnect();}
});
test('finalized state cannot exceed a provider latest head',()=>using(async f=>{
    f.state.finalHeights=[113n,113n];await assert.rejects(run(f.options()),/exceeds latest/);assert.equal(f.state.signs,0);
}));
test('approval expiring after an asynchronous loader guard stops before signing',()=>using(async f=>{
    const o=f.options();o.approval=f.grant('EXECUTE',{issued_at:new Date(Date.now()-1000).toISOString(),expires_at:new Date(Date.now()+20).toISOString()});
    f.state.loaded=async(action,s)=>{await new Promise(r=>setTimeout(r,40));return s;};await assert.rejects(run(o),/Fresh public approval/);assert.equal(f.state.signs,0);assert.equal(f.state.broadcasts.length,0);
}));
test('noncanonical RPC quantities and malformed read failures cannot imply absence',()=>using(async f=>{
    f.state.mutation=(m,p,v)=>m==='eth_chainId'?'0x0aa36a7':v;await assert.rejects(run(f.options()),/Canonical RPC/);assert.equal(f.state.signs,0);
    f.state.mutation=null;const original=f.rpcs[0].call;
    f.rpcs[0].call=async(m,p)=>{if(m==='eth_call'&&f.iface.parseTransaction({data:p[0].data}).name==='readPublication')throw new Error('provider unavailable');return original(m,p);};
    await assert.rejects(run(f.options()),/provider unavailable/);assert.equal(f.state.signs,0);
}));
test('private retention cannot overlap the repository',()=>using(async f=>{const o=f.options();o.directory=f.repo;await assert.rejects(run(o),/outside repository/);assert.equal(f.state.calls.length,0);}));
test('losing acknowledgement lineage or altering retained signed plan stops without submission',()=>using(async f=>{
    await run(f.options());const p=f.read('plan'),st=f.store(false);fs.unlinkSync(path.join(f.directory,'plan.encrypted.json'));
    try{await st.session(()=>st.save('plan',{...p,transaction_id:h('wrong')}));}finally{st.close();}
    await assert.rejects(run(f.options()),/Original signed public/);assert.equal(f.state.broadcasts.length,1);
}));
test('orphan acknowledgement after attempt deletion is rejected',()=>using(async f=>{
    await run(f.options());fs.unlinkSync(path.join(f.directory,'attempt.encrypted.json'));await assert.rejects(run(f.options()),/lineage missing/);assert.equal(f.state.broadcasts.length,1);
}));
for(const change of [{confirmations:1},{confirmations:129},{max_fee_gwei:'21'},{priority_fee_gwei:'3'},{max_total_fee_eth:'0.2'},{rpc_urls:['https://same.example.invalid/a','https://same.example.invalid/b']},{extra:'private'}])
    test('strict fixture configuration rejects '+JSON.stringify(change),()=>using(async f=>assert.throws(()=>N.configuration({...f.config,...change}))));
