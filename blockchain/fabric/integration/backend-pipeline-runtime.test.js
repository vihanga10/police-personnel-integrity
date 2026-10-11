'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {setup}=require('./backend-pipeline-runtime');
const {loadLocalRuntime}=require('../../public/findings/configured-public-runtime');
test('pipeline harness provisions real local HTTPS/EVM and pins the configured disk wallet',async t=>{
    const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'ppi-pipeline-runtime-'));fs.chmodSync(root,0o700);
    t.after(()=>fs.rmSync(root,{recursive:true,force:true}));const x=await setup(t,root);
    const key=path.join(root,'recovery.key');fs.writeFileSync(key,crypto.randomBytes(32),{mode:0o600});
    const r=loadLocalRuntime({file:x.file,sha256:crypto.createHash('sha256').update(fs.readFileSync(x.file)).digest('hex'),
        job:{repo:x.f.repo,selection:{network_config_sha256:x.c.network_config_sha256,destination:x.evm.destination},
            networkConfigFile:x.networkFile,recoveryKeyFile:key}});t.after(()=>r.close());
    assert.equal(await r.rpcs[0].call('eth_chainId',[]),'0xaa36a7');assert.equal(await r.rpcs[1].call('eth_chainId',[]),'0xaa36a7');
    assert.equal(r.wallet.address.toLowerCase(),x.evm.destination.writer);assert.equal(x.state.requests.length,2);
});
