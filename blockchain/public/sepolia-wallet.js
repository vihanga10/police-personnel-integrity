'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {Wallet,encryptKeystoreJson}=require('ethers');
const F=require('./deployment-files');
const POLICY='SEPOLIA_DEPLOYMENT_WALLET_V1';
function outsideGit(dir){dir=F.safePath(dir);for(let p=dir;;p=path.dirname(p)){if(fs.existsSync(path.join(p,'.git')))throw new Error('Wallet must remain outside Git');if(path.dirname(p)===p)break;}return dir;}
async function initialize(root,backup){root=outsideGit(root);backup=outsideGit(backup);if(root===backup||root.startsWith(backup+path.sep)||backup.startsWith(root+path.sep))throw new Error('Separate key roots required');for(const dir of [root,backup]){if(fs.existsSync(dir))throw new Error('Wallet root already exists; preserve it');}
    F.privateDir(root,true);F.privateDir(backup,true);
    const w=Wallet.createRandom(),password=crypto.randomBytes(32).toString('base64');
    const encrypted=JSON.parse(await encryptKeystoreJson({address:w.address,privateKey:w.privateKey},password,{scrypt:{N:16384,r:8,p:1}}));
    const meta={policy:POLICY,chain_id:11155111,address:w.address,primary_root:root,backup_root:backup,keystore_sha256:F.digest(encrypted)};
    // Passwords are random files, not operator-entered secrets. Keep both roots private.
    for(const dir of [root,backup]){F.write(path.join(dir,'wallet.json'),encrypted);F.write(path.join(dir,'unlock.json'),{password});F.write(path.join(dir,'wallet-info.json'),meta);}
    F.write(path.join(root,'network.json'),{policy:'SEPOLIA_DEPLOYMENT_NETWORK_V1',rpc_urls:['REPLACE_PRIMARY_HTTPS_RPC_URL','REPLACE_SECOND_HTTPS_RPC_URL'],max_fee_gwei:'5',priority_fee_gwei:'1',max_total_fee_eth:'0.025',confirmations:12});
    const restored=await load(root,backup);if(restored.address!==w.address)throw new Error('Wallet recovery differs');return {status:'PASSED',chain_id:11155111,address:w.address};
}
async function load(root,backup){root=outsideGit(root);backup=outsideGit(backup);F.privateDir(root);F.privateDir(backup);const a=F.read(path.join(root,'wallet-info.json')),b=F.read(path.join(backup,'wallet-info.json'));if(F.stable(a)!==F.stable(b)||a.policy!==POLICY||a.chain_id!==11155111||a.primary_root!==root||a.backup_root!==backup)throw new Error('Wallet copies differ');const keyA=F.read(path.join(root,'wallet.json')),keyB=F.read(path.join(backup,'wallet.json')),passA=F.read(path.join(root,'unlock.json')),passB=F.read(path.join(backup,'unlock.json'));if(F.digest(keyA)!==a.keystore_sha256||F.stable(keyA)!==F.stable(keyB)||F.stable(passA)!==F.stable(passB)||!/^[A-Za-z0-9+/]{43}=$/.test(passA.password))throw new Error('Wallet backup differs');const wallet=await Wallet.fromEncryptedJson(JSON.stringify(keyA),passA.password),copy=await Wallet.fromEncryptedJson(JSON.stringify(keyB),passB.password);if(wallet.address!==a.address||copy.privateKey!==wallet.privateKey)throw new Error('Recovered wallet differs');return wallet;}
module.exports={initialize,load,outsideGit};
