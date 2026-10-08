'use strict';
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process');
const F=require('./deployment-files'),W=require('./sepolia-wallet'),R=require('./sepolia-rpc'),{artifact}=require('./deployment-artifact'),{run}=require('./deployment-engine');
function args(argv){const values={},flags=new Set();for(let i=0;i<argv.length;i++){const k=argv[i];if(['--initialize-wallet','--execute','--reconcile'].includes(k)){if(flags.has(k))throw new Error('Duplicate option');flags.add(k);}else if(['--wallet-root','--backup-wallet-root'].includes(k)){if(values[k]||!argv[i+1]||argv[i+1].startsWith('--'))throw new Error('Invalid option');values[k]=argv[++i];}else throw new Error('Unknown option');}if(!values['--wallet-root']||!values['--backup-wallet-root']||flags.size>1)throw new Error('Use wallet and backup roots with at most one mode flag');return {root:values['--wallet-root'],backup:values['--backup-wallet-root'],initialize:flags.has('--initialize-wallet'),mode:flags.has('--execute')?'EXECUTE':flags.has('--reconcile')?'RECONCILE':'VALIDATE'};}
function revision(){const repo=path.resolve(__dirname,'../..');const git=(...v)=>cp.execFileSync('git',['-C',repo,...v],{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();if(git('status','--porcelain')||git('branch','--show-current')!=='feat/identity-resolution')throw new Error('Committed clean feature branch required');git('merge-base','--is-ancestor','f257a75','HEAD');return git('rev-parse','HEAD');}
async function main(argv){const opt=args(argv),codeRevision=revision();
    if(opt.initialize){const result=await W.initialize(opt.root,opt.backup);console.log('Dedicated Sepolia wallet setup and encrypted backup recovery: PASSED');console.log(JSON.stringify({...result,code_revision:codeRevision}));console.log('Owner-only encrypted keystores and random unlock files created outside Git. No RPC connection, funding, database or blockchain changes. Edit private network.json and obtain faucet test ETH next.');return;}
    console.log('Sepolia phase: wallet_backup_recovery');
    const wallet=await W.load(opt.root,opt.backup);
    console.log('Sepolia phase: private_network_configuration');
    const config=R.configuration(F.read(path.join(path.resolve(opt.root),'network.json')));
    console.log('Sepolia phase: pinned_compilation');
    const a=artifact(wallet.address),rpcs=config.urls.map(R.endpoint),directory=path.join(path.resolve(opt.root),'deployment');
    console.log('Sepolia phase: guarded_'+opt.mode.toLowerCase());
    // Fixed primary wallet path owns exactly one deployment journal. Backup cannot become a second publisher.
    const result=await F.locked(directory,()=>run({mode:opt.mode,wallet,rpcs,config,artifact:a,directory}));
    console.log('Sepolia contract deployment '+opt.mode+': '+result.status);console.log(JSON.stringify({...result,code_revision:codeRevision}));
    console.log(result.status==='PENDING'?'Original transaction preserved. Wait for finality, then rerun --reconcile; use --execute only to rebroadcast the same original if needed.':'No research commitments submitted. Research anchoring and audit execution remain pending.');
}
if(require.main===module)main(process.argv.slice(2)).catch(()=>{console.error('Sepolia setup/deployment stopped. Private keys, original transaction journal and any deployed contract remain preserved. Check network configuration, test balance and nonce; do not reset or delete.');process.exitCode=1;});
module.exports={main,args,revision};
