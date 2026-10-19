'use strict';
// Separate journal and contract; original network configuration/journals are never edited.
const fs=require('node:fs'),path=require('node:path'),{getAddress}=require('ethers');
const F=require('../deployment-files'),W=require('../sepolia-wallet'),N=require('../promotions/network'),L=require('./live-network');
const {privateFile}=require('../../fabric/client/intake-gateway'),{parseUnique}=require('../promotions/live-json');
const {artifact}=require('./artifact'),{run}=require('./live-deployment-engine');
function args(values){const out={mode:'VALIDATE'};let mode=false;for(let i=0;i<values.length;i++){const k=values[i];if(['--execute','--reconcile','--preview'].includes(k)){N.check(!mode,'One mode required');mode=true;out.mode=k==='--execute'?'EXECUTE':k==='--reconcile'?'RECONCILE':'VALIDATE';}else{N.check(['--network-file','--network-sha256','--wallet-root','--backup-wallet-root','--journal-root'].includes(k)&&!out[k]&&values[i+1]&&!values[i+1].startsWith('--'),'Exact deployment options required');out[k]=values[++i];}}for(const k of ['--network-file','--network-sha256','--wallet-root','--backup-wallet-root','--journal-root'])N.check(out[k],'Deployment path/pin missing');return out;}
async function main(argv){
  const opt=args(argv),repo=path.resolve(__dirname,'../../..');
  const raw=privateFile(opt['--network-file'],repo);N.check(raw.length<=1048576&&fs.statSync(opt['--network-file']).nlink===1&&require('./artifact').byteSha(raw)===opt['--network-sha256'],'Pinned private live configuration required');
  const config=L.settings(parseUnique(raw.toString('utf8'))),wallet=await W.load(opt['--wallet-root'],opt['--backup-wallet-root']);
  const journal=path.resolve(opt['--journal-root']);N.check(path.isAbsolute(opt['--journal-root'])&&!journal.startsWith(repo+path.sep)&&![path.resolve(opt['--wallet-root']),path.resolve(opt['--backup-wallet-root'])].some(r=>journal===r||journal.startsWith(r+path.sep)),'Dedicated journal outside repository/wallet roots required');
  const a=artifact(wallet.address),compiled={...a,writer:getAddress(a.writer),creation_sha256:F.digest(a.bytecode),settings_sha256:F.digest(a.settings)};
  const rpcs=config.urls.map(url=>L.endpoint(url));
  const pinned=rpcs.map(r=>({call:async(method,params)=>{N.check(require('./artifact').byteSha(privateFile(opt['--network-file'],repo))===opt['--network-sha256'],'Live configuration changed');const value=await r.call(method,params);N.check(require('./artifact').byteSha(privateFile(opt['--network-file'],repo))===opt['--network-sha256'],'Live configuration changed');return value;}}));
  const result=opt.mode==='VALIDATE'&&!fs.existsSync(journal)?await run({mode:opt.mode,wallet,rpcs:pinned,config,artifact:compiled,directory:journal}):await F.locked(journal,()=>run({mode:opt.mode,wallet,rpcs:pinned,config,artifact:compiled,directory:journal}));
  console.log(JSON.stringify({...result,scope:'DEDICATED_EMPTY_PERSONNEL_INTAKE_CONTRACT',officer_data_published:false}));
}
if(require.main===module)main(process.argv.slice(2)).catch(()=>{console.error(JSON.stringify({status:'STOPPED',category:'PERSONNEL_INTAKE_DEPLOYMENT_OR_VERIFICATION_FAILED',recovery:'RECONCILE_ORIGINAL_RETAINED_TRANSACTION',original_data_journals_changed:false}));process.exitCode=1;});
module.exports={args,main};
