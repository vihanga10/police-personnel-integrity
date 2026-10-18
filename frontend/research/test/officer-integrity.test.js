'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const root=path.join(__dirname,'..');
const uid='00000000-0000-0000-0000-000000000001';
const officer={officer_uid:uid,names:['Reported Officer'],nic:'000000001V'};
const workspace={generation:1,observed_at:'2026-10-11T00:00:00Z',coverage_start:'2026-10-01T00:00:00Z',coverage_end:'2026-10-10T00:00:00Z',findings:[],authority:[],
  anchoring:Object.fromEntries(['fabric','public','recovery'].map(k=>[k,{status:'NOT_CONFIGURED',receipt_sha256:null}])),can_request_review:false};
const response=(value,status=200)=>({ok:status<400,status,json:async()=>structuredClone(value)});
const wait=async check=>{for(let n=0;n<200;n++){if(check())return;await new Promise(r=>setTimeout(r,5));}throw Error('DOM workflow did not settle');};
const view={policy:'OFFICER_INTEGRITY_VIEW_V1',original_available:true,all_recomputed_checks_passed:true,verification_errors:[],basis:'RECOMPUTED_FROM_RETAINED_ENCRYPTED_EVIDENCE',
  original:{publication_id:'p'.repeat(64),commitment:'c'.repeat(64),leaf_sha256:'1'.repeat(64),leaf_index:12,proof_length:13,recomputed_root:'r'.repeat(64),inclusion_verified:true,merkle_root:'r'.repeat(64),
    batch_publication_id:'b'.repeat(64),sepolia_contract:'0x4Ae794040d9794cd3b50BB06Fd41eE540c2435a6',sepolia_sealing_block:'0xb52fdb',fabric_channel:'personnel',fabric_chaincode:'officer-evidence-v1',verified_on:'2026-10-09',officers_in_batch:6596},
  uploads:[{record_type:'TRANSFER_HISTORY',record_type_label:'Transfers',batch_id:'x',filename:'<img src=x onerror=alert(1)>.csv',uploaded_at:'2026-10-18T08:00:00Z',activated_at:'2026-10-18T08:30:00Z',activation_reference:'a'.repeat(64),
    rows_for_officer:[{row:1,leaf_sha256:'2'.repeat(64),included:true}],rows_in_batch:5,publication_id:'q'.repeat(64),merkle_root:'m'.repeat(64),recomputed_root:'m'.repeat(64),root_matches_published:true,all_rows_included:true,
    fabric_transaction_id:'f'.repeat(64),public_transaction_id:'0x'+'e'.repeat(64),public_contract:'0x'+'c'.repeat(40),verified_at:'2026-10-18T08:27:00Z'}],
  checkpoint_chain:{policy:'OFFICER_CHECKPOINT_CHAIN_V1',genesis:'1'.repeat(64),length:1,head:'h'.repeat(64),links:[{sequence:1,previous:'1'.repeat(64),hash:'h'.repeat(64),batch_id:'x',record_type_label:'Transfers',activated_at:'2026-10-18T08:30:00Z'}]},
  limits:['An inclusion check proves a retained commitment belongs to a published root, not that the record is true.']};
function router(overrides={}){return url=>{if(overrides[url])return overrides[url]();if(url==='/api/auth/session')return response({username:'station.one',role:'STATION_OIC',scope_type:'STATION',scope_id:'S1',csrf_token:'csrf'});
  if(url==='/api/officers/search')return response({items:[officer],total:1});if(url.endsWith('/integrity'))return response(view);if(url.startsWith('/api/research/officers/'))return response(workspace);return response({authenticated:false});};}
async function setup(handler){
  const dom=new JSDOM(fs.readFileSync(path.join(root,'index.html'),'utf8'),{url:'https://access.test:9443',runScripts:'outside-only',pretendToBeVisual:true});
  const calls=[];dom.window.fetch=async(url,options)=>{calls.push([url,options]);return handler(url,options);};dom.window.eval(fs.readFileSync(path.join(root,'app.js'),'utf8'));
  await wait(()=>!dom.window.document.getElementById('application').hidden);
  const d=dom.window.document;d.getElementById('search-query').value='000000001V';d.getElementById('search-form').dispatchEvent(new dom.window.Event('submit',{bubbles:true,cancelable:true}));
  await wait(()=>d.querySelector('.officer-result'));d.querySelector('.officer-result').click();await wait(()=>!d.getElementById('workspace-body').hidden);return {dom,d,calls};
}
test('integrity tab shows the original fingerprint, uploads and checkpoint chain as safe text',async()=>{
  const t=await setup(router());try{t.d.getElementById('tab-integrity').click();await wait(()=>t.d.getElementById('integrity-results').textContent.includes('Original fingerprint'));
    const text=t.d.getElementById('integrity-results').textContent;
    for(const expected of ['one of 6596 officers','officer-evidence-v1','Uploads that mention this officer','Transfers','row 1 of 5','Officer checkpoint chain','1 link','Passed'])assert(text.includes(expected),expected);
    assert(text.includes('<img src=x'));assert.equal(t.d.querySelector('#integrity-results img'),null);
    assert(t.d.getElementById('integrity-summary').textContent.includes('All recomputed fingerprint checks passed'));
    const call=t.calls.find(([u])=>u.endsWith('/integrity'));assert.equal(call[0],'/api/research/officers/'+uid+'/integrity');assert.equal(t.dom.window.localStorage.length,0);
  }finally{t.dom.window.close();}});
test('a failed recomputation is shown plainly and never as verified',async()=>{
  const bad={...view,all_recomputed_checks_passed:false,verification_errors:['ANALYSIS_VISIBILITY_BINDING_DIFFERS'],uploads:[]};
  const t=await setup(router({}));t.dom.window.fetch=async(u)=>u.endsWith('/integrity')?response(bad):router()(u);
  try{t.d.getElementById('tab-integrity').click();await wait(()=>t.d.getElementById('integrity-summary').textContent.includes('did not pass'));
    assert(t.d.getElementById('integrity-summary').textContent.includes('ANALYSIS_VISIBILITY_BINDING_DIFFERS'));assert(!t.d.getElementById('integrity-summary').textContent.includes('All recomputed'));
  }finally{t.dom.window.close();}});
test('missing original fingerprint is explained and a server error never claims verification',async()=>{
  const none={...view,original:null,original_available:false,uploads:[],checkpoint_chain:{...view.checkpoint_chain,length:0,links:[],genesis:'0'.repeat(64),head:'0'.repeat(64)}};
  const t=await setup(router({}));t.dom.window.fetch=async(u)=>u.endsWith('/integrity')?response(none):router()(u);
  try{t.d.getElementById('tab-integrity').click();await wait(()=>t.d.getElementById('integrity-results').textContent.includes('not been installed'));
    assert(t.d.getElementById('integrity-results').textContent.includes('No verified upload mentions this officer yet'));
  }finally{t.dom.window.close();}
  const e=await setup(router({}));e.dom.window.fetch=async(u)=>u.endsWith('/integrity')?response({error:'RESEARCH_SERVICE_UNAVAILABLE'},503):router()(u);
  try{e.d.getElementById('tab-integrity').click();await wait(()=>e.d.getElementById('integrity-results').textContent.includes('could not be recomputed'));assert(!e.d.getElementById('integrity-summary').textContent.includes('passed'));}finally{e.dom.window.close();}});
test('integrity results clear when the officer view is closed',async()=>{
  const t=await setup(router());try{t.d.getElementById('tab-integrity').click();await wait(()=>t.d.getElementById('integrity-results').textContent.includes('Original fingerprint'));
    t.d.getElementById('logout').click();assert.equal(t.d.getElementById('integrity-results').textContent,'');await new Promise(r=>setTimeout(r,100));
  }finally{t.dom.window.close();}});
