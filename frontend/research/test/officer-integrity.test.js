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
    anchors:{chunk:32,chunk_size:100,transactions_per_chain:68,fabric:{transaction_id:'3'.repeat(64),block_number:110,validation_code:0},sepolia:{transaction_hash:'0x'+'4'.repeat(64),block:'0xb52cb5',block_hash:'0x'+'5'.repeat(64)},
      fabric_begin:{transaction_id:'6'.repeat(64)},fabric_seal:{transaction_id:'7'.repeat(64)},sepolia_begin:{transaction_hash:'0x'+'8'.repeat(64)},sepolia_final:{transaction_hash:'0x'+'9'.repeat(64)}},
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
    for(const expected of ['one of 6596 officers','officer-evidence-v1','Uploads that mention this officer','Transfers','row 1 of 5','Officer checkpoint chain','1 link','Passed','Stored original receipts for this officer','chunk 32','block 110','3'.repeat(64),'4'.repeat(64)])assert(text.includes(expected),expected);
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
test('a read-only account is pointed to the working review page instead of a misleading permission message',async()=>{
  const t=await setup(router());try{await new Promise(r=>setTimeout(r,50));const note=t.d.getElementById('review-message').textContent;
    assert(note.includes('Reviews & corrections')&&note.includes('separately provisioned protected review flow'));assert(!note.includes('separately granted reviewer identity'));
    assert.equal(t.d.getElementById('review-button').disabled,true);
  }finally{await new Promise(r=>setTimeout(r,60));t.dom.window.close();}});

const liveBase=path_=>'/api/research/officers/'+uid+'/integrity'+path_;
const withLive=(available=true)=>({...view,live_check_available:available});
const liveResult=(over={})=>({basis:'FRESH_READ_NOW',overall:'PASSED',checked_at:'2026-10-19T00:30:00.000Z',transactions_submitted:0,
  fabric:{status:'READ',organizations:['Org1MSP','Org2MSP'],each_organization_matches:{Org1MSP:true,Org2MSP:true},organizations_agree:true,batch_root_matches:true,batch_officer_count_matches:true,network_identity_verified:true,passed:true},
  sepolia:{status:'READ',finalized_block:11944555,officer_value_matches_commitment:true,batch_root_present:true,batch_officer_count:6596,batch_sealed:true,officer_count_matches:true,sealed_block_is_finalized:true,passed:true},
  limits:['A passing check shows the chains currently return the stored commitment for this officer; it does not show the record is true.'],...over});
async function openIntegrity(t){t.d.getElementById('tab-integrity').click();await wait(()=>t.d.getElementById('integrity-results').textContent.includes('Original fingerprint'));}
const quiet=()=>new Promise(r=>setTimeout(r,80));
test('live check: the button reads the chains, shows a plain pass and guards against double clicks',async()=>{
  let resolve,calls=0;const t=await setup(router({[liveBase('')]:()=>response(withLive()),[liveBase('/live')]:()=>{calls++;return new Promise(r=>{resolve=()=>r(response(liveResult()));});}}));
  try{await openIntegrity(t);const button=t.d.getElementById('live-check');assert.ok(button);assert(t.d.getElementById('integrity-results').textContent.includes('makes no transaction'));
    button.click();button.click();await wait(()=>button.disabled);assert(t.d.getElementById('live-result').textContent.includes('Reading Fabric and Sepolia'));
    resolve();await wait(()=>t.d.getElementById('live-result').textContent.includes('Live chain check'));
    const text=t.d.getElementById('live-result').textContent;assert.equal(calls,1);assert.equal(button.disabled,false);
    for(const expected of ['Passed','Fabric organization 1 returned this officer’s stored commitment: yes','Fabric organization 2 returned this officer’s stored commitment: yes','The two organizations agree with each other: yes','The Sepolia contract returned this officer’s stored commitment: yes','sealed with 6596 officers: yes','finalized block 11944555: yes','Both chains currently return the stored commitment','made no transaction'])assert(text.includes(expected),expected);
    assert(!text.includes('NO'));const post=t.calls.find(([u])=>u.endsWith('/integrity/live'));assert.equal(post[0],liveBase('/live'));assert.deepEqual(JSON.parse(post[1].body),{});assert.equal(t.dom.window.localStorage.length,0);
  }finally{await quiet();t.dom.window.close();}});
test('live check: a mismatch is shown as not confirmed, never as passed',async()=>{
  const bad=liveResult({overall:'FAILED',fabric:{...liveResult().fabric,each_organization_matches:{Org1MSP:true,Org2MSP:false},organizations_agree:false,passed:false}});
  const t=await setup(router({[liveBase('')]:()=>response(withLive()),[liveBase('/live')]:()=>response(bad)}));
  try{await openIntegrity(t);t.d.getElementById('live-check').click();await wait(()=>t.d.getElementById('live-result').textContent.includes('Does not match'));
    const text=t.d.getElementById('live-result').textContent;assert(text.includes('organization 2 returned this officer’s stored commitment: NO')&&text.includes('The two organizations agree with each other: NO')&&text.includes('is not confirmed by this check'));
    assert(!text.includes('Both chains currently return'));assert.equal(t.d.querySelector('#live-result .pill').className.includes('red'),true);
  }finally{await quiet();t.dom.window.close();}});
test('live check: an unreadable chain says it proves nothing and shows only a short code',async()=>{
  const down=liveResult({overall:'UNAVAILABLE',fabric:{status:'UNAVAILABLE',reason:'NETWORK_ERROR'},passed:false});
  const t=await setup(router({[liveBase('')]:()=>response(withLive()),[liveBase('/live')]:()=>response(down)}));
  try{await openIntegrity(t);t.d.getElementById('live-check').click();await wait(()=>t.d.getElementById('live-result').textContent.includes('Could not be read'));
    const text=t.d.getElementById('live-result').textContent;assert(text.includes('Fabric could not be read (NETWORK_ERROR). Nothing is claimed about it.')&&text.includes('proves nothing either way'));
    assert(!text.includes('Both chains currently return')&&!/\bPassed\b/.test(text.replace('Passed','')));assert.equal(t.d.querySelector('#live-result .pill').className.includes('amber'),true);
  }finally{await quiet();t.dom.window.close();}});
test('live check: a server refusal is shown and the button works again; not-enabled servers show a plain note instead',async()=>{
  const t=await setup(router({[liveBase('')]:()=>response(withLive()),[liveBase('/live')]:()=>response({error:'LIVE_CHECK_NOT_CONFIGURED'},503)}));
  try{await openIntegrity(t);const button=t.d.getElementById('live-check');button.click();await wait(()=>t.d.getElementById('live-result').textContent.length>0&&!button.disabled);
    assert(t.d.getElementById('live-result').textContent.length>5);assert(!t.d.getElementById('live-result').textContent.includes('Passed'));assert.equal(button.disabled,false);
  }finally{await quiet();t.dom.window.close();}
  const n=await setup(router({[liveBase('')]:()=>response(withLive(false))}));
  try{await openIntegrity(n);assert.equal(n.d.getElementById('live-check'),null);assert(n.d.getElementById('integrity-results').textContent.includes('Live chain check: not enabled on this server'));assert(n.d.getElementById('integrity-results').textContent.includes('not a read of the chains'));}finally{await quiet();n.dom.window.close();}});
test('live check: a late answer after the officer view is closed is discarded and the result is cleared',async()=>{
  let resolve;const t=await setup(router({[liveBase('')]:()=>response(withLive()),[liveBase('/live')]:()=>new Promise(r=>{resolve=()=>r(response(liveResult()));})}));
  try{await openIntegrity(t);t.d.getElementById('live-check').click();await wait(()=>!!resolve);t.d.getElementById('logout').click();assert.equal(t.d.getElementById('integrity-results').textContent,'');
    resolve();await quiet();assert.equal(t.d.getElementById('integrity-results').textContent,'');assert.equal(t.d.getElementById('live-result'),null);
  }finally{await quiet();t.dom.window.close();}});
