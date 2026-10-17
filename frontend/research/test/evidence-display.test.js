'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {JSDOM}=require('jsdom');
const root=path.join(__dirname,'..');
const uid='00000000-0000-0000-0000-000000000001';
const officer={officer_uid:uid,names:['Reported Officer'],nic:'000000001V'};
const workspace={generation:1,observed_at:'2026-10-11T00:00:00Z',coverage_start:'2026-10-01T00:00:00Z',coverage_end:'2026-10-10T00:00:00Z',
  findings:[{finding_id:'00000000-0000-0000-0000-000000000201',head_sha256:'b'.repeat(64),dimension:'rank',status:'REPORTED_CONTRADICTION_CANDIDATE',effective_on:'2024-12-31',known_at:'2026-10-01T00:00:00Z',versions:[{kind:'FINDING',recorded_at:'2026-10-01T00:00:00Z',entry_sha256:'b'.repeat(64),reason:'Reported disagreement',decision:null}]}],
  authority:[],anchoring:Object.fromEntries(['fabric','public','recovery'].map(k=>[k,{status:'NOT_CONFIGURED',receipt_sha256:null}])),can_request_review:true};
const answer={effective_on:'2024-12-31',known_at:'2026-10-10T00:00:00Z',query_digest:'c'.repeat(64),comparison_digest:'d'.repeat(64),
  projections:[{dimension:'rank',status:'CONFLICTING_REPORTS',candidates:[{fields:{to_rank:'<img src=x onerror="alert(1)">'},effective_from:'2024-01-01',mode:'EVENT'}],review:[],future:[],expired:[],reasons:['HISTORICAL_IDENTITY_UNASSESSED']}],versions:[],comparisons:[]};
const response=(value,status=200)=>({ok:status<400,status,json:async()=>structuredClone(value)});
const wait=async check=>{for(let n=0;n<100;n++){if(check())return;await new Promise(r=>setTimeout(r,5));}throw Error('DOM workflow did not settle');};
async function setup(handler,configure){
  const dom=new JSDOM(fs.readFileSync(path.join(root,'index.html'),'utf8'),{url:'https://access.test:9443',runScripts:'outside-only',pretendToBeVisual:true});
  const calls=[];dom.window.fetch=async(url,options)=>{calls.push([url,options]);return handler?handler(url,options):response({username:'station.one',role:'STATION_OIC',scope_type:'STATION',scope_id:'S1',csrf_token:'csrf'});};
  if(configure)configure(dom.window);dom.window.eval(fs.readFileSync(path.join(root,'app.js'),'utf8'));await wait(()=>!dom.window.document.getElementById('application').hidden);
  return {dom,d:dom.window.document,calls,submit:id=>dom.window.document.getElementById(id).dispatchEvent(new dom.window.Event('submit',{bubbles:true,cancelable:true}))};
}
async function selected(t){t.d.getElementById('search-query').value='000000001V';t.submit('search-form');await wait(()=>t.d.querySelector('.officer-result'));t.d.querySelector('.officer-result').click();await wait(()=>!t.d.getElementById('workspace-body').hidden);}
function router(url){if(url==='/api/auth/session')return response({username:'station.one',role:'STATION_OIC',scope_type:'STATION',scope_id:'S1',csrf_token:'csrf'});if(url==='/api/officers/search')return response({items:[officer],total:1});if(url.startsWith('/api/research/officers/'))return response(workspace);if(url==='/api/research/history')return response(answer);return response({authenticated:false});}
test('connected promotion evidence shows actual analysis time and clears at logout',async()=>{
 const analysis={reported_promotions:1,latest_recorded_at:'2026-10-16T09:00:00.123456+00:00'};
 const uploaded={items:[{raw_record_id:'e'.repeat(64),fields:{officer_nic_no:'000000001V',to_rank:'Inspector of Police'},received_at:'2026-10-16T08:00:00Z',publication:{fabric_transaction_id:'f'.repeat(64),public_transaction_id:'0x'+'a'.repeat(64)}}],analysis};
 const t=await setup(u=>u.startsWith('/api/research/officers/')?response({...workspace,coverage_end:analysis.latest_recorded_at,additional_promotion_reports:uploaded,promotion_analysis:analysis}):router(u));
 try{await selected(t);const root=t.d.getElementById('full-records');assert(root.textContent.includes('Connected promotion evidence: 1'));assert(root.textContent.includes('connected to History, Authority and Contradictions'));t.d.getElementById('use-recorded-boundary').click();t.submit('history-form');await wait(()=>t.calls.some(([u])=>u==='/api/research/history'));assert.equal(JSON.parse(t.calls.find(([u])=>u==='/api/research/history')[1].body).known_at,analysis.latest_recorded_at);t.d.getElementById('logout').click();assert.equal(root.textContent,'');await wait(()=>t.d.getElementById('login-message').textContent.includes('Signed out securely'));}finally{t.dom.window.close();}
});
test('history displays promotion provenance as safe text with its chain references',async()=>{
 const summary={reported_promotions:1,latest_recorded_at:'2026-10-10T00:00:00Z'};
 const evidence={batch_id:'<img src=x onerror=alert(1)>',publication:{fabric_transaction_id:'f'.repeat(64),public_transaction_id:'0x'+'a'.repeat(64)}};
 const t=await setup(u=>u==='/api/research/history'?response({...answer,promotion_analysis:summary,promotion_evidence:[evidence]}):router(u));
 try{await selected(t);t.d.getElementById('tab-history').click();t.submit('history-form');await wait(()=>t.d.querySelector('#history-results .promotion-analysis-summary'));const root=t.d.getElementById('history-results');assert(root.textContent.includes('f'.repeat(64)));assert(root.textContent.includes('<img src=x'));assert.equal(root.querySelector('img'),null);t.d.getElementById('logout').click();assert.equal(root.textContent,'');await wait(()=>t.d.getElementById('login-message').textContent.includes('Signed out securely'));}finally{t.dom.window.close();}
});


test('source identity badge is shared and officer internal reference is absent',async()=>{
 const t=await setup(router);try{await selected(t);assert.ok(t.d.getElementById('officer-workspace').textContent.includes('Source-reported identity'));assert.equal(t.d.getElementById('officer-reference'),null);assert.ok(!t.d.getElementById('officer-workspace').textContent.includes(uid));}finally{t.dom.window.close();}
});
test('running history does not replace retained contradiction results or issue authority requests',async()=>{
 const t=await setup(router);try{await selected(t);t.d.getElementById('contradiction-results').textContent='Previously compared source pair';t.d.getElementById('authority-workflow-results').textContent='Previously assessed action';t.submit('history-form');await wait(()=>t.d.querySelector('.projection-grid'));assert.equal(t.d.getElementById('contradiction-results').textContent,'Previously compared source pair');assert.equal(t.d.getElementById('authority-workflow-results').textContent,'Previously assessed action');assert.ok(!t.calls.some(([u])=>u==='/api/research/authority'||u==='/api/research/contradictions'));}finally{t.dom.window.close();}
});
test('new promotion times and pending acceptance reasons remain distinct from original snapshot',async()=>{
 const w={...workspace,evidence_updates:{latest_analysis_at:'2026-10-16T14:58:00Z',latest_publication_verified_at:'2026-10-16T14:57:00Z'},current_assignment:{pending_promotions:1,row_outcomes:[{status:'PENDING_REVIEW',to_rank:'Police Constable Class 2',effective_on:'2026-10-16',effective_now:true,decision_retained:true,reasons:['AUTHORITY_CANNOT_VERIFY']}]}};
 const t=await setup(u=>u.startsWith('/api/research/officers/')?response(w):router(u));try{await selected(t);const h=t.d.getElementById('observation-label').textContent;assert.ok(h.includes('Original evidence snapshot'));assert.ok(h.includes('New evidence connected'));assert.ok(t.d.querySelector('.promotion-acceptance').textContent.includes('matching assessment'));t.d.getElementById('logout').click();assert.equal(t.d.getElementById('full-records').textContent,'');assert.equal(t.d.getElementById('observation-label').textContent,'');await wait(()=>t.d.getElementById('login-message').textContent.includes('Signed out securely'));}finally{t.dom.window.close();}
});
test('history rank periods show reference dates and source meaning without fabricating validity',async()=>{
 const a={...answer,rank_timeline:[{rank:'Entry Constable',reported_from:'2014-01-02',reported_until:'2024-01-01',date_meaning:'Enlistment reference date; rank effective date unassessed',boundary_basis:'Display boundary only',source_categories:['Police HR information system']}],projections:[{...answer.projections[0],supporting:[{fields:{current_rank:'Inspector'},mode:'SNAPSHOT',reported_dataset:'officer_service_information.csv'}],review:[{fields:{restriction_id:'R1'},mode:'INTERVAL',reported_dataset:'officer_restrictions.csv',reasons:['REPORTED_DATE_MISSING']}]}]};
 const t=await setup(u=>u==='/api/research/history'?response(a):router(u));try{await selected(t);t.submit('history-form');await wait(()=>t.d.querySelector('.rank-periods'));const text=t.d.getElementById('history-results').textContent;for(const word of ['2014-01-02','2024-01-01','Enlistment reference date','Police HR information system','Service Record Book (SRB)','How this supports','Why review is needed'])assert.ok(text.includes(word),word);}finally{t.dom.window.close();}
});
