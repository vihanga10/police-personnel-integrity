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
test('all six tabs use accessible keyboard navigation and labelled controls',async()=>{const t=await setup(router);try{await selected(t);const tabs=[...t.d.querySelectorAll('[role=tab]')];assert.equal(tabs.length,6);tabs[0].dispatchEvent(new t.dom.window.KeyboardEvent('keydown',{key:'End',bubbles:true}));assert.equal(t.d.activeElement.id,'tab-anchoring');assert.equal(t.d.getElementById('tab-anchoring').getAttribute('aria-selected'),'true');for(const el of t.d.querySelectorAll('input,select,textarea'))assert.ok(t.d.querySelector(`label[for="${el.id}"]`),'Every form control has a label');assert.ok(t.d.querySelector('a.skip'));}finally{t.dom.window.close();}});
test('historical values and finding explanations render as text without HTML injection',async()=>{const t=await setup(router);try{await selected(t);t.d.getElementById('tab-history').click();t.submit('history-form');await wait(()=>t.d.querySelector('.projection-grid'));assert.ok(t.d.getElementById('history-results').textContent.includes('<img src=x'));assert.equal(t.d.getElementById('history-results').querySelector('img'),null);assert.ok(t.d.getElementById('contradiction-results').textContent.includes('does not establish agreement'));}finally{t.dom.window.close();}});
test('Colombo local time is converted explicitly; query never sends role or scope',async()=>{const t=await setup(router);try{await selected(t);t.d.getElementById('query-timezone').value='COLOMBO';t.d.getElementById('known-date').value='2026-10-10T05:30';t.submit('history-form');await wait(()=>t.calls.some(([u])=>u==='/api/research/history'));const body=JSON.parse(t.calls.find(([u])=>u==='/api/research/history')[1].body);assert.equal(body.known_at,'2026-10-10T00:00:00.000Z');assert.deepEqual(Object.keys(body).sort(),['effective_on','known_at','officer_uid']);await wait(()=>!t.d.getElementById('history-button').disabled);}finally{t.dom.window.close();}});
test('a withheld officer cannot show an old workspace after selection',async()=>{let allow=true;const t=await setup(u=>u.startsWith('/api/research/officers/')?allow?response(workspace):response({error:'DETAILS_WITHHELD'},403):router(u));try{await selected(t);allow=false;t.d.querySelector('.officer-result').click();await wait(()=>t.d.getElementById('workspace-state').textContent.includes('withheld'));assert.equal(t.d.getElementById('workspace-body').hidden,true);assert.equal(t.d.getElementById('findings-results').textContent,'');}finally{t.dom.window.close();}});
test('uncertain review submission is never automatically retried; manual retry retains exact operation and content',async()=>{let attempts=0;const t=await setup((u,o)=>{if(u==='/api/research/requests'){attempts++;if(attempts===1)throw Error('lost response');const b=JSON.parse(o.body);return response({operation_id:b.operation_id,request_sha256:'e'.repeat(64),status:'PENDING_AUTHORITY',explanation:'Request retained, pending authority.'});}return router(u);});try{await selected(t);t.d.getElementById('review-reason').value='Evidence needs assessment.';t.submit('review-form');await wait(()=>t.d.getElementById('review-message').textContent.includes('Operation ID'));await wait(()=>!t.d.getElementById('review-button').disabled);assert.equal(attempts,1);t.d.getElementById('review-reason').value='Changed while the acknowledgement was unknown';t.submit('review-form');await wait(()=>t.d.getElementById('request-status').textContent.includes('pending authority'));const calls=t.calls.filter(([u])=>u==='/api/research/requests');assert.equal(calls[0][1].body,calls[1][1].body);assert.equal(t.dom.window.localStorage.length,0);assert.equal(t.dom.window.sessionStorage.length,0);}finally{t.dom.window.close();}});
test('double-click review submission has one request',async()=>{let release;const t=await setup((u,o)=>u==='/api/research/requests'?new Promise(resolve=>{release=()=>resolve(response({operation_id:JSON.parse(o.body).operation_id,request_sha256:'e'.repeat(64),status:'PENDING_AUTHORITY',explanation:'Pending authority'}));}):router(u));try{await selected(t);t.d.getElementById('review-reason').value='Fixture reason';t.submit('review-form');t.submit('review-form');await wait(()=>release);assert.equal(t.calls.filter(([u])=>u==='/api/research/requests').length,1);release();await wait(()=>t.d.getElementById('review-message').textContent.includes('Request retained'));}finally{t.dom.window.close();}});
test('logout clears private identity, finding, query and account text from the DOM',async()=>{const t=await setup(router);try{await selected(t);t.d.getElementById('logout').click();await wait(()=>t.d.getElementById('login-message').textContent.includes('Signed out securely'));assert.ok(!t.d.body.textContent.includes(officer.nic));assert.ok(!t.d.body.textContent.includes(officer.names[0]));assert.ok(!t.d.body.textContent.includes('station.one'));assert.equal(t.d.getElementById('review-finding').children.length,0);}finally{t.dom.window.close();}});
test('a late officer response cannot reopen a closed workspace',async()=>{let finish;const t=await setup(u=>u.startsWith('/api/research/officers/')?new Promise(r=>{finish=()=>r(response(workspace));}):router(u));try{t.d.getElementById('search-query').value='000000001V';t.submit('search-form');await wait(()=>t.d.querySelector('.officer-result'));t.d.querySelector('.officer-result').click();await wait(()=>finish);t.d.getElementById('close-officer').click();finish();await new Promise(r=>setTimeout(r,20));assert.equal(t.d.getElementById('officer-workspace').hidden,true);assert.equal(t.d.getElementById('workspace-body').hidden,true);}finally{t.dom.window.close();}});
test('static UI has no external dependency, unsafe HTML sink or browser persistence',()=>{const js=fs.readFileSync(path.join(root,'app.js'),'utf8');const html=fs.readFileSync(path.join(root,'index.html'),'utf8');assert.ok(!/innerHTML|insertAdjacentHTML|document\.write|localStorage\.|sessionStorage\./.test(js));assert.ok(!/<script[^>]+src="https?:/.test(html));assert.ok(/prefers-reduced-motion/.test(fs.readFileSync(path.join(root,'styles.css'),'utf8')));assert.ok(/max-width:600px/.test(fs.readFileSync(path.join(root,'styles.css'),'utf8')));});

test('delayed search cannot repopulate private names after background clearing',async()=>{
  let finish;const t=await setup(u=>u==='/api/officers/search'?new Promise(r=>{finish=()=>r(response({items:[officer],total:1}));}):router(u));
  try{t.d.getElementById('search-query').value=officer.nic;t.submit('search-form');await wait(()=>finish);
    Object.defineProperty(t.d,'hidden',{configurable:true,value:true});t.d.dispatchEvent(new t.dom.window.Event('visibilitychange'));
    finish();await new Promise(r=>setTimeout(r,20));assert.equal(t.d.querySelector('.officer-result'),null);assert.equal(t.d.getElementById('search-query').value,'');assert.equal(t.d.getElementById('search-pagination').hidden,true);
  }finally{t.dom.window.close();}
});

test('sign-out clears private content immediately while the server reply is delayed',async()=>{
  let finish;const t=await setup(u=>u==='/api/auth/logout'?new Promise(r=>{finish=()=>r(response({authenticated:false}));}):router(u));
  try{await selected(t);t.d.getElementById('show-password').click();t.d.getElementById('logout').click();
    assert.equal(t.d.getElementById('application').hidden,true);assert.equal(t.d.getElementById('officer-name').textContent,'');assert.equal(t.d.getElementById('password').type,'password');finish();await wait(()=>t.d.getElementById('login-message').textContent.includes('Signed out securely'));
  }finally{t.dom.window.close();}
});

test('a failed new search clears the earlier result list',async()=>{
  let failed=false;const t=await setup(u=>u==='/api/officers/search'&&failed?response({error:'RATE_LIMITED'},429):router(u));
  try{await selected(t);failed=true;t.submit('search-form');await wait(()=>t.d.getElementById('app-message').textContent.includes('Too many'));assert.equal(t.d.querySelector('.officer-result'),null);
  }finally{t.dom.window.close();}
});

test('definitive validation rejection permits editing a new request without reusing the rejected intent',async()=>{
  let attempts=0;const t=await setup((u,o)=>u==='/api/research/requests'?(++attempts===1?response({error:'INVALID_REVIEW_REQUEST'},400):response({operation_id:JSON.parse(o.body).operation_id,request_sha256:'e'.repeat(64),status:'PENDING_AUTHORITY',explanation:'Pending authority'})):router(u));
  try{await selected(t);t.d.getElementById('review-reason').value='Invalid fixture content';t.submit('review-form');await wait(()=>t.d.getElementById('review-message').textContent.includes('1,200'));await wait(()=>!t.d.getElementById('review-button').disabled);
    t.d.getElementById('review-reason').value='Edited valid content';t.submit('review-form');await wait(()=>t.d.getElementById('request-status').textContent.includes('Pending authority'));const sent=t.calls.filter(([u])=>u==='/api/research/requests').map(([,o])=>JSON.parse(o.body));assert.notEqual(sent[0].operation_id,sent[1].operation_id);assert.equal(sent[1].reason,'Edited valid content');
  }finally{t.dom.window.close();}
});

test('blank review reasons never create an operation or backend request',async()=>{
  const t=await setup(router);try{await selected(t);t.d.getElementById('review-reason').value='  ';t.submit('review-form');assert.equal(t.calls.filter(([u])=>u==='/api/research/requests').length,0);assert.equal(t.d.getElementById('operation-id').value,'');assert.ok(t.d.getElementById('review-message').textContent.includes('Provide a reason'));}finally{t.dom.window.close();}
});

test('scoped read-only grants render findings but deny review controls',async()=>{
  const t=await setup(u=>u.startsWith('/api/research/officers/')?response({...workspace,can_request_review:false}):router(u));
  try{await selected(t);assert.ok(t.d.getElementById('findings-results').textContent.includes('Rank finding'));assert.equal(t.d.getElementById('review-button').disabled,true);t.submit('review-form');assert.equal(t.calls.filter(([u])=>u==='/api/research/requests').length,0);}finally{t.dom.window.close();}
});

test('expired session on a protected query clears officer content before showing login',async()=>{
  const t=await setup(u=>u==='/api/research/history'?response({error:'LOGIN_REQUIRED'},401):router(u));
  try{await selected(t);t.submit('history-form');await wait(()=>!t.d.getElementById('login-screen').hidden);assert.equal(t.d.getElementById('officer-name').textContent,'');assert.equal(t.d.getElementById('history-results').textContent,'');assert.ok(!t.d.body.textContent.includes(officer.nic));}finally{t.dom.window.close();}
});

test('old query completion cannot overwrite the next selected officer query or enable its button',async()=>{
  const pending=[];const t=await setup(u=>u==='/api/research/history'?new Promise(r=>pending.push(()=>r(response(answer)))):router(u));
  try{await selected(t);t.submit('history-form');await wait(()=>pending.length===1);t.d.querySelector('.officer-result').click();await wait(()=>!t.d.getElementById('workspace-body').hidden);assert.equal(t.d.getElementById('history-button').disabled,false);t.submit('history-form');await wait(()=>pending.length===2);
    pending[0]();await new Promise(r=>setTimeout(r,20));assert.equal(t.d.getElementById('history-button').disabled,true);assert.equal(t.d.querySelector('.projection-grid'),null);pending[1]();await wait(()=>!t.d.getElementById('history-button').disabled);assert.ok(t.d.querySelector('.projection-grid'));
  }finally{t.dom.window.close();}
});

test('initial delayed session denial cannot undo a completed sign-in',async()=>{
  let deny;let sessionCalls=0;const dom=new JSDOM(fs.readFileSync(path.join(root,'index.html'),'utf8'),{url:'https://access.test:9443',runScripts:'outside-only',pretendToBeVisual:true});
  const d=dom.window.document;
  dom.window.fetch=async u=>{if(u==='/api/auth/session'&&++sessionCalls===1)return new Promise(r=>{deny=()=>r(response({error:'LOGIN_REQUIRED'},401));});if(u==='/api/auth/login')return response({authenticated:true});return router('/api/auth/session');};
  try{dom.window.eval(fs.readFileSync(path.join(root,'app.js'),'utf8'));await wait(()=>deny);d.getElementById('username').value='station.one';d.getElementById('password').value='fixture-password';d.getElementById('login-form').dispatchEvent(new dom.window.Event('submit',{bubbles:true,cancelable:true}));await wait(()=>!d.getElementById('application').hidden);deny();await new Promise(r=>setTimeout(r,20));assert.equal(d.getElementById('application').hidden,false);assert.equal(d.getElementById('password').value,'');}finally{dom.window.close();}
});

test('history and comparisons show bounded dataset provenance and full trace references',async()=>{
  const claim={reference:'a'.repeat(64),fields:{to_rank:'Reported Inspector'},effective_from:'2024-01-01',mode:'EVENT',reported_dataset:'promotion_history.csv',provenance_sha256:'f'.repeat(64)};
  const provenanceAnswer={...answer,projections:[{...answer.projections[0],candidates:[claim]}],comparisons:[{dimension:'rank',status:'REPORTED_CONTRADICTION_CANDIDATE',reasons:[],evidence_references:[claim.reference],evidence:[claim]}]};
  const t=await setup(u=>u==='/api/research/history'?response(provenanceAnswer):router(u));
  try{await selected(t);t.submit('history-form');await wait(()=>t.d.querySelector('.projection-grid'));for(const id of ['history-results','contradiction-results']){assert.ok(t.d.getElementById(id).textContent.includes('promotion_history.csv'));assert.ok(t.d.getElementById(id).textContent.includes('f'.repeat(64)));assert.ok(t.d.getElementById(id).textContent.includes('Independent custody unverified'));}}finally{t.dom.window.close();}
});

test('action-date and outcome filtering inspects retained authority records without asserting a new decision',async()=>{
  const authority=[{action_type:'TRANSFER',action_on:'2024-01-01',status:'VALID',reasons:['AUTHENTICATED_TEMPORAL_REVIEW_ASSESSMENT'],assessment_receipt_sha256:'a'.repeat(64)},
    {action_type:'PROMOTION',action_on:'2024-02-01',status:'CANNOT_VERIFY',reasons:['AUTHORITY_AND_DELEGATION_UNASSESSED'],assessment_receipt_sha256:null}];
  const t=await setup(u=>u.startsWith('/api/research/officers/')?response({...workspace,authority}):router(u));
  try{await selected(t);const before=t.calls.length;t.d.getElementById('authority-date').value='2024-01-01';t.d.getElementById('authority-outcome').value='VALID';t.submit('authority-filter-form');assert.ok(t.d.getElementById('authority-results').textContent.includes('Transfer'));assert.ok(!t.d.getElementById('authority-results').textContent.includes('Promotion'));assert.equal(t.calls.length,before);
    t.d.getElementById('authority-outcome').value='INVALID';t.submit('authority-filter-form');assert.ok(t.d.getElementById('authority-results').textContent.includes('No authority records match'));t.d.getElementById('clear-authority-filter').click();assert.ok(t.d.getElementById('authority-results').textContent.includes('Promotion'));
  }finally{t.dom.window.close();}
});

test('reported evidence needing review remains inspectable even without applicable candidates',async()=>{
  const claim={fields:{current_rank:'Unassessed reported SP'},effective_from:null,mode:'SNAPSHOT',reported_dataset:'officer_service_information.csv'};
  const result={...answer,projections:[{...answer.projections[0],candidates:[],review:[claim]}]};
  const t=await setup(u=>u==='/api/research/history'?response(result):router(u));
  try{await selected(t);t.submit('history-form');await wait(()=>t.d.querySelector('.projection-grid'));assert.ok(t.d.getElementById('history-results').textContent.includes('Evidence needing review (1)'));assert.ok(t.d.getElementById('history-results').textContent.includes('Unassessed reported SP'));}finally{t.dom.window.close();}
});

test('recent requests recover a retained operation after reopening the officer without creating a new request',async()=>{
  const record={operation_id:'00000000-0000-0000-0000-000000000301',status:'PENDING_AUTHORITY',request_sha256:'f'.repeat(64),explanation:'Pending authority'};
  const t=await setup(u=>u.endsWith('/requests')?response({items:[record],limit:20}):u.startsWith('/api/research/requests/')?response(record):router(u));
  try{await selected(t);t.d.getElementById('load-recent-requests').click();await wait(()=>t.d.getElementById('recent-requests').querySelector('button'));t.d.getElementById('recent-requests').querySelector('button').click();await wait(()=>t.d.getElementById('request-status').textContent.includes(record.operation_id));assert.equal(t.d.getElementById('operation-id').value,record.operation_id);assert.equal(t.calls.filter(([u,o])=>u==='/api/research/requests'&&o.method==='POST').length,0);}finally{t.dom.window.close();}
});

test('a stalled submission reaches its deadline and retains the exact operation for read-only recovery',async()=>{
  const deadlines=[];let submissions=0;
  const t=await setup((u,o)=>u==='/api/research/requests'?new Promise((resolve,reject)=>{submissions++;o.signal.addEventListener('abort',()=>reject(Error('fixture deadline')),{once:true});}):router(u),w=>{
    w.setTimeout=(callback,delay)=>{assert.equal(delay,20000);deadlines.push(callback);return deadlines.length;};w.clearTimeout=()=>{};
  });
  try{await selected(t);t.d.getElementById('review-reason').value='Fixture deadline recovery';t.submit('review-form');await wait(()=>submissions===1);const operation=t.d.getElementById('operation-id').value;deadlines.at(-1)();await wait(()=>t.d.getElementById('review-message').textContent.includes('response was not received'));
    assert.equal(submissions,1);assert.equal(t.d.getElementById('operation-id').value,operation);assert.equal(t.d.getElementById('check-last-request').hidden,false);assert.equal(t.d.getElementById('review-button').textContent,'Retry the exact retained request');
  }finally{t.dom.window.close();}
});

test('connected detail names render safely and late replies cannot repopulate after sign-out',async()=>{
  let finish;const t=await setup(u=>u==='/api/research/browse'?new Promise(r=>{finish=()=>r(response({items:[{...officer,names:['<img src=x onerror=alert(1)>']}]}));}):router(u));
  try{t.d.getElementById('load-connected').click();await wait(()=>finish);t.d.getElementById('logout').click();finish();await new Promise(r=>setTimeout(r,20));assert.equal(t.d.getElementById('connected-results').textContent,'');assert.equal(t.d.querySelector('#connected-results img'),null);}finally{t.dom.window.close();}
});
test('connected officer names open their scoped workspace and clear on backgrounding',async()=>{
  const t=await setup(u=>u==='/api/research/browse'?response({items:[{...officer,details_available:true}]}):router(u));
  try{t.d.getElementById('load-connected').click();await wait(()=>t.d.querySelector('#connected-results button'));t.d.querySelector('#connected-results button').click();await wait(()=>!t.d.getElementById('workspace-body').hidden);Object.defineProperty(t.d,'hidden',{configurable:true,value:true});t.d.dispatchEvent(new t.dom.window.Event('visibilitychange'));assert.equal(t.d.getElementById('connected-results').textContent,'');assert.equal(t.d.getElementById('officer-name').textContent,'');}finally{t.dom.window.close();}
});
test('first query preserves exact microsecond knowledge boundary despite datetime input precision',async()=>{
  const end='2026-10-10T12:34:56.123456+00:00';const t=await setup(u=>u.startsWith('/api/research/officers/')?response({...workspace,coverage_start:end,coverage_end:end}):router(u));
  try{await selected(t);t.submit('history-form');await wait(()=>t.calls.some(([u])=>u==='/api/research/history'));assert.equal(JSON.parse(t.calls.find(([u])=>u==='/api/research/history')[1].body).known_at,end);await wait(()=>!t.d.getElementById('history-button').disabled);}finally{t.dom.window.close();}
});

test('fixed session countdown preserves full details beyond five minutes and clears them at thirty minutes',async()=>{
  const start=Date.now();let now=start;const intervals=[];
  const full={...workspace,expires_at:null,display_lifecycle:'RETAINED_LAST_VERIFIED_SNAPSHOT',full_records:[{dataset:'officer_personal_information.csv',raw_record_id:'f'.repeat(64),fields:{full_name:'Reported Officer',address:'<img src=x onerror=alert(1)>'}}]};
  const t=await setup(u=>u==='/api/auth/session'?response({username:'station.one',role:'STATION_OIC',scope_type:'STATION',scope_id:'S1',csrf_token:'csrf',server_time:start/1000,expires_at:start/1000+1800}):u.startsWith('/api/research/officers/')?response(full):router(u),window=>{
    const OriginalDate=window.Date;window.Date=class extends OriginalDate{constructor(...args){super(...(args.length?args:[now]));}static now(){return now;}};
    window.setInterval=callback=>{intervals.push(callback);return intervals.length;};
  });
  try{
    await selected(t);assert.ok(t.d.getElementById('session-countdown').textContent.includes('30:00'));
    assert.ok(t.d.getElementById('full-records').textContent.includes('<img src=x'));
    assert.equal(t.d.getElementById('full-records').querySelector('img'),null);
    now+=601000;intervals[0]();assert.ok(t.d.getElementById('session-countdown').textContent.includes('19:59'));
    assert.equal(t.d.getElementById('application').hidden,false);assert.ok(t.d.getElementById('full-records').textContent.includes('Reported Officer'));
    now=start+1800000;intervals[0]();assert.equal(t.d.getElementById('application').hidden,true);
    assert.equal(t.d.getElementById('full-records').textContent,'');assert.equal(t.d.getElementById('account-name').textContent,'');
    assert.equal(t.calls.filter(([u])=>u==='/api/auth/logout').length,0);
  }finally{t.dom.window.close();}
});


test('page-exit signal uses bounded authenticated keepalive and clears protected fields without logging out',async()=>{
  const t=await setup(router);try{await selected(t);t.dom.window.dispatchEvent(new t.dom.window.PageTransitionEvent('pagehide',{persisted:false}));
    const signal=t.calls.find(([u])=>u==='/api/accountability/session-signal');assert(signal);assert.equal(signal[1].keepalive,true);assert.equal(signal[1].headers['x-csrf-token'],'csrf');assert.deepEqual(JSON.parse(signal[1].body),{event:'PAGE_EXIT',page:'WORKSPACE',persisted:false});assert.equal(t.d.getElementById('officer-name').textContent,'');assert.equal(t.d.getElementById('account-name').textContent,'');assert.equal(t.d.getElementById('search-results').textContent,'');assert(!t.calls.some(([u])=>u==='/api/auth/logout'));
  }finally{t.dom.window.close();}
});

test('scope browser tables include all permitted identities and distinguish unavailable full details',async()=>{
 const other={...officer,officer_uid:'00000000-0000-0000-0000-000000000002',names:['<img src=x> Second'],nic:'000000002V',details_available:false};
 const t=await setup((u,o)=>u==='/api/research/browse'?response({items:[{...officer,details_available:true},other],total:2,scope_options:{DIVISION:['A'],STATION:['S1']}}):router(u));
 try{t.d.getElementById('load-connected').click();await wait(()=>t.d.querySelectorAll('#connected-results tbody tr').length===2);assert.equal(t.d.querySelectorAll('#connected-results button').length,1);assert.ok(t.d.getElementById('connected-results').textContent.includes('000000002V'));assert.ok(t.d.getElementById('connected-results').textContent.includes('Details unavailable'));assert.equal(t.d.querySelector('#connected-results img'),null);const b=JSON.parse(t.calls.find(([u])=>u==='/api/research/browse')[1].body);assert.equal(b.query,'');assert.equal(b.limit,25);assert.equal(b.availability,'ALL');assert.equal(Object.hasOwn(b,'role'),false);}finally{t.dom.window.close();}
});
test('scope browser filtering and paging preserve submitted criteria and clear private filters at logout',async()=>{
 const t=await setup((u,o)=>u==='/api/research/browse'?response({items:[{...officer,details_available:true}],total:50,scope_options:{DIVISION:['A','B']}}):router(u));
 try{t.d.getElementById('load-connected').click();await wait(()=>!t.d.getElementById('browse-button').disabled);t.d.getElementById('browse-query').value='Reported';t.d.getElementById('browse-level').value='DIVISION';t.d.getElementById('browse-level').dispatchEvent(new t.dom.window.Event('change'));t.d.getElementById('browse-scope').value='B';t.submit('browse-form');await wait(()=>t.calls.filter(([u])=>u==='/api/research/browse').length===2&&!t.d.getElementById('browse-button').disabled);t.d.getElementById('browse-query').value='Unsubmitted edit';t.d.getElementById('browse-next').click();await wait(()=>t.calls.filter(([u])=>u==='/api/research/browse').length===3);const b=JSON.parse(t.calls.filter(([u])=>u==='/api/research/browse')[2][1].body);assert.equal(b.offset,25);assert.equal(b.query,'Reported');assert.equal(b.scope_id,'B');t.d.getElementById('logout').click();assert.equal(t.d.getElementById('browse-query').value,'');assert.equal(t.d.getElementById('browse-scope').options.length,1);assert.equal(t.d.getElementById('connected-results').textContent,'');assert.equal(t.d.getElementById('officer-browser').hidden,true);await new Promise(r=>setTimeout(r,20));}finally{t.dom.window.close();}
});
test('late browser response cannot restore table or scoped filter values after background clearing',async()=>{
 let finish;const t=await setup(u=>u==='/api/research/browse'?new Promise(r=>finish=()=>r(response({items:[officer],total:1,scope_options:{DIVISION:['PRIVATE']}}))):router(u));
 try{t.d.getElementById('load-connected').click();await wait(()=>finish);Object.defineProperty(t.d,'hidden',{configurable:true,value:true});t.d.dispatchEvent(new t.dom.window.Event('visibilitychange'));finish();await new Promise(r=>setTimeout(r,20));assert.equal(t.d.getElementById('connected-results').textContent,'');assert.equal(t.d.getElementById('browse-scope').textContent,'All permitted scopes');assert.equal(t.d.getElementById('officer-browser').hidden,true);await new Promise(r=>setTimeout(r,20));}finally{t.dom.window.close();}
});

test('all-source profile shows full source values without inventing journal coverage',async()=>{
 const source={...workspace,evidence_view:'SIGNED_FULL_SOURCE_PROFILE',coverage_start:null,coverage_end:null,can_request_review:false,findings:[],full_records:[{dataset:'officer_service_information.csv',raw_record_id:'a'.repeat(64),fields:{current_station:'<img src=x> Station',current_police_no:'1234'}}]};
 const t=await setup(u=>u.startsWith('/api/research/officers/')?response(source):router(u));
 try{await selected(t);assert.ok(t.d.getElementById('full-records').textContent.includes('1234'));assert.equal(t.d.querySelector('#full-records img'),null);assert.equal(t.d.getElementById('history-button').disabled,true);assert.equal(t.d.getElementById('review-button').disabled,true);assert.ok(t.d.getElementById('history-results').textContent.includes('not connected'));}finally{t.dom.window.close();}
});
test('table shows reported posting rather than simulated access membership',async()=>{
 const t=await setup(u=>u==='/api/research/browse'?response({items:[{...officer,details_available:true,membership:{DIVISION:'RESEARCH_DIVISION_A',STATION:'RESEARCH_STATION_A'},reported_posting:{division:'Reported division',station:'Reported Police Station'}}],total:1}):router(u));
 try{t.d.getElementById('load-connected').click();await wait(()=>t.d.querySelector('#connected-results tbody tr'));const text=t.d.getElementById('connected-results').textContent;assert.ok(text.includes('Reported Police Station'));assert.equal(text.includes('RESEARCH_DIVISION_A'),false);t.d.querySelector('#connected-results tbody tr td:nth-child(2)').click();await wait(()=>!t.d.getElementById('workspace-body').hidden);assert.equal(t.calls.filter(([u])=>u.startsWith('/api/research/officers/')).length,1);}finally{t.dom.window.close();}
});
