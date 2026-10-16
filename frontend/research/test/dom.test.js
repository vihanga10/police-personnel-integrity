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
test('application anchoring observations are separate, text-safe and cleared at logout',async()=>{const t=await setup(u=>u.endsWith('/application-anchoring')?response({scope:'APPLICATION_FINDINGS_PREFIX_ONLY',status:'BOTH_CHAINS_VERIFIED',entry_count:3,observed_at:1791882000,publication_id:'<img src=x onerror=alert(1)>',fabric_transaction_id:'a'.repeat(64),public_transaction_id:'0x'+'b'.repeat(64)}):router(u));try{await selected(t);t.d.getElementById('tab-anchoring').click();await wait(()=>t.d.getElementById('application-anchoring-results').textContent.includes('3 saved'));const root=t.d.getElementById('application-anchoring-results');assert.ok(root.textContent.includes('not checked the live chains'));assert.equal(root.querySelector('img'),null);t.d.getElementById('logout').click();assert.equal(root.textContent,'');await wait(()=>t.d.getElementById('login-message').textContent.includes('Signed out securely'));}finally{t.dom.window.close();}});
test('late application anchoring observation cannot repopulate a signed-out screen',async()=>{let release;const t=await setup(u=>u.endsWith('/application-anchoring')?new Promise(resolve=>{release=()=>resolve(response({scope:'APPLICATION_FINDINGS_PREFIX_ONLY',status:'NOT_OBSERVED',entry_count:99}));}):router(u));try{await selected(t);t.d.getElementById('tab-anchoring').click();await wait(()=>release);t.d.getElementById('logout').click();release();await new Promise(r=>setTimeout(r,30));assert.equal(t.d.getElementById('application-anchoring-results').textContent,'');}finally{t.dom.window.close();}});
test('historical values and finding explanations render as text without HTML injection',async()=>{const t=await setup(router);try{await selected(t);t.d.getElementById('tab-history').click();t.submit('history-form');await wait(()=>t.d.querySelector('.projection-grid'));assert.ok(t.d.getElementById('history-results').textContent.includes('<img src=x'));assert.equal(t.d.getElementById('history-results').querySelector('img'),null);assert.ok(t.d.getElementById('contradiction-results').textContent.includes('does not establish agreement'));}finally{t.dom.window.close();}});
test('Colombo local time is converted explicitly; query never sends role or scope',async()=>{const t=await setup(router);try{await selected(t);t.d.getElementById('query-timezone').value='COLOMBO';t.d.getElementById('known-date').value='2026-10-10T05:30';t.submit('history-form');await wait(()=>t.calls.some(([u])=>u==='/api/research/history'));const body=JSON.parse(t.calls.find(([u])=>u==='/api/research/history')[1].body);assert.equal(body.known_at,'2026-10-10T00:00:00.000Z');assert.deepEqual(Object.keys(body).sort(),['effective_on','known_at','officer_uid']);await wait(()=>!t.d.getElementById('history-button').disabled);}finally{t.dom.window.close();}});
test('a withheld officer cannot show an old workspace after selection',async()=>{let allow=true;const t=await setup(u=>u.startsWith('/api/research/officers/')?allow?response(workspace):response({error:'DETAILS_WITHHELD'},403):router(u));try{await selected(t);allow=false;t.d.querySelector('.officer-result').click();await wait(()=>t.d.getElementById('workspace-state').textContent.includes('withheld'));assert.equal(t.d.getElementById('workspace-body').hidden,true);assert.equal(t.d.getElementById('findings-results').textContent,'');}finally{t.dom.window.close();}});
test('uncertain review submission is never automatically retried; manual retry retains exact operation and content',async()=>{let attempts=0;const t=await setup((u,o)=>{if(u==='/api/research/requests'){attempts++;if(attempts===1)throw Error('lost response');const b=JSON.parse(o.body);return response({operation_id:b.operation_id,request_sha256:'e'.repeat(64),status:'PENDING_AUTHORITY',explanation:'Request retained, pending authority.'});}return router(u);});try{await selected(t);t.d.getElementById('review-reason').value='Evidence needs assessment.';t.submit('review-form');await wait(()=>t.d.getElementById('review-message').textContent.includes('Operation ID'));await wait(()=>!t.d.getElementById('review-button').disabled);assert.equal(attempts,1);t.d.getElementById('review-reason').value='Changed while the acknowledgement was unknown';t.submit('review-form');await wait(()=>t.d.getElementById('request-status').textContent.includes('pending authority'));const calls=t.calls.filter(([u])=>u==='/api/research/requests');assert.equal(calls[0][1].body,calls[1][1].body);assert.equal(t.dom.window.localStorage.length,0);assert.equal(t.dom.window.sessionStorage.length,0);}finally{t.dom.window.close();}});
test('double-click review submission has one request',async()=>{let release;const t=await setup((u,o)=>u==='/api/research/requests'?new Promise(resolve=>{release=()=>resolve(response({operation_id:JSON.parse(o.body).operation_id,request_sha256:'e'.repeat(64),status:'PENDING_AUTHORITY',explanation:'Pending authority'}));}):router(u));try{await selected(t);t.d.getElementById('review-reason').value='Fixture reason';t.submit('review-form');t.submit('review-form');await wait(()=>release);assert.equal(t.calls.filter(([u])=>u==='/api/research/requests').length,1);release();await wait(()=>t.d.getElementById('review-message').textContent.includes('Request retained'));}finally{t.dom.window.close();}});
test('logout clears private identity, finding, query and account text from the DOM',async()=>{const t=await setup(router);try{await selected(t);t.d.getElementById('logout').click();await wait(()=>t.d.getElementById('login-message').textContent.includes('Signed out securely'));assert.ok(!t.d.body.textContent.includes(officer.nic));assert.ok(!t.d.body.textContent.includes(officer.names[0]));assert.ok(!t.d.body.textContent.includes('station.one'));assert.equal(t.d.getElementById('review-finding').children.length,0);}finally{t.dom.window.close();}});
test('a late officer response cannot reopen a closed workspace',async()=>{let finish;const t=await setup(u=>u.startsWith('/api/research/officers/')?new Promise(r=>{finish=()=>r(response(workspace));}):router(u));try{t.d.getElementById('search-query').value='000000001V';t.submit('search-form');await wait(()=>t.d.querySelector('.officer-result'));t.d.querySelector('.officer-result').click();await wait(()=>finish);t.d.getElementById('close-officer').click();finish();await new Promise(r=>setTimeout(r,20));assert.equal(t.d.getElementById('officer-workspace').hidden,true);assert.equal(t.d.getElementById('workspace-body').hidden,true);}finally{t.dom.window.close();}});
test('first-party React sources have no unsafe HTML sink or browser persistence',()=>{const js=['src/controllers/app.js','src/controllers/reviews.js','src/controllers/accountability.js','src/charts.jsx','src/entry.jsx',...['Officers','Reviews','Accountability'].map(n=>'src/pages/'+n+'.jsx')].map(n=>fs.readFileSync(path.join(root,n),'utf8')).join('\n');const html=fs.readFileSync(path.join(root,'index.html'),'utf8');assert.ok(!/innerHTML|insertAdjacentHTML|document\.write|localStorage\.|sessionStorage\./.test(js));assert.ok(!/<script[^>]+src="https?:/.test(html));assert.ok(/prefers-reduced-motion/.test(fs.readFileSync(path.join(root,'styles.css'),'utf8')));assert.ok(/max-width:600px/.test(fs.readFileSync(path.join(root,'styles.css'),'utf8')));});

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
 try{t.d.getElementById('load-connected').click();await wait(()=>t.d.querySelectorAll('#connected-results tbody tr').length===2);assert.equal(t.d.querySelectorAll('#connected-results button').length,1);assert.ok(t.d.getElementById('connected-results').textContent.includes('000000002V'));assert.ok(t.d.getElementById('connected-results').textContent.includes('Details unavailable'));assert.equal(t.d.querySelector('#connected-results img'),null);const b=JSON.parse(t.calls.find(([u,o])=>u==='/api/research/browse'&&JSON.parse(o.body).limit===25)[1].body);assert.equal(b.query,'');assert.equal(b.limit,25);assert.equal(b.availability,'ALL');assert.equal(Object.hasOwn(b,'role'),false);}finally{t.dom.window.close();}
});
test('scope browser filtering and paging preserve submitted criteria and clear private filters at logout',async()=>{
 const t=await setup((u,o)=>u==='/api/research/browse'?response({items:[{...officer,details_available:true}],total:50,scope_options:{DIVISION:['A','B']}}):router(u));
 try{t.d.getElementById('load-connected').click();await wait(()=>!t.d.getElementById('browse-button').disabled);t.d.getElementById('browse-query').value='Reported';t.d.getElementById('browse-level').value='DIVISION';t.d.getElementById('browse-level').dispatchEvent(new t.dom.window.Event('change'));t.d.getElementById('browse-scope').value='B';t.submit('browse-form');await wait(()=>t.calls.filter(([u,o])=>u==='/api/research/browse'&&JSON.parse(o.body).limit===25).length===2&&!t.d.getElementById('browse-button').disabled);t.d.getElementById('browse-query').value='Unsubmitted edit';t.d.getElementById('browse-next').click();await wait(()=>t.calls.filter(([u,o])=>u==='/api/research/browse'&&JSON.parse(o.body).limit===25).length===3);const b=JSON.parse(t.calls.filter(([u,o])=>u==='/api/research/browse'&&JSON.parse(o.body).limit===25)[2][1].body);assert.equal(b.offset,25);assert.equal(b.query,'Reported');assert.equal(b.scope_id,'B');t.d.getElementById('logout').click();assert.equal(t.d.getElementById('browse-query').value,'');assert.equal(t.d.getElementById('browse-scope').options.length,1);assert.equal(t.d.getElementById('connected-results').textContent,'');assert.equal(t.d.getElementById('officer-browser').hidden,true);await new Promise(r=>setTimeout(r,20));}finally{t.dom.window.close();}
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

test('open details shows and focuses profile immediately; back restores the table and filters',async()=>{
 const t=await setup(u=>u==='/api/research/browse'?response({items:[{...officer,details_available:true}],total:1}):router(u));
 try{t.d.getElementById('load-connected').click();await wait(()=>t.d.querySelector('#connected-results button'));t.d.getElementById('browse-query').value='Reported';t.d.querySelector('#connected-results button').click();assert.equal(t.d.getElementById('officer-selector').hidden,true);assert.equal(t.d.getElementById('officer-workspace').hidden,false);assert.equal(t.d.activeElement.id,'officer-name');await wait(()=>!t.d.getElementById('workspace-body').hidden);t.d.getElementById('close-officer').click();assert.equal(t.d.getElementById('officer-selector').hidden,false);assert.equal(t.d.getElementById('officer-workspace').hidden,true);assert.equal(t.d.querySelectorAll('#connected-results tbody tr').length,1);assert.equal(t.d.getElementById('browse-query').value,'Reported');assert.equal(t.d.activeElement.id,'browse-query');}finally{t.dom.window.close();}
});
test('open details failure is visible in the focused workspace and permits return to table',async()=>{
 const t=await setup(u=>u==='/api/research/browse'?response({items:[{...officer,details_available:true}],total:1}):u.startsWith('/api/research/officers/')?response({error:'DETAILS_WITHHELD'},403):router(u));
 try{t.d.getElementById('load-connected').click();await wait(()=>t.d.querySelector('#connected-results button'));t.d.querySelector('#connected-results button').click();await wait(()=>t.d.getElementById('workspace-state').textContent.includes('withheld'));assert.equal(t.d.getElementById('officer-selector').hidden,true);assert.equal(t.d.getElementById('officer-workspace').hidden,false);assert.equal(t.d.getElementById('workspace-body').hidden,true);t.d.getElementById('close-officer').click();assert.equal(t.d.getElementById('officer-selector').hidden,false);}finally{t.dom.window.close();}
});

test('personal and service source sections appear first and expanded',async()=>{
 const source={...workspace,evidence_view:'SIGNED_FULL_SOURCE_PROFILE',coverage_start:null,coverage_end:null,can_request_review:false,findings:[],full_records:['operations.csv','officer_service_information.csv','officer_personal_information.csv'].map((dataset,i)=>({dataset,raw_record_id:String(i).repeat(64),fields:{reported_value:'Source text'}}))};
 const t=await setup(u=>u.startsWith('/api/research/officers/')?response(source):router(u));
 try{await selected(t);const sections=[...t.d.querySelectorAll('#full-records > details')];assert.ok(sections[0].querySelector('summary').textContent.includes('Officer personal information'));assert.ok(sections[1].querySelector('summary').textContent.includes('Officer service information'));assert.equal(sections[0].open,true);assert.equal(sections[1].open,true);assert.equal(sections[2].open,false);}finally{t.dom.window.close();}
});

test('new baseline history uses the exact recorded boundary after changing time zone',async()=>{
 const boundary='2026-10-13T03:00:00.123456+00:00';
 const baseline={...workspace,coverage_start:boundary,coverage_end:boundary,findings:[],can_request_review:false,historical_workspace_available:true};
 const t=await setup(u=>u.startsWith('/api/research/officers/')?response(baseline):router(u));
 try{await selected(t);assert.equal(t.d.getElementById('history-button').disabled,false);assert.ok(t.d.getElementById('coverage-label').textContent.includes(boundary));assert.ok(t.d.getElementById('coverage-label').textContent.includes('earlier effective dates'));
 t.d.getElementById('query-timezone').value='COLOMBO';t.d.getElementById('known-date').value='2020-01-01T00:00';t.d.getElementById('use-recorded-boundary').click();assert.equal(t.d.getElementById('query-timezone').value,'UTC');
 t.d.getElementById('effective-date').value='2024-12-31';t.submit('history-form');await wait(()=>t.calls.some(([u])=>u==='/api/research/history'));
 const body=JSON.parse(t.calls.find(([u])=>u==='/api/research/history')[1].body);assert.equal(body.known_at,boundary);assert.equal(body.effective_on,'2024-12-31');assert.equal(t.d.getElementById('review-button').disabled,true);await wait(()=>!t.d.getElementById('history-button').disabled);
 }finally{t.dom.window.close();}
});

test('recorded-boundary selection never enables an unconnected source history',async()=>{
 const source={...workspace,evidence_view:'SIGNED_FULL_SOURCE_PROFILE',coverage_start:null,coverage_end:null,findings:[],can_request_review:false};
 const t=await setup(u=>u.startsWith('/api/research/officers/')?response(source):router(u));
 try{await selected(t);t.d.getElementById('use-recorded-boundary').click();assert.equal(t.d.getElementById('history-button').disabled,true);t.submit('history-form');assert.equal(t.calls.filter(([u])=>u==='/api/research/history').length,0);
 }finally{t.dom.window.close();}
});

const authorityAnswer={known_at:'2026-10-13T06:00:00.123456Z',total:1,offset:0,limit:25,items:[{
 action_reference:'a'.repeat(64),action_type:'AUTHORIZE_PROMOTION',action_on:'2024-01-01',status:'VALID',mode:'EXPLICIT_ASSESSED_INPUTS',
 reasons:['EXPLICIT_RESEARCH_ASSESSMENT'],actors:[{identity:null,on:'2024-01-01',state_reference:'b'.repeat(64),assessment_supplied:true}],
 rules:[{reference:'<img src=x>',powers:['AUTHORIZE_PROMOTION'],ranks:['SP'],roles:['Reviewed role'],actor_scopes:['Reviewed scope'],target_scopes:['Reviewed target'],start:'2020-01-01',end:null,may_delegate:true}],
 delegations:[{reference:'Delegation D1',parent_reference:'Rule R1',issuer:null,recipient:null,powers:['AUTHORIZE_PROMOTION'],target_scopes:['Reviewed target'],issued_on:'2023-01-01',start:'2023-01-01',end:null,revoked_from:null}],
 successful_paths:['Delegation D1'],assessment_versions:[{reference:'c'.repeat(64),recorded_at:'2026-10-13T05:59:00Z',version:1,supersedes:null}],
 assessment_reference:'c'.repeat(64),source_reference:'d'.repeat(64),destination_reference:'e'.repeat(64),dataset:'promotion_history.csv'}]};
const comparisonAnswer={effective_on:'2024-12-31',known_at:'2026-10-10T00:00:00Z',generation:1,query_digest:'a'.repeat(64),comparison_digest:'b'.repeat(64),
 total:1,unfiltered_total:1,offset:0,limit:25,excluded_versions:[{reference:'c'.repeat(64),reason:'WITHDRAWN'}],items:[{dimension:'rank',status:'REPORTED_CONTRADICTION_CANDIDATE',
 cross_reported_source:true,reasons:['SOURCE_INDEPENDENCE_UNVERIFIED'],comparison_reference:'d'.repeat(64),version_references:['e'.repeat(64),'f'.repeat(64)],destination_references:['a'.repeat(64)],receipt_references:['b'.repeat(64)],evidence:[]}]};

test('operational authority tab inspects rules, delegation dates and retained versions safely',async()=>{
 const t=await setup((u,o)=>u.startsWith('/api/research/officers/')?response({...workspace,priority2_available:true}):u==='/api/research/authority'?response(authorityAnswer):router(u,o));
 try{await selected(t);t.d.getElementById('tab-authority').click();await wait(()=>t.d.getElementById('authority-message').textContent.includes('1 reported actions'));const root=t.d.getElementById('authority-workflow-results');assert.ok(root.textContent.includes('Delegation D1'));assert.ok(root.textContent.includes('2023-01-01'));assert.ok(root.textContent.includes('No police action is approved'));assert.ok(root.textContent.includes('<img src=x>'));assert.equal(root.querySelector('img'),null);
 const body=JSON.parse(t.calls.find(([u])=>u==='/api/research/authority')[1].body);assert.equal(body.known_at,null);assert.deepEqual(Object.keys(body).sort(),['action_on','known_at','limit','officer_uid','offset','status']);
 }finally{t.dom.window.close();}
});

test('direct contradiction form filters reported sources and retains explicit evidence bindings',async()=>{
 const t=await setup((u,o)=>u==='/api/research/contradictions'?response(comparisonAnswer):router(u,o));
 try{await selected(t);t.d.getElementById('contradiction-effective').value='2024-12-31';t.d.getElementById('contradiction-zone').value='COLOMBO';t.d.getElementById('contradiction-known').value='2026-10-10T05:30';t.d.getElementById('contradiction-source').value='CROSS_REPORTED';t.submit('contradiction-form');await wait(()=>!t.d.getElementById('contradiction-button').disabled);
 const body=JSON.parse(t.calls.find(([u])=>u==='/api/research/contradictions')[1].body);assert.equal(body.known_at,'2026-10-10T00:00:00.000Z');assert.equal(body.relationship,'CROSS_REPORTED');assert.equal(body.dimension,'ALL');const text=t.d.getElementById('contradiction-results').textContent;assert.ok(text.includes('Different reported sources'));assert.ok(text.includes('Recorded receipts'));assert.ok(text.includes('Withdrawn'));assert.ok(text.includes('do not establish an accepted contradiction'));
 }finally{t.dom.window.close();}
});

test('late authority response cannot reveal actor or assessment details after logout',async()=>{
 let finish;const t=await setup((u,o)=>u.startsWith('/api/research/officers/')?response({...workspace,priority2_available:true}):u==='/api/research/authority'?new Promise(r=>{finish=()=>r(response(authorityAnswer));}):router(u,o));
 try{await selected(t);t.d.getElementById('tab-authority').click();await wait(()=>finish);t.d.getElementById('logout').click();finish();await wait(()=>t.d.getElementById('login-message').textContent.includes('Signed out securely'));await new Promise(r=>setTimeout(r,20));assert.equal(t.d.getElementById('authority-workflow-results').textContent,'');assert.equal(t.d.getElementById('authority-known').value,'');assert.equal(t.d.getElementById('authority-message').textContent,'');
 }finally{t.dom.window.close();}
});

test('late contradiction response cannot replace the next officer or background-cleared page',async()=>{
 let finish;const t=await setup((u,o)=>u==='/api/research/contradictions'?new Promise(r=>{finish=()=>r(response(comparisonAnswer));}):router(u,o));
 try{await selected(t);t.submit('contradiction-form');await wait(()=>finish);Object.defineProperty(t.d,'hidden',{configurable:true,value:true});t.d.dispatchEvent(new t.dom.window.Event('visibilitychange'));finish();await new Promise(r=>setTimeout(r,20));assert.equal(t.d.getElementById('contradiction-results').textContent,'');assert.equal(t.d.getElementById('contradiction-effective').value,'');assert.equal(t.d.getElementById('contradiction-message').textContent,'');
 }finally{t.dom.window.close();}
});


test('unit SDIG dashboard uses returned counts, CID label and accessible marker',async()=>{
 const t=await setup((u,o)=>u==='/api/auth/session'?response({username:'research.sdig',role:'SDIG',scope_type:'UNIT',scope_id:'CID',csrf_token:'csrf'}):u==='/api/research/unit-dashboard'?response({unit:'CID',unit_label:'CID',officers:150,details_available:150,divisions:1,status_counts:{Active:140,Interdicted:10},rank_counts:{'Senior Deputy Inspector General of Police':1,'Sub Inspector of Police':27},latest_copy_issued_at:1791900000}):u==='/api/research/browse'?response({items:[{...officer,unit_type:'CID',details_available:true}],total:150,scope_options:{}}):response({}));
 try{await wait(()=>t.d.getElementById('dashboard-metrics').textContent.includes('150'));assert.equal(t.d.getElementById('account-scope').textContent,'CID unit');assert.equal(t.d.getElementById('unit-dashboard-title').textContent,'CID officer dashboard');assert.equal(t.d.querySelector('.research-label'),null);t.d.getElementById('load-connected').click();await wait(()=>t.d.querySelector('.unit-marker'));assert.equal(t.d.querySelector('.unit-marker').getAttribute('aria-label'),'CID officer');t.d.getElementById('logout').click();assert.equal(t.d.getElementById('dashboard-metrics').textContent,'');assert.equal(t.d.getElementById('unit-dashboard').hidden,true);await wait(()=>t.d.getElementById('login-message').textContent.includes('Signed out'));}finally{t.dom.window.close();}
});
test('late dashboard cannot restore counts after page becomes hidden',async()=>{
 let finish;const t=await setup(u=>u==='/api/auth/session'?response({username:'research.sdig',role:'SDIG',scope_type:'UNIT',scope_id:'CID',csrf_token:'csrf'}):u==='/api/research/unit-dashboard'?new Promise(r=>{finish=()=>r(response({unit_label:'CID',officers:150,details_available:150,divisions:1,status_counts:{Active:150},rank_counts:{}}));}):response({}));
 try{await wait(()=>finish);Object.defineProperty(t.d,'hidden',{configurable:true,value:true});t.d.dispatchEvent(new t.dom.window.Event('visibilitychange'));finish();await new Promise(r=>setTimeout(r,20));assert.equal(t.d.getElementById('dashboard-metrics').textContent,'');assert.equal(t.d.getElementById('unit-dashboard').hidden,true);}finally{t.dom.window.close();}
});
test('login sends authenticator code only to authentication and clears it on success',async()=>{
 const t=await setup(router);try{t.d.getElementById('logout').click();await wait(()=>t.d.getElementById('login-message').textContent.includes('Signed out'));t.d.getElementById('username').value='research.sdig';t.d.getElementById('password').value='fixture-password';t.d.getElementById('totp-code').value='123456';t.submit('login-form');await wait(()=>!t.d.getElementById('application').hidden);const login=t.calls.find(([u])=>u==='/api/auth/login');assert.equal(JSON.parse(login[1].body).totp_code,'123456');assert.equal(t.d.getElementById('totp-code').value,'');assert.equal(t.d.getElementById('totp-code').getAttribute('autocomplete'),'one-time-code');}finally{t.dom.window.close();}
});

test('selected profile hides directory heading and uses an accessible external back arrow',async()=>{
 const t=await setup(router);try{await selected(t);assert.equal(t.d.querySelector('.page-heading').hidden,true);const back=t.d.getElementById('close-officer');assert.equal(back.getAttribute('aria-label'),'Back to officers');assert.ok(back.querySelector('svg'));assert.equal(back.closest('.officer-header'),null);assert.equal(back.parentElement.id,'officer-workspace');back.click();assert.equal(t.d.querySelector('.page-heading').hidden,false);assert.equal(t.d.getElementById('officer-workspace').hidden,true);}finally{t.dom.window.close();}
});
test('source tables retain every heterogeneous field, falsy value and exact reference safely',async()=>{
 const records=[{dataset:'officer_personal_information.csv',fields:{name:'<img src=x onerror=alert(1)>',age:0,active:false},raw_record_id:'a'.repeat(64)},{dataset:'officer_personal_information.csv',fields:{name:'Second reported row',extra:'Additional source value'},raw_record_id:'b'.repeat(64)}];
 const t=await setup(u=>u.startsWith('/api/research/officers/')?response({...workspace,full_records:records}):router(u));try{await selected(t);const root=t.d.getElementById('full-records');assert.equal(root.querySelector('h3').textContent,'Officer Overview');const wrap=root.querySelector('[role=region]');assert.equal(wrap.tabIndex,0);assert.ok(t.d.getElementById(wrap.getAttribute('aria-labelledby')));const table=wrap.querySelector('table');assert.equal(table.querySelectorAll('tbody tr').length,2);assert.ok(table.textContent.includes('Additional source value'));assert.ok(table.textContent.includes('false'));assert.ok(table.textContent.includes('<img src=x'));assert.equal(table.querySelector('img'),null);assert.equal(table.querySelectorAll('tbody tr')[0].children[2].textContent,'0');assert.ok(table.textContent.includes('a'.repeat(64)));assert.ok(table.textContent.includes('b'.repeat(64)));t.d.getElementById('logout').click();assert.equal(root.textContent,'');await wait(()=>t.d.getElementById('login-message').textContent.includes('Signed out securely'));}finally{t.dom.window.close();}
});

test('uncertain authority shows simple meanings and preserves every technical reason and evidence reference',async()=>{
 const reasons=['ACTION_DATE_SEMANTICS_UNASSESSED','ACTOR_IDENTITY_UNRESOLVED','ACTOR_HISTORY_IDENTITY_UNRESOLVED','GOVERNING_RULE_UNASSESSED','DELEGATION_EVIDENCE_UNASSESSED','GEOGRAPHIC_AND_POWER_SCOPE_UNASSESSED','FUTURE_UNKNOWN_CODE','<img src=x onerror=alert(1)>'];
 const item={...authorityAnswer.items[0],status:'CANNOT_VERIFY',mode:'REPORTED_INPUTS_ONLY',actors:[],rules:[],delegations:[],assessment_versions:[],assessment_reference:null,successful_paths:[],reasons};
 const t=await setup(u=>u.startsWith('/api/research/officers/')?response({...workspace,priority2_available:true}):u==='/api/research/authority'?response({...authorityAnswer,items:[item]}):router(u));
 try{await selected(t);t.d.getElementById('tab-authority').click();await wait(()=>t.d.querySelector('.authority-explanation'));const root=t.d.getElementById('authority-workflow-results'),box=root.querySelector('.authority-explanation');assert.ok(box.textContent.includes('Why cannot verify?'));assert.ok(box.textContent.includes('has not been reliably linked'));assert.ok(box.textContent.includes('does not mean the action was invalid'));assert.ok(box.textContent.includes('may not be needed'));
 const technical=box.querySelector('details');assert.equal(technical.open,false);for(const code of reasons)assert.ok([...technical.querySelectorAll('code')].some(n=>n.textContent===code));assert.equal(box.querySelector('img'),null);assert.ok(root.textContent.includes(item.source_reference));assert.ok(root.textContent.includes('0 rules, 0 delegations'));
 t.d.getElementById('logout').click();assert.equal(root.textContent,'');await wait(()=>t.d.getElementById('login-message').textContent.includes('Signed out'));
 }finally{t.dom.window.close();}
});
test('valid authority keeps the algorithm outcome without an uncertainty explanation',async()=>{
 const t=await setup(u=>u.startsWith('/api/research/officers/')?response({...workspace,priority2_available:true}):u==='/api/research/authority'?response(authorityAnswer):router(u));
 try{await selected(t);t.d.getElementById('tab-authority').click();await wait(()=>t.d.getElementById('authority-message').textContent.includes('1 reported actions'));const root=t.d.getElementById('authority-workflow-results');assert.ok(root.textContent.includes('Authority assessment: valid'));assert.equal(root.querySelector('.authority-explanation'),null);assert.ok(root.textContent.includes('Delegation D1'));}finally{t.dom.window.close();}
});
test('legacy authority cards also explain uncertainty without changing their status',async()=>{
 const t=await setup(u=>u.startsWith('/api/research/officers/')?response({...workspace,authority:[{action_type:'AUTHORIZE_TRANSFER',action_on:'2024-01-01',status:'CANNOT_VERIFY',reasons:['GOVERNING_RULE_UNASSESSED'],assessment_receipt_sha256:'f'.repeat(64)}]}):router(u));
 try{await selected(t);const root=t.d.getElementById('authority-results');assert.ok(root.textContent.includes('Why cannot verify?'));assert.ok(root.textContent.includes('has not been assessed'));assert.ok(root.textContent.includes('f'.repeat(64)));}finally{t.dom.window.close();}
});

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
