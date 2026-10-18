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
const claim=(value,from='2020-01-01')=>({fields:{to_rank:value},effective_from:from,mode:'EVENT',reported_dataset:'transfer_history',reasons:[]});
const projection=(dimension,candidates,review=[],reasons=['HISTORICAL_IDENTITY_UNASSESSED','AUTHORITY_AND_DELEGATION_UNASSESSED'])=>({dimension,status:'CANNOT_VERIFY',candidates,supporting:[],review,future:[],expired:[],reasons});
const answerFor=(known,projections)=>({effective_on:'2021-01-01',known_at:known,query_digest:'c'.repeat(64),comparison_digest:'d'.repeat(64),projections,versions:[],comparisons:[]});
const late=answerFor('2026-10-10T00:00:00Z',[projection('rank',[claim('Chief Inspector','2020-01-01')]),projection('posting',[],[claim('S1'),claim('S2')]),projection('police_number',[claim('A'),claim('B')])]);
const early=answerFor('2026-10-05T00:00:00Z',[projection('rank',[claim('Inspector','2015-01-01')]),projection('posting',[],[claim('S1'),claim('S2')]),projection('police_number',[claim('A'),claim('B')])]);
function router(overrides={}){return (url,options)=>{if(overrides[url])return overrides[url](options);if(url==='/api/auth/session')return response({username:'station.one',role:'STATION_OIC',scope_type:'STATION',scope_id:'S1',csrf_token:'csrf'});
  if(url==='/api/officers/search')return response({items:[officer],total:1});if(url==='/api/research/history'){const known=JSON.parse(options.body).known_at;return response(known.startsWith('2026-10-05')?early:late);}
  if(url.startsWith('/api/research/officers/'))return response(workspace);return response({authenticated:false});};}
async function setup(handler){
  const dom=new JSDOM(fs.readFileSync(path.join(root,'index.html'),'utf8'),{url:'https://access.test:9443',runScripts:'outside-only',pretendToBeVisual:true});
  const calls=[];dom.window.fetch=async(url,options)=>{calls.push([url,options]);return handler(url,options);};dom.window.eval(fs.readFileSync(path.join(root,'app.js'),'utf8'));
  await wait(()=>!dom.window.document.getElementById('application').hidden);
  const d=dom.window.document,submit=id=>d.getElementById(id).dispatchEvent(new dom.window.Event('submit',{bubbles:true,cancelable:true}));
  d.getElementById('search-query').value='000000001V';submit('search-form');await wait(()=>d.querySelector('.officer-result'));d.querySelector('.officer-result').click();await wait(()=>!d.getElementById('workspace-body').hidden);
  return {dom,d,calls,submit};
}
async function ask(t,known='2026-10-10T00:00'){t.d.getElementById('effective-date').value='2021-01-01';t.d.getElementById('known-date').value=known;t.d.getElementById('query-timezone').value='UTC';t.submit('history-form');await wait(()=>t.d.querySelector('.answer-box'));}
const settle=()=>new Promise(r=>setTimeout(r,60));
test('the answer box leads with the value, the date it applies from, and an honest status',async()=>{
  const t=await setup(router());try{await ask(t);const box=t.d.querySelector('.answer-box').textContent;
    assert(box.includes('Chief Inspector')&&box.includes('since 2020-01-01')&&box.includes('reported, not verified'));
    assert(box.includes('Not established')&&box.includes('2 records need review'));assert(box.includes('Several reported candidates (2)'));
    assert.equal(t.d.querySelectorAll('.answer-box details').length,1);assert(t.d.querySelector('.answer-box details summary').textContent==='Limits of this answer');
    assert(t.d.querySelector('.projection-grid').textContent.includes('Chief Inspector'),'the detailed card still carries the same value');
  }finally{await settle();t.dom.window.close();}});
test('repeated caveats are collapsed: no per-card paragraph, reasons sit behind one expandable line',async()=>{
  const t=await setup(router());try{await ask(t);const grid=t.d.querySelector('.projection-grid');
    assert(!grid.textContent.includes('Why cannot verify?'));const why=[...grid.querySelectorAll('details summary')].filter(s=>s.textContent.startsWith('Why this is not verified'));
    assert.equal(why.length,3);assert.equal(why[0].textContent,'Why this is not verified (2)');assert(why[0].parentElement.open===false);
  }finally{await settle();t.dom.window.close();}});
test('compare shows the same question as known on two dates and marks what changed',async()=>{
  const t=await setup(router());try{await ask(t);t.d.getElementById('compare-known-date').value='2026-10-05T00:00';t.d.getElementById('compare-button').click();
    await wait(()=>t.d.querySelector('#compare-results table'));const text=t.d.getElementById('compare-results').textContent;
    assert(text.includes('Inspector')&&text.includes('Chief Inspector')&&text.includes('Changed')&&text.includes('1 item differ'));
    const rows=[...t.d.querySelectorAll('#compare-results tbody tr')].map(r=>r.lastElementChild.textContent);assert.deepEqual(rows,['Changed','Same','Same']);
    const call=t.calls.filter(([u])=>u==='/api/research/history').pop();assert.equal(JSON.parse(call[1].body).known_at,'2026-10-05T00:00:00.000Z');assert.equal(JSON.parse(call[1].body).effective_on,'2021-01-01');
    t.d.getElementById('compare-known-date').value='2026-10-10T00:00';t.d.getElementById('compare-button').click();
    await wait(()=>t.d.getElementById('compare-results').textContent.includes('No difference'));
  }finally{await settle();t.dom.window.close();}});
test('compare needs a first answer and shows a server refusal instead of a table',async()=>{
  const t=await setup(router({}));try{t.d.getElementById('compare-known-date').value='2026-10-05T00:00';t.d.getElementById('compare-button').click();await settle();
    assert(t.d.getElementById('compare-message').textContent.includes('Run the historical query first'));
    await ask(t);t.dom.window.fetch=async(u,o)=>u==='/api/research/history'?response({error:'KNOWN_AT_OUTSIDE_COVERAGE'},422):router()(u,o);
    t.d.getElementById('compare-known-date').value='2026-09-01T00:00';t.d.getElementById('compare-button').click();await wait(()=>t.d.getElementById('compare-message').textContent!=='');
    assert.equal(t.d.querySelector('#compare-results table'),null);assert(!t.d.getElementById('compare-message').textContent.includes('undefined'));
  }finally{await settle();t.dom.window.close();}});
test('a new query or closing the officer clears an old comparison; values render as text',async()=>{
  const evil=answerFor('2026-10-10T00:00:00Z',[projection('rank',[claim('<img src=x onerror=alert(1)>')])]);
  const t=await setup(router({'/api/research/history':o=>response(JSON.parse(o.body).known_at.startsWith('2026-10-05')?early:evil)}));
  try{await ask(t);assert.equal(t.d.querySelector('.answer-box img'),null);assert(t.d.querySelector('.answer-box').textContent.includes('<img src=x'));
    t.d.getElementById('compare-known-date').value='2026-10-05T00:00';t.d.getElementById('compare-button').click();await wait(()=>t.d.querySelector('#compare-results table'));
    t.submit('history-form');await wait(()=>t.d.getElementById('compare-results').textContent==='');
  }finally{await settle();t.dom.window.close();}});
