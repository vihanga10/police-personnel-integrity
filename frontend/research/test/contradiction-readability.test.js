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
const LIM=['HISTORICAL_IDENTITY_UNASSESSED','REPORTED_DATE_SEMANTICS_UNASSESSED','SOURCE_INDEPENDENCE_UNVERIFIED','CLASSIFICATION_UNASSESSED'];
const ev=(fields,from,dataset='transfer_history',mode='EVENT')=>({fields,effective_from:from,effective_until:null,mode,reported_dataset:dataset,reasons:[]});
const item=(dimension,status,evidence,reasons,cross=true)=>({dimension,status,cross_reported_source:cross,reasons:[...reasons,...LIM],evidence,comparison_reference:'a'.repeat(64),version_references:['b'.repeat(64),'c'.repeat(64)],destination_references:['d'.repeat(64),'e'.repeat(64)],receipt_references:['f'.repeat(64),'1'.repeat(64)]});
const items=[item('rank','REPORTED_CONTRADICTION_CANDIDATE',[ev({to_rank:'Inspector'},'2020-01-01'),ev({to_rank:'<img src=x onerror=alert(1)>'},'2020-01-01')],['SAME_EVENT_DATE_DIFFERENT_VALUES']),
  item('police_number','REPORTED_AGREEMENT',[ev({police_no:'1',number_type:'police'},'2020-01-01',undefined,'INTERVAL'),ev({police_no:'1',number_type:'police'},'2020-01-01',undefined,'INTERVAL')],[]),
  item('posting','UNRESOLVED_COMPARISON',[ev({unit:'U1'},'2020-01-01'),ev({unit:'U2'},'2020-01-01')],['POSTING_SEMANTICS_UNAPPROVED'],false),
  item('restrictions','NO_REPORTED_CONFLICT_AT_POINT',[ev({restriction_id:'RS/1'},'2020-01-01'),ev({restriction_id:'RS/2'},'2020-01-01')],[])];
const answer={effective_on:'2021-01-01',known_at:'2026-10-10T00:00:00Z',items,total:4,unfiltered_total:4,offset:0,limit:25,excluded_versions:[],query_digest:'c'.repeat(64),comparison_digest:'d'.repeat(64)};
function router(overrides={}){return (url,options)=>{if(overrides[url])return overrides[url](options);if(url==='/api/auth/session')return response({username:'station.one',role:'STATION_OIC',scope_type:'STATION',scope_id:'S1',csrf_token:'csrf'});
  if(url==='/api/officers/search')return response({items:[officer],total:1});if(url==='/api/research/contradictions')return response(answer);
  if(url.startsWith('/api/research/officers/'))return response(workspace);return response({authenticated:false});};}
async function setup(handler){
  const dom=new JSDOM(fs.readFileSync(path.join(root,'index.html'),'utf8'),{url:'https://access.test:9443',runScripts:'outside-only',pretendToBeVisual:true});
  const calls=[];dom.window.fetch=async(url,options)=>{calls.push([url,options]);return handler(url,options);};dom.window.eval(fs.readFileSync(path.join(root,'app.js'),'utf8'));
  await wait(()=>!dom.window.document.getElementById('application').hidden);
  const d=dom.window.document,submit=id=>d.getElementById(id).dispatchEvent(new dom.window.Event('submit',{bubbles:true,cancelable:true}));
  d.getElementById('search-query').value='000000001V';submit('search-form');await wait(()=>d.querySelector('.officer-result'));d.querySelector('.officer-result').click();await wait(()=>!d.getElementById('workspace-body').hidden);
  return {dom,d,calls,submit};
}
async function compare(t){t.d.getElementById('tab-contradictions').click();t.d.getElementById('contradiction-effective').value='2021-01-01';t.d.getElementById('contradiction-known').value='2026-10-10T00:00:00.000';t.submit('contradiction-form');await wait(()=>t.d.querySelector('#contradiction-results .pair-card'));}
const settle=()=>new Promise(r=>setTimeout(r,60));
test('each compared pair shows both reports side by side with a one-line plain verdict',async()=>{
  const t=await setup(router());try{await compare(t);const cards=[...t.d.querySelectorAll('#contradiction-results .pair-card')];assert.equal(cards.length,4);
    assert.deepEqual(cards.map(c=>c.querySelectorAll('.pair-side').length),[2,2,2,2]);
    const verdicts=cards.map(c=>c.querySelector('.pair-verdict').textContent);
    assert(verdicts[0].includes('disagree')&&verdicts[1].includes('agree')&&verdicts[1].includes('does not prove')&&verdicts[2].includes('cannot be compared')&&verdicts[3].includes('Not a conflict'));
    assert(cards[0].textContent.includes('Inspector')&&cards[2].textContent.includes('U1')&&cards[2].textContent.includes('U2'));
  }finally{await settle();t.dom.window.close();}});
test('standard limits are stated once; only pair-specific reasons stay on a card; full evidence is collapsed',async()=>{
  const t=await setup(router());try{await compare(t);const results=t.d.getElementById('contradiction-results');
    assert(results.querySelector('.notice').textContent.includes('Every comparison also carries these limits'));
    const first=results.querySelector('.pair-card');assert(first.textContent.includes('Same event date different values'));
    for(const text of ['Historical identity has not been accepted','Independent source custody has not been verified','Historical classification has not been assessed'])assert(!first.querySelector('.reasons')?.textContent.includes(text),text);
    const full=[...first.querySelectorAll('details')].find(d=>d.querySelector('summary').textContent==='Evidence details and exact bindings');assert(full&&full.open===false);
    assert(full.textContent.includes('Exact evidence versions and bindings')&&full.querySelectorAll('.evidence-item').length===2,'the complete evidence is still available');
    assert.equal(results.querySelectorAll('.pair-card>.reasons').length,2,'only the two cards with a pair-specific reason keep a reasons list');
  }finally{await settle();t.dom.window.close();}});
test('report values are shown as text and an empty comparison keeps its honest message',async()=>{
  const t=await setup(router({'/api/research/contradictions':()=>response({...answer,items:[],total:0,unfiltered_total:0})}));
  try{t.d.getElementById('tab-contradictions').click();t.d.getElementById('contradiction-effective').value='2021-01-01';t.d.getElementById('contradiction-known').value='2026-10-10T00:00:00.000';t.submit('contradiction-form');
    await wait(()=>t.d.getElementById('contradiction-results').textContent.includes('does not prove agreement'));assert.equal(t.d.querySelector('#contradiction-results .pair-card'),null);
  }finally{await settle();t.dom.window.close();}
  const u=await setup(router());try{await compare(u);assert.equal(u.d.querySelector('#contradiction-results img'),null);assert(u.d.querySelector('#contradiction-results').textContent.includes('<img src=x'));}finally{await settle();u.dom.window.close();}});
