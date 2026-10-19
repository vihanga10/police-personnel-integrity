const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const {JSDOM,VirtualConsole}=require('jsdom');
const reply=value=>({ok:true,status:200,json:async()=>structuredClone(value)});
const wait=async f=>{for(let n=0;n<200;n++){if(f())return;await new Promise(r=>setTimeout(r,5));}throw Error('DOM did not settle');};
const history={policy:'UPLOAD_PIPELINE_HISTORY_V1',total:2,record_types:{Education:1,Transfers:1},items:[
 {batch_id:'b'.repeat(8)+'-1111-4111-8111-111111111111',record_type:'TRANSFER_HISTORY',record_type_label:'Transfers',filename:'<img src=x onerror=alert(1)>.csv',uploader:{username:'research.hq',role:'HQ_ADMIN'},
  received_at:'2026-10-18T04:00:00Z',source_reference:'HQ/TRF/ORDER/1',source_system:'PF_REGISTRY',file_sha256:'f'.repeat(64),rows:{total:5,ready:4,duplicate:1,needs_review:0},
  acceptance:{ACCEPTED:2,PENDING_REVIEW:2,NOT_ACCEPTED:0},current_stage:'ROW_REVIEWED',last_event_at:'2026-10-18T05:00:00Z',events:[
   {stage:'UPLOAD_PREVIEW_RETAINED',at:'2026-10-18T04:00:00Z',actor:{username:'research.hq',role:'HQ_ADMIN'},detail:'transfers.csv'},
   {stage:'IGP_APPROVED_PROCESSING',at:'2026-10-18T04:05:00Z',actor:{username:'research.igp',role:'IGP'},detail:'Inspected exact rows'},
   {stage:'BOTH_CHAINS_VERIFIED',at:'2026-10-18T04:25:00Z',actor:null,detail:'Fabric aa · Sepolia 0xbb'},
   {stage:'ROW_REVIEWED',at:'2026-10-18T05:00:00Z',actor:{username:'research.igp',role:'IGP'},detail:'Row 1 · ROW_ACCEPT'}]}]};
function setup(overrides={}){
 const dom=new JSDOM(fs.readFileSync('accountability.html','utf8'),{url:'https://access.test:9443/accountability',runScripts:'outside-only',pretendToBeVisual:true,virtualConsole:new VirtualConsole()}),calls=[];
 dom.window.AbortSignal=AbortSignal;
 dom.window.fetch=async(u,o)=>{calls.push([u,o]);if(overrides[u])return overrides[u]();
  const data=u==='/api/auth/session'?{username:'research.igp',role:'IGP',csrf_token:'fixture',server_time:Date.now()/1000,expires_at:Date.now()/1000+1800}:
   u==='/api/accountability/anchoring'?{status:'NEW_EVENTS_PENDING',private_chain_verified:true,anchored_through_sequence:800,latest_local_sequence:805,unanchored_events:5,transaction_id:'a'.repeat(64),last_verified_at:1792300000}:
   u==='/api/accountability/uploads'?history:u==='/api/accountability/logs'?{items:[],integrity:'LOCAL_CHAIN_VERIFIED',next_before_sequence:null}:{can_read_access_logs:true};
  return reply(data);};
 dom.window.eval(fs.readFileSync('accountability.js','utf8'));return {dom,d:dom.window.document,calls};
}
test('private blockchain status is described plainly with no public-anchoring text',async()=>{
 const t=setup();try{const box=t.d.getElementById('anchor-status');await wait(()=>box.textContent.includes('Hyperledger Fabric'));
  const text=box.textContent;assert(text.includes('verified through event 800 of 805'));assert(text.includes('5 newer events not yet anchored'));
  assert(text.includes('not a fresh chain read'));assert(!/public anchoring|not configured/i.test(text));assert(t.d.body.textContent.includes('Private blockchain log coverage'));
 }finally{t.dom.window.close();}});
test('a failed anchor check explains itself instead of showing a bare error code',async()=>{
 const t=setup({'/api/accountability/anchoring':()=>reply({status:'VERIFICATION_FAILED',private_chain_verified:false,public_chain_anchored:false})});
 try{const box=t.d.getElementById('anchor-status');await wait(()=>box.textContent.includes('could not be verified'));
  assert(box.textContent.includes('local log remains intact'));assert(!box.textContent.includes('No verified Fabric batch'));assert(!/public anchoring/i.test(box.textContent));
 }finally{t.dom.window.close();}});
test('upload history lists record type, uploader, row counts and every timed stage as plain text',async()=>{
 const t=setup();try{await wait(()=>t.d.querySelector('#upload-rows tr'));
  const row=t.d.querySelector('#upload-rows tr').textContent;assert(row.includes('Transfers'));assert(row.includes('research.hq'));assert(row.includes('5 total · 4 new · 1 duplicate'));assert(row.includes('2 accepted · 2 pending review'));
  assert.equal(t.d.querySelector('#upload-rows img'),null);assert(row.includes('<img src=x'));
  for(const text of ['Upload previewed and retained','IGP approved processing','Verified on Fabric and Sepolia','Independent row review','research.igp (IGP)'])assert(row.includes(text),text);
  assert(t.d.getElementById('uploads-summary').textContent.includes('2 uploads retained · Education 1 · Transfers 1'));
  assert.equal(t.calls.find(([u])=>u==='/api/accountability/uploads')[1].redirect,'error');
 }finally{t.dom.window.close();}});
test('upload history is cleared when the page is backgrounded and when permission is withdrawn',async()=>{
 const t=setup();try{await wait(()=>t.d.querySelector('#upload-rows tr'));Object.defineProperty(t.d,'hidden',{value:true});t.d.dispatchEvent(new t.dom.window.Event('visibilitychange'));
  assert.equal(t.d.querySelectorAll('#upload-rows tr').length,0);assert.equal(t.d.getElementById('uploads-summary').textContent,'');
 }finally{t.dom.window.close();}
 const denied=setup({'/api/accountability/uploads':()=>({ok:false,status:403,json:async()=>({error:'LOG_ACCESS_DENIED'})})});
 try{await wait(()=>denied.d.getElementById('uploads-summary').textContent.includes('no current permission'));assert.equal(denied.d.querySelectorAll('#upload-rows tr').length,0);}finally{denied.dom.window.close();}});
test('new upload actions can be filtered in the log viewer',async()=>{
 const t=setup();try{await wait(()=>t.d.querySelector('#upload-rows tr')&&t.d.getElementById('anchor-status').textContent.includes('Fabric'));const values=[...t.d.getElementById('action').options].map(o=>o.value||o.textContent);
  for(const a of ['DATASET_IMPORT_PREVIEW','DATASET_IMPORT_DECIDE','DATASET_IMPORT_REVIEW','DATASET_PIPELINE_WORKER','PROMOTION_UPLOAD_PREVIEW','UPLOAD_HISTORY_READ'])assert(values.includes(a),a);
 }finally{t.dom.window.close();}});
