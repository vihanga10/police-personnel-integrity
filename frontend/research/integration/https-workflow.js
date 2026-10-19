'use strict';
// Real application JS -> HTTPS -> actual ASGI/access store/research algorithms.
// jsdom executes the DOM, not a graphical browser. Fixtures are invented.
const assert=require('node:assert/strict');
const https=require('node:https');
const fs=require('node:fs');
const {JSDOM}=require('jsdom');
const origin=process.env.PPI_UI_TEST_ORIGIN,ca=fs.readFileSync(process.env.PPI_UI_TEST_CA);
const uid='00000000-0000-0000-0000-000000000001';
const wait=async predicate=>{for(let i=0;i<200;i++){if(predicate())return;await new Promise(r=>setTimeout(r,10));}throw Error('HTTPS UI workflow did not settle');};
let cookie='',csrf='',dropAcknowledgement=false,submissions=0;
async function transport(url,options={}){
  return new Promise((resolve,reject)=>{
    const target=new URL(url,origin);assert.equal(target.origin,origin);
    const headers={...options.headers,Origin:origin};if(cookie)headers.Cookie=cookie;
    const req=https.request(target,{method:options.method||'GET',ca,minVersion:'TLSv1.3',headers,timeout:15000},res=>{const chunks=[];res.on('data',x=>chunks.push(x));res.on('end',()=>{if(res.headers['set-cookie'])cookie=res.headers['set-cookie'][0].split(';')[0];const text=Buffer.concat(chunks).toString();if(target.pathname==='/api/research/requests'&&options.method==='POST'){submissions++;if(dropAcknowledgement){dropAcknowledgement=false;reject(Error('Fixture lost response AFTER durable request commit'));return;}}resolve({ok:res.statusCode<400,status:res.statusCode,headers:res.headers,text:async()=>text,json:async()=>JSON.parse(text)});});});
    req.on('error',reject);req.on('timeout',()=>req.destroy(Error('Fixture deadline')));req.end(options.body);
  });
}
async function main(){
  const html=await transport('/');assert.equal(html.status,200);assert.ok(html.headers['content-security-policy'].includes("script-src 'self'"));
  const source=await(await transport('/assets/app.js')).text();const css=await(await transport('/assets/styles.css')).text();assert.ok(css.includes('@media(max-width:600px)'));
  const dom=new JSDOM(await html.text(),{url:origin,runScripts:'outside-only',pretendToBeVisual:true});
  const completed=[];const originalPush=completed.push.bind(completed);completed.push=name=>{console.log('UI check: '+name);return originalPush(name);};const d=dom.window.document,$=id=>d.getElementById(id),submit=id=>$(id).dispatchEvent(new dom.window.Event('submit',{bubbles:true,cancelable:true}));
  dom.window.fetch=transport;
  try{
    dom.window.eval(source);await wait(()=>!$('login-screen').hidden);assert.equal($('application').hidden,true);completed.push('ANONYMOUS_UI_LOCK');
    $('username').value='station.one';$('password').value=process.env.PPI_UI_TEST_PASSWORD;submit('login-form');await wait(()=>!$('application').hidden);assert.equal($('password').value,'');assert.equal(d.cookie,'');completed.push('REAL_HTTPS_LOGIN');
    const session=await(await transport('/api/auth/session')).json();csrf=session.csrf_token;
    $('search-kind').value='NAME';$('search-query').value='විහඟ';submit('search-form');await wait(()=>d.querySelector('.officer-result'));assert.equal(d.querySelectorAll('.officer-result').length,1);completed.push('SINHALA_SCOPED_SEARCH');
    d.querySelector('.officer-result').click();await wait(()=>!$('workspace-body').hidden);assert.ok($('observation-label').textContent.includes('UTC'));assert.ok(d.body.textContent.includes('not a fresh live verification'));completed.push('SIGNED_OBSERVED_WORKSPACE');
    for(const tab of ['overview','history','authority','contradictions','reviews','anchoring']){$('tab-'+tab).click();assert.equal($('panel-'+tab).hidden,false);}completed.push('SIX_RESEARCH_VIEWS');
    assert.ok($('authority-results').textContent.includes('Cannot verify'));assert.ok($('anchoring-results').textContent.includes('Finality pending'));completed.push('UNASSESSED_AUTHORITY_AND_FINALITY');
    const packet=await(await transport('/api/research/officers/'+uid)).json();const start=packet.coverage_start;
    $('tab-history').click();$('effective-date').value='2024-12-31';$('known-date').value=new Date(start).toISOString().slice(0,23);submit('history-form');await wait(()=>$('history-results').querySelector('.projection-grid'));assert.ok($('history-results').textContent.includes('Reported Inspector'));assert.ok($('contradiction-results').textContent.includes('Reported disagreement candidate'));completed.push('BEFORE_CORRECTION_QUERY');
    $('known-date').value=new Date(packet.coverage_end).toISOString().slice(0,23);submit('history-form');await wait(()=>!$('history-button').disabled);assert.ok(!$('history-results').textContent.includes('Reported Inspector'));assert.ok($('contradiction-results').textContent.includes('Reported values agree'));completed.push('AFTER_CORRECTION_QUERY');
    $('known-date').value='1900-01-01T00:00';submit('history-form');await wait(()=>!$('history-button').disabled);assert.ok($('history-results').textContent.includes('outside recorded history'));completed.push('COVERAGE_GAP_FAILS_CLOSED');
    const outside=await transport('/api/research/officers/00000000-0000-0000-0000-000000000005');assert.equal(outside.status,404);completed.push('DIRECT_ID_SCOPE_ENFORCEMENT');
    const missing=await transport('/api/research/history',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({officer_uid:uid,effective_on:'2024-12-31',known_at:packet.coverage_end})});assert.equal(missing.status,403);completed.push('DIRECT_QUERY_CSRF_ENFORCEMENT');
    $('tab-reviews').click();$('review-reason').value='HTTPS fixture: authority assessment required.';dropAcknowledgement=true;submit('review-form');await wait(()=>$('review-message').textContent.includes('response was not received'));const operation=$('operation-id').value;assert.equal(submissions,1);assert.ok(operation);completed.push('LOST_ACK_NO_AUTOMATIC_RETRY');
    $('check-last-request').click();await wait(()=>$('request-status').textContent.includes('Pending temporal authority'));assert.equal(submissions,1);assert.ok($('request-status').textContent.includes(operation));completed.push('READ_ONLY_REQUEST_RECOVERY');
    // A second explicit request is a correction request, not a source rewrite.
    $('review-kind').value='CORRECTION';$('review-reason').value='HTTPS fixture: preserve the original finding.';$('review-reason').dispatchEvent(new dom.window.Event('input',{bubbles:true}));submit('review-form');await wait(()=>submissions===2);await wait(()=>!$('review-message').textContent.includes('Retaining this request'));assert.ok($('review-message').textContent.includes('No decision'));completed.push('CORRECTION_REQUEST_PRESERVES_FINDING');
    $('load-recent-requests').click();await wait(()=>$('recent-requests').querySelectorAll('button').length===2);assert.equal(submissions,2);completed.push('RECENT_REQUEST_SCOPE_AND_RECOVERY');
    assert.equal(dom.window.localStorage.length,0);assert.equal(dom.window.sessionStorage.length,0);completed.push('NO_BROWSER_PERSONNEL_PERSISTENCE');
    $('logout').click();await wait(()=>$('login-message').textContent.includes('Signed out securely'));assert.equal($('officer-name').textContent,'');assert.equal($('findings-results').textContent,'');assert.equal((await transport('/api/auth/session')).status,401);completed.push('LOGOUT_AND_PRIVATE_DOM_CLEAR');
    assert.equal(completed.length,17);console.log('17 UI-script-to-HTTPS/backend scenarios passed; invented fixture data only.');
    console.log('DOM execution is verified; graphical browser rendering, original source replay, live finality and independent deployment are not established.');
  }finally{dom.window.close();}
}
main().catch(e=>{console.error('Isolated UI workflow stopped:',e.name,e.message);process.exitCode=1;});
