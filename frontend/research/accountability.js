'use strict';
(() => {
  const el=id=>document.getElementById(id);
  let csrf=null, cursor=null, generation=0, busy=false;
  const fmt=new Intl.DateTimeFormat('en-GB',{timeZone:'Asia/Colombo',dateStyle:'medium',timeStyle:'medium'});
  function clear(){generation++;el('rows').replaceChildren();el('account').textContent='';el('integrity').textContent='';cursor=null;el('older').hidden=true;}
  function message(text){el('message').textContent=text;}
  async function api(path,body){const response=await fetch(path,{method:body?'POST':'GET',credentials:'same-origin',redirect:'error',cache:'no-store',headers:body?{'content-type':'application/json','x-csrf-token':csrf}:{},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(20000)});const value=await response.json();if(!response.ok){const error=new Error(value.error||'REQUEST_FAILED');error.status=response.status;throw error;}return value;}
  function cell(row,text){const td=document.createElement('td');td.textContent=text;row.append(td);}
  function render(value){for(const item of value.items){const row=document.createElement('tr');const actor=item.actor;let time='Not captured';try{time=fmt.format(new Date(item.recorded_at));}catch{}
    cell(row,time);cell(row,actor?.username||(actor?.key_id?'Operator key '+actor.key_id:'Unresolved / unauthenticated'));cell(row,actor?.role?`${actor.role} · ${actor.scope_id||actor.scope_type} · v${actor.account_version}${actor.authentication_state&&actor.authentication_state!=='ACTIVE'?' · '+actor.authentication_state:''}`:'Not captured');cell(row,`${item.action}${item.phase?' · '+item.phase:''}`);cell(row,item.requested_officer_uid||item.finding_id||item.operation_id||(item.returned_officer_uids?.length?'Returned UUIDs: '+item.returned_officer_uids.join(', '):'Not captured'));cell(row,item.outcome||'Not captured');cell(row,item.reason||'—');cell(row,item.request_id||'Not captured');el('rows').append(row);}
    cursor=value.next_before_sequence;el('older').hidden=!cursor;el('integrity').textContent=`${value.integrity} · ${el('rows').children.length} events shown · independent anchoring: not established`;}
  async function load(older=false){if(busy)return;busy=true;el('refresh').disabled=true;el('older').disabled=true;const mine=generation;
    if(!older){el('rows').replaceChildren();cursor=null;el('older').hidden=true;}
    const legacy=el('source').value==='legacy';
    try{const value=await api('/api/accountability/'+el('source').value,{limit:50,before_sequence:older?cursor:null,action:legacy?null:el('action').value||null,outcome:legacy?null:el('outcome').value||null});if(mine!==generation)return;render(value);message(value.items.length?'Events loaded. Refresh to see newer activity.':'No matching events.');}
    catch(error){if(mine!==generation)return;clear();if(error.status===401){csrf=null;el('controls').hidden=true;message('Your session ended. Return to the officer workspace and sign in again.');}else if(error.status===403){el('controls').hidden=true;message('Your account has no current permission to inspect access logs.');}else message('Logs could not be loaded. The request outcome may be recorded even if the response was interrupted.');}
    finally{busy=false;el('refresh').disabled=false;el('older').disabled=false;}}
  el('filters').addEventListener('submit',event=>{event.preventDefault();load();});el('older').addEventListener('click',()=>load(true));
  el('source').addEventListener('change',()=>{el('action').disabled=el('outcome').disabled=el('source').value==='legacy';clear();message('Load events from the selected source.');});
  el('logout').addEventListener('click',async()=>{clear();el('controls').hidden=true;const old=csrf;csrf=null;try{await fetch('/api/auth/logout',{method:'POST',credentials:'same-origin',redirect:'error',headers:{'content-type':'application/json','x-csrf-token':old||''},body:'{}',signal:AbortSignal.timeout(20000)});}catch{}location.assign('/');});
  document.addEventListener('visibilitychange',()=>{if(document.hidden){clear();message('Private log contents cleared while this page was in the background. Load events again.');}});
  window.addEventListener('pagehide',()=>{clear();csrf=null;});
  (async()=>{const mine=generation;try{const session=await api('/api/auth/session');await api('/api/accountability/capabilities');if(mine!==generation)return;csrf=session.csrf_token;el('account').textContent=`${session.username} · ${session.role} · explicit log-inspection permission`;el('controls').hidden=false;await load();}catch(error){if(mine!==generation)return;clear();message(error.status===401?'Sign in through the officer workspace first.':'Your account has no current permission to inspect access logs.');}})();
})();
