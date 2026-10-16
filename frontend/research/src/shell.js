let importEpoch=0;
// Shared presentation only: authorization is supplied by the existing server.
const label=value=>String(value||'').replaceAll('_',' ').replace(/\b\w/g,c=>c.toUpperCase());
export function updateShell(session){
 const mine=++importEpoch,link=document.getElementById('nav-imports');if(link){link.hidden=true;fetch('/api/research/promotions/capabilities',{credentials:'same-origin',cache:'no-store',redirect:'error',signal:AbortSignal.timeout(20000)}).then(async response=>{if(!response.ok)return;const value=await response.json();if(mine===importEpoch&&!document.hidden&&value.configured&&value.can_inspect)link.hidden=false;}).catch(()=>{});}

 const values={'profile-initials':session.role==='HQ_ADMIN'?'HQ':session.role||'', 'account-role':label(session.role), 'account-scope':session.scope_type==='ALL'?'All officers':session.scope_type==='UNIT'?({CID:'CID unit',CCIB:'CCIB unit',CRIMINAL_DIVISION:'Criminal Divisions'}[session.scope_id]||label(session.scope_id)):label(session.scope_type)+' · '+(session.scope_id||''), 'scope-caption':session.scope_type==='ALL'?'':'Your permitted scope'};
 for(const [id,value]of Object.entries(values)){const el=document.getElementById(id);if(el)el.textContent=value;}
}
export function clearShell(){importEpoch++;const link=document.getElementById('nav-imports');if(link)link.hidden=true;for(const id of ['profile-initials','account-role','account-scope','scope-caption']){const el=document.getElementById(id);if(el)el.textContent='';}}
