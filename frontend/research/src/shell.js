// Shared presentation only: authorization is supplied by the existing server.
const label=value=>String(value||'').replaceAll('_',' ').replace(/\b\w/g,c=>c.toUpperCase());
export function updateShell(session){
 const values={'profile-initials':session.role==='HQ_ADMIN'?'HQ':session.role||'', 'account-role':label(session.role), 'account-scope':session.scope_type==='ALL'?'All officers':session.scope_type==='UNIT'?({CID:'CID unit',CCIB:'CCIB unit',CRIMINAL_DIVISION:'Criminal Divisions'}[session.scope_id]||label(session.scope_id)):label(session.scope_type)+' · '+(session.scope_id||''), 'scope-caption':session.scope_type==='ALL'?'':'Your permitted scope'};
 for(const [id,value]of Object.entries(values)){const el=document.getElementById(id);if(el)el.textContent=value;}
}
export function clearShell(){for(const id of ['profile-initials','account-role','account-scope','scope-caption']){const el=document.getElementById(id);if(el)el.textContent='';}}
