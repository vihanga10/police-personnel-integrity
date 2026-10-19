"""Disposable projection benchmark, not private Mac data."""
import json,sqlite3,tempfile,time
from pathlib import Path
from research_workspace_fixture import initialize,sign,identifier
from app.access import full_source_profiles as F,personnel_dashboard as D
with tempfile.TemporaryDirectory(prefix='dashboard-scale-') as tmp:
 store,key,_=initialize(Path(tmp));now=int(store.clock());profiles={};officers=[]
 with sqlite3.connect(store.path) as c:
  c.executescript(F.SCHEMA)
  for n in range(1,6597):
   rows=[dict(dataset='officer_personal_information.csv',raw_record_id=f'{n*100:064x}',fields={'full_name':'Invented scale officer '+str(n)}),dict(dataset='officer_service_information.csv',raw_record_id=f'{n*100+1:064x}',fields={'current_unit_type':'CID' if n<=150 else 'Station Crime Branch','current_rank':'Senior Deputy Inspector General of Police' if n==1 else 'Police Constable Class 1','current_unit_name':'Fixture unit '+str(n%607),'current_station':'Fixture station '+str(n%607),'current_province':'Fixture province','service_status':'Active'})]
   for j in range(24):rows.append(dict(dataset='promotion_history.csv',raw_record_id=f'{n*100+j+2:064x}',fields={f'field_{k}':'Invented scale evidence value '+str(n)+' '+('x'*48) for k in range(20)}))
   p=sign(key,dict(policy=F.POLICY,kind='SOURCE_PROFILE',record_origin='GENERATED_RESEARCH_RECORDS',issued_at=now,generation=1,source_public_sha256='a'*64,source_context_sha256='c'*64,officer_uid=identifier(n),full_records=rows,reported_posting=F.posting(rows)))
   ident=store.index('SOURCE_PROFILE',identifier(n));profiles[ident]=F.P.fingerprint(p);c.execute('INSERT INTO source_profiles VALUES(?,?,?)',(1,ident,store.seal('SOURCE_PROFILE',[1,ident],p)))
   officers.append(dict(officer_uid=identifier(n),names=['Invented scale officer '+str(n)],nic=str(199000000000+n),source_raw_id=f'{n:064x}'))
  metadata=sign(key,dict(policy=F.POLICY,kind='SOURCE_SET',record_origin='GENERATED_RESEARCH_RECORDS',issued_at=now,generation=1,source_public_sha256='a'*64,source_context_sha256='c'*64,profiles=profiles));c.execute('INSERT INTO source_profile_sets VALUES(?,?)',(1,store.seal('SOURCE_SET',1,metadata)))
 meta=F.active_set(store);times={}
 for label in ['cold','warm']:
  start=time.monotonic();rows=D.compact_profiles(store,meta,officers);summary=D.summarize(rows,6596,0,0);times[label]=round(time.monotonic()-start,3);assert len(rows)==6596 and summary['groups'][0]['highest_rank']=='SDIG'

 from copy import deepcopy
 from scoped_access_fixture import sign as access_sign,grant as account
 from research_workspace_fixture import disclosure,PASSWORD
 from app.access.research_service import ResearchService
 from app.access.research_app import create_app
 from test_scoped_access_api import Client
 with store.access.transaction() as c:directory=store.access._directory(c)
 template=directory['officers'][0];directory=deepcopy(directory);directory['generation']+=1;directory['officers']=[]
 for o in officers:directory['officers'].append({**deepcopy(template),**o})
 store.access.put_directory(access_sign(key,directory));store.access.put_account(account(key,'IGP','ALL',None,version=2))
 with store.transaction() as c:
  for o in officers:
   value=disclosure(key,officer=o['officer_uid'],now=now,version=2,reviews=False);ident=store.index('GRANT',identifier(100),o['officer_uid'])
   c.execute('INSERT OR REPLACE INTO disclosures VALUES(?,?,?)',(ident,value['payload']['issued_at'],store.seal('GRANT',ident,value)))
 store._personnel_dashboard_cache['key']=None
 client=Client(create_app(store,origin='https://access.test:9443'));client.login()
 http_times={}
 for label in ['cold','warm']:
  start=time.monotonic();code,_,value=client.request('/api/research/personnel-dashboard');http_times[label]=round(time.monotonic()-start,3)
  assert code==200,(code,value)
  assert value['disclosed_officers']==6596
 print(json.dumps(dict(fixture_officers=6596,fixture_source_records=6596*26,encrypted_database_bytes=store.path.stat().st_size,projection_seconds=times,authorized_http_seconds=http_times,actual_mac_timing_not_established=True),indent=2))
