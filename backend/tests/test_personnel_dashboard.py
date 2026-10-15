import time
import pytest
from app.access import personnel_dashboard as D,full_source_profiles as F
from app.access.policy import AccessError
from app.access.research_service import ResearchService
from research_workspace_fixture import initialize,sign,identifier,PASSWORD,disclosure
from scoped_access_fixture import grant as account
@pytest.fixture
def env(tmp_path):
 clock=[time.time()];store,key,_=initialize(tmp_path,clock=lambda:clock[0]);clock[0]+=2
 store.access.put_account(account(key,'IGP','ALL',None,version=2,now=clock[0]));now=int(clock[0]);profiles=[];grants=[]
 values=[('CID','Senior Deputy Inspector General of Police','CID HQ',''),('CID','Senior Deputy Inspector General of Police','CID HQ',''),('CCIB','Inspector of Police','CCIB HQ',''),('Criminal Division','Superintendent of Police','Division Crime Unit',''),('Station Crime Branch','Police Constable Class 1','Station Crime Branch S','Station S'),('Police Station','Chief Inspector of Police','Police Station S','Station S')]
 for n,(unit,rank,name,station) in enumerate(values,1):
  rows=[dict(dataset='officer_personal_information.csv',raw_record_id=f'{n:064x}',fields={'full_name':f'Fixture {n}'}),dict(dataset='officer_service_information.csv',raw_record_id=f'{100+n:064x}',fields=dict(current_unit_type=unit,current_rank=rank,current_unit_name=name,current_unit_location='Fixture location',current_station=station,current_division='Division A' if station else '',current_province='Province A' if station else '',current_police_no=str(n),service_status='Active'))]
  profiles.append(sign(key,dict(policy=F.POLICY,kind='SOURCE_PROFILE',record_origin='GENERATED_RESEARCH_RECORDS',issued_at=now,generation=1,source_public_sha256='a'*64,source_context_sha256='c'*64,officer_uid=identifier(n),full_records=rows,reported_posting=F.posting(rows))))
  grants.append(disclosure(key,officer=identifier(n),now=now,version=2,reviews=False))
 metadata=sign(key,dict(policy=F.POLICY,kind='SOURCE_SET',record_origin='GENERATED_RESEARCH_RECORDS',issued_at=now,generation=1,source_public_sha256='a'*64,source_context_sha256='c'*64,profiles={store.index('SOURCE_PROFILE',p['payload']['officer_uid']):F.P.fingerprint(p) for p in profiles}))
 F.publish(store,profiles,metadata,grants);token,_=store.access.login('station.one',PASSWORD,'fixture-peer')
 return store,key,clock,token,profiles

def read(env):return D.dashboard(ResearchService(env[0]),env[3])
def test_real_scope_disclosure_source_units_and_all_highest_rank_ties(env):
 value=read(env);assert value['permitted_officers']==value['disclosed_officers']==6
 groups={g['code']:g for g in value['groups']};assert groups['CID']['officers']==2 and groups['STATION_CRIME_BRANCH']['officers']==1
 assert groups['OTHER']['officers']==1 and value['authority_established'] is False
 assert groups['CID']['highest_rank']=='SDIG' and len(groups['CID']['highest_officer_uids'])==2
 assert value['data_quality']['non_station_assignments']==3 and value['data_quality']['missing_station']==1
 assert value['data_quality']['unresolved_unit_or_rank']==0

def test_warm_projection_cache_rechecks_ciphertext_tampering(env):
 store=env[0];read(env);ident=store.index('SOURCE_PROFILE',identifier(2))
 with store.transaction() as c:c.execute('UPDATE source_profiles SET value=? WHERE id=?',(b'corrupt',ident))
 with pytest.raises(AccessError,match='DASHBOARD_SOURCE_VERIFICATION_FAILED'):read(env)

def test_scoped_user_never_sees_other_officers_or_their_counts(env):
 store,key,clock,_,_=env;store.access.put_account(account(key,'STATION_OIC','STATION','S1',version=3,now=clock[0]));token,_=store.access.login('station.one',PASSWORD,'fixture-peer-2')
 value=D.dashboard(ResearchService(store),token);assert value['permitted_officers']==1
 assert value['disclosed_officers']==0 and not value['officers'];assert all(g['officers']==0 for g in value['groups'])

def test_grant_revocation_after_warm_cache_hides_profiles(env):
 store=env[0];read(env)
 with store.transaction() as c:c.execute('DELETE FROM disclosures WHERE id=?',(store.index('GRANT',identifier(100),identifier(2)),))
 value=read(env);assert value['disclosed_officers']==5;assert identifier(2) not in [r['officer_uid'] for r in value['officers']]

def test_account_expiry_during_collection_denies_return(env,monkeypatch):
 original=D.compact_profiles
 def change(*args):
  result=original(*args);env[2][0]+=4000;return result
 monkeypatch.setattr(D,'compact_profiles',change)
 with pytest.raises(AccessError):read(env)

def test_rank_order_is_hierarchy_and_unmapped_values_are_visible():
 assert D.rank_order('SDIG')<D.rank_order('DIG')<D.rank_order('PC_C1')
 value=D.project({'issued_at':1,'full_records':[{'dataset':'officer_service_information.csv','raw_record_id':'a'*64,'fields':{'current_rank':'unrecognized','current_unit_type':'unrecognized'}}]})
 assert value['unit_type']=='UNRESOLVED' and value['quality']=='UNMAPPED_UNIT_OR_RANK'

def test_missing_or_multiple_service_rows_never_choose_a_winner():
 assert D.project({'full_records':[]})['quality']=='MULTIPLE_OR_MISSING_SERVICE_ROWS'
 assert D.project({'full_records':[{'dataset':'officer_service_information.csv'}]*2})['unit_type']=='UNRESOLVED'

def test_anonymous_and_expired_sessions_cannot_read(env):
 with pytest.raises(AccessError):D.dashboard(ResearchService(env[0]),'invalid')
 env[2][0]+=1801
 with pytest.raises(AccessError):read(env)

def test_missing_profile_row_fails_even_after_warm_cache(env):
 store=env[0];read(env)
 with store.transaction() as c:c.execute('DELETE FROM source_profiles WHERE id=?',(store.index('SOURCE_PROFILE',identifier(1)),))
 with pytest.raises(AccessError):read(env)

def test_dashboard_does_not_write_source_rows(env):
 store=env[0]
 with store.transaction() as c:before=c.execute('SELECT * FROM source_profiles ORDER BY id').fetchall()
 read(env);read(env)
 with store.transaction() as c:assert c.execute('SELECT * FROM source_profiles ORDER BY id').fetchall()==before

def test_readonly_http_endpoint_uses_existing_session_and_denies_anonymous(env):
 from app.access.research_app import create_app
 from test_scoped_access_api import Client
 c=Client(create_app(env[0],origin='https://access.test:9443'));c.login()
 status,_,value=c.request('/api/research/personnel-dashboard')
 assert status==200 and value['disclosed_officers']==6
 from app.access.accountability import action_for
 assert action_for('/api/research/personnel-dashboard')=='UNIT_DASHBOARD_READ'
 anonymous=Client(create_app(env[0],origin='https://access.test:9443'))
 assert anonymous.request('/api/research/personnel-dashboard')[0]==401
