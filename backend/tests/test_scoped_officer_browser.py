import time
import pytest
from app.access.policy import AccessError
from app.access.research_service import ResearchService
from app.access.research_app import create_app
from research_workspace_fixture import initialize, disclosure, identifier, PASSWORD
from scoped_access_fixture import grant, sign
from test_scoped_access_api import Client

ACCOUNTS = [
 ('research.igp','IGP','ALL',None,6),
 ('research.hq','HQ_ADMIN','ALL',None,6),
 ('research.sdig','SDIG','PROVINCE','P1',4),
 ('research.dig.a','DIG','DIVISION','V1',2),
 ('research.dig.b','DIG','DIVISION','V2',1),
 ('research.ssp','SSP','DIVISION','V1',2),
 ('research.sp','SP','DIVISION','V1',2),
 ('research.oic.a','STATION_OIC','STATION','S1',1),
 ('research.oic.b','STATION_OIC','STATION','S3',1),
 ('research.inactive','DIG','DIVISION','V1',0),
]
def request(**values):
    result=dict(kind='NAME',query='',availability='ALL',level='ALL',scope_id='',limit=25,offset=0)
    result.update(values); return result

@pytest.fixture
def env(tmp_path):
    store,key,_=initialize(tmp_path)
    return store,key,ResearchService(store)

def enroll(env, row):
    store,key,service=env; login,role,level,scope,total=row
    envelope=grant(key,role,level,scope,login=login,version=2,active=login!='research.inactive')
    envelope['payload']['user_id']=identifier(200)
    store.access.put_account(sign(key,envelope['payload']),PASSWORD)
    return store.access.login(login,PASSWORD,'fixture-peer')

@pytest.mark.parametrize('row',ACCOUNTS,ids=[r[0] for r in ACCOUNTS])
def test_all_ten_account_scope_cases(env,row):
    store,key,service=env
    if row[0]=='research.inactive':
        with pytest.raises(AccessError):enroll(env,row)
        return
    token,csrf=enroll(env,row)
    answer=service.browse(token,csrf,request())
    assert answer['total']==row[4]
    scope=row[3];level=row[2]
    assert all(level=='ALL' or o['membership'][level]==scope for o in answer['items'])
    assert all(not o['details_available'] for o in answer['items']) # account version changed, old grant unavailable
    visible={o['membership']['STATION'] for o in answer['items'] if o['membership']['STATION']}
    assert set(answer['scope_options']['STATION'])==visible

def test_hq_browses_all_names_with_only_one_connected_packet_and_current_grant(env):
    store,key,service=env;token,csrf=enroll(env,ACCOUNTS[1])
    store.import_grant(disclosure(key,user=identifier(200),version=2))
    first=service.browse(token,csrf,request(limit=2))
    second=service.browse(token,csrf,request(limit=2,offset=2))
    assert first['total']==second['total']==6 and len(first['items'])==2
    assert not set(x['officer_uid'] for x in first['items']) & set(x['officer_uid'] for x in second['items'])
    available=service.browse(token,csrf,request(availability='AVAILABLE'))
    assert available['total']==1 and available['items'][0]['officer_uid']==identifier(1)
    assert service.browse(token,csrf,request(availability='UNAVAILABLE'))['total']==5
    assert service.browse(token,csrf,request(query='විහඟ'))['total']==6
    assert service.browse(token,csrf,request(kind='NIC',query='000000001'))['total']==1
    assert service.browse(token,csrf,request(kind='REFERENCE',query=identifier(2)))['total']==1
    assert service.browse(token,csrf,request(level='DIVISION',scope_id='V2'))['total']==1

def test_scoped_filter_cannot_disclose_other_division(env,monkeypatch):
    store,key,service=env;token,csrf=enroll(env,ACCOUNTS[3])
    monkeypatch.setattr(service,'authorized',lambda *a,**k:pytest.fail('Out-of-scope packet inspected'))
    answer=service.browse(token,csrf,request(level='DIVISION',scope_id='V2'))
    assert answer['total']==0 and answer['items']==[]
    assert 'V2' not in answer['scope_options']['DIVISION']

@pytest.mark.parametrize('changes',[{'limit':True},{'limit':51},{'offset':-1},{'kind':'ROLE'},
 {'query':'x\nsecret'},{'level':'ALL','scope_id':'V1'},{'availability':'WITHHELD'}])
def test_browser_rejects_invalid_fields(env,changes):
    store,key,service=env;token,csrf=store.access.login('station.one',PASSWORD,'fixture-peer')
    with pytest.raises(AccessError) as exc:service.browse(token,csrf,request(**changes))
    assert exc.value.status==400

def test_http_csrf_and_role_injection_and_logout(env):
    store,key,service=env;client=Client(create_app(store,origin='https://access.test:9443'));client.login()
    assert client.request('/api/research/browse','POST',request(),csrf='')[0]==403
    assert client.request('/api/research/browse','POST',{**request(),'role':'HQ_ADMIN'})[0]==400
    assert client.request('/api/research/browse','POST',request())[2]['total']==1
    assert client.request('/api/auth/logout','POST',{})[0]==200
    assert client.request('/api/research/browse','POST',request())[0]==401

def test_revoked_account_and_expired_session_cannot_browse(env):
    store,key,service=env;token,csrf=store.access.login('station.one',PASSWORD,'fixture-peer')
    store.access.put_account(grant(key,version=2,active=False))
    with pytest.raises(AccessError):service.browse(token,csrf,request())

from test_accountability import env as accountability_env, events

def test_browser_search_is_retained_in_encrypted_accountability(accountability_env):
    store,logs,client,*_=accountability_env
    value=request(kind='NIC',query='000000001V')
    assert client.request('/api/research/browse','POST',value)[0]==200
    done=[e for e in events(logs) if e['action']=='OFFICER_SEARCH' and e['phase']=='COMPLETED']
    assert done[-1]['search']=={'kind':'NIC','query':'000000001V'}
    assert done[-1]['returned_officer_uids']==[identifier(1)]
    assert b'000000001V' not in logs.db.read_bytes()
