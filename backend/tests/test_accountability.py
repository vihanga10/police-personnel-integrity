import base64
from copy import deepcopy
import json
import os
import sqlite3
import time
import pytest
from app.access import accountability as A
from app.access.policy import encoded,AccessError
from app.access.research_app import create_app,configured
from research_workspace_fixture import initialize,identifier,PASSWORD,review_body
from scoped_access_fixture import grant
from test_scoped_access_api import Client

FILTERS={'limit':100,'before_sequence':None,'action':None,'outcome':None}

def write(path,value):
    path.write_text(json.dumps(value));path.chmod(0o600)

def reader_grant(key,user=identifier(100),version=1,now=None):
    now=int(time.time()) if now is None else int(now)
    p={'policy':A.POLICY,'kind':'READ_ACCESS_LOGS','user_id':user,'account_version':version,
       'issued_at':now-1,'expires_at':now+3600,'review_reference':'ISOLATED_RESEARCH_LOG_TEST'}
    return {'key_id':'test-admin','payload':p,'signature':base64.b64encode(key.sign(encoded(p))).decode()}

@pytest.fixture
def env(tmp_path):
    clock=[time.time()];s,key,cfg=initialize(tmp_path,clock=lambda:clock[0])
    root=tmp_path/'accountability';root.mkdir(mode=0o700)
    f=tmp_path/'accountability.key';f.write_bytes(os.urandom(32));f.chmod(0o600)
    logs=A.AccountabilityStore(root,f,access=s.access,create=True)
    g=tmp_path/'reader.json';write(g,reader_grant(key,now=clock[0]));logs.grant_files=(str(g),)
    s.accountability=logs;c=Client(create_app(s,origin='https://access.test:9443'));c.login()
    return s,logs,c,key,g,clock,cfg

def events(logs):
    with logs.locked() as connection:return [v for _,v in logs.verify(connection)[0]]

def test_login_success_denial_malformed_and_throttle_are_logged(env):
    s,logs,c,*_=env
    for body in ({'username':'station.one','password':'wrong-secret-password'},
                 {'username':'!!!raw-private-login','password':PASSWORD}, {'username':'station.one'}):
        c.request('/api/auth/login','POST',body)
    for _ in range(5):c.request('/api/auth/login','POST',{'username':'station.one','password':'wrong-secret-password'})
    done=[v for v in events(logs) if v['phase']=='COMPLETED' and v['action']=='LOGIN']
    assert done[0]['outcome']=='ALLOWED' and done[0]['actor']['authenticated']
    assert {v['status'] for v in done}>={200,400,401,429}
    text=json.dumps(events(logs));assert PASSWORD not in text and 'wrong-secret-password' not in text and '!!!raw-private-login' not in text

def test_target_actor_outcome_trace_and_search_privacy(env):
    _,logs,c,*_=env
    assert c.request('/api/research/officers/'+identifier(1))[0]==200
    assert c.request('/api/research/officers/'+identifier(5))[0]==404
    c.request('/api/officers/search','POST',{'kind':'NIC','query':'PRIVATE_SEARCH_TEXT'})
    done=[v for v in events(logs) if v['phase']=='COMPLETED']
    views=[v for v in done if v['action']=='WORKSPACE_READ']
    assert [v['outcome'] for v in views]==['ALLOWED','DENIED']
    assert views[1]['requested_officer_uid']==identifier(5) and views[1]['reason']=='NOT_FOUND'
    assert views[0]['actor']['role']=='STATION_OIC' and views[0]['actor']['scope_id']=='S1'
    for v in views:assert any(x['phase']=='RECEIVED' and x['request_id']==v['request_id'] for x in events(logs))
    assert any(e.get('search',{}).get('query')=='PRIVATE_SEARCH_TEXT' for e in events(logs))
    assert b'PRIVATE_SEARCH_TEXT' not in logs.db.read_bytes()

def test_search_logs_returned_identifiers_without_names_nic_or_query(env):
    _,logs,c,*_=env
    status,_,answer=c.request('/api/officers/search','POST',{'kind':'NAME','query':'Same Reported Name'})
    assert status==200 and answer['items']
    event=events(logs)[-1]
    assert event['returned_officer_uids']==[item['officer_uid'] for item in answer['items']]
    text=json.dumps(events(logs))
    assert event['search']=={'kind':'NAME','query':'Same Reported Name'}
    assert 'Same Reported Name' in text
    for item in answer['items']:assert item['nic'] not in text

def test_log_reader_is_explicit_and_reads_are_logged(env):
    _,logs,c,*_=env
    logs.grant_files=()
    assert c.request('/api/accountability/logs','POST',FILTERS)[0]==403
    assert events(logs)[-1]['reason']=='LOG_ACCESS_DENIED'
    logs.grant_files=(str(env[4]),)
    status,_,body=c.request('/api/accountability/logs','POST',FILTERS)
    assert status==200 and body['integrity']=='LOCAL_CHAIN_VERIFIED' and not body['independently_anchored']
    assert events(logs)[-1]['action']=='ACCESS_LOG_READ'

@pytest.mark.parametrize('change',[{'limit':0},{'limit':101},{'limit':True},{'before_sequence':0},{'action':'RAW_PRIVATE_ACTION'},{'outcome':'SECRET'},{'extra':'role'}])
def test_log_filters_are_bounded(env,change):
    assert env[2].request('/api/accountability/logs','POST',{**FILTERS,**change})[0]==400

def test_pagination_and_legacy_remain_honest(env):
    _,logs,c,*_=env
    for _ in range(3):c.request('/api/auth/session')
    first=c.request('/api/accountability/logs','POST',{**FILTERS,'limit':2})[2]
    second=c.request('/api/accountability/logs','POST',{**FILTERS,'limit':2,'before_sequence':first['next_before_sequence']})[2]
    assert {x['sequence'] for x in first['items']}.isdisjoint(x['sequence'] for x in second['items'])
    old=c.request('/api/accountability/legacy','POST',FILTERS)
    assert old[0]==200 and old[2]['items']
    assert all(x['account_role_at_event'] is None and x['request_id'] is None for x in old[2]['items'])

def test_expired_session_and_logout_attribution(env):
    _,logs,c,_,_,clock,*_=env
    clock[0]+=1801
    assert c.request('/api/auth/session')[0]==401
    assert events(logs)[-1]['actor']['authentication_state']=='SESSION_EXPIRED'
    clock[0]-=1801;c.login();assert c.request('/api/auth/logout','POST',{})[0]==200
    assert events(logs)[-1]['action']=='LOGOUT' and events(logs)[-1]['actor']['authenticated']

def test_reader_expiry_signature_and_version_denial(env):
    s,logs,c,key,g,clock,*_=env
    write(g,reader_grant(key,version=2,now=clock[0]));assert c.request('/api/accountability/logs','POST',FILTERS)[0]==403
    bad=reader_grant(key,now=clock[0]);bad['signature']='AA=='
    write(g,bad);assert c.request('/api/accountability/logs','POST',FILTERS)[0]==403
    write(g,reader_grant(key,now=clock[0]-4000));assert c.request('/api/accountability/logs','POST',FILTERS)[0]==403
    write(g,reader_grant(key,now=clock[0]));s.access.put_account(grant(key,version=2,now=clock[0]));c.login()
    assert c.request('/api/accountability/logs','POST',FILTERS)[0]==403

def test_ciphertext_and_tamper_detection_before_dispatch(env):
    _,logs,c,*_=env
    assert b'station.one' not in logs.db.read_bytes() and PASSWORD.encode() not in logs.db.read_bytes()
    with sqlite3.connect(logs.db) as connection:
        connection.execute('DROP TRIGGER no_event_update')
        connection.execute("UPDATE events SET digest=? WHERE seq=1",('0'*64,))
    status,_,body=c.request('/api/research/officers/'+identifier(1))
    assert status==503 and body['error']=='ACCOUNTABILITY_UNAVAILABLE'

def test_deleted_tail_detected_and_committed_checkpoint_gap_recovers(env):
    _,logs,c,*_=env
    saved=logs.checkpoint.read_bytes();c.request('/api/auth/session')
    logs.checkpoint.write_bytes(saved)
    assert c.request('/api/auth/session')[0]==200 # Valid authenticated suffix after checkpoint failure.
    with sqlite3.connect(logs.db) as connection:
        connection.execute('DROP TRIGGER no_event_delete')
        connection.execute('DELETE FROM events WHERE seq=(SELECT MAX(seq) FROM events)')
    assert c.request('/api/auth/session')[0]==503

def test_completion_failure_does_not_claim_rollback_or_retry(env,monkeypatch):
    _,logs,c,*_=env;append=logs.append
    def failed(v):
        if v['phase']=='COMPLETED':raise OSError('private secret failure')
        return append(v)
    monkeypatch.setattr(logs,'append',failed)
    status,_,body=c.request('/api/auth/logout','POST',{})
    assert status==503 and body['operation_outcome_unknown'] is True
    assert 'private secret' not in json.dumps(body)
    assert events(logs)[-1]['phase']=='RECEIVED'

def test_review_and_correction_reasons_are_retained_only_in_encrypted_events(env):
    _,logs,c,*_=env
    value=review_body(reason='PRIVATE_REVIEW_REASON')
    assert c.request('/api/research/requests','POST',value)[0]==200
    done=events(logs)[-1]
    assert done['operation_id']==value['operation_id'] and done['finding_id']==value['finding_id']
    assert done['request_details']['reason']=='PRIVATE_REVIEW_REASON'
    assert b'PRIVATE_REVIEW_REASON' not in logs.db.read_bytes()
    value=review_body(kind='CORRECTION',operation_id=identifier(302),reason='PRIVATE_CORRECTION_REASON')
    assert c.request('/api/research/requests','POST',value)[0]==200
    assert events(logs)[-1]['action']=='CORRECTION_REQUEST'

def test_config_separate_key_and_reader_permission_signed(env,tmp_path):
    s,logs,_,_,g,_,cfg=env
    ac=tmp_path/'accountability-config.json'
    write(ac,{'policy':'ACCOUNTABILITY_CONFIG_V1','state_directory':str(logs.root),
             'key_file':str(tmp_path/'accountability.key'),'reader_grants':[str(g)]})
    value=json.loads(cfg.read_text());value['accountability_config']=str(ac);write(cfg,value)
    restored,_=configured(cfg);assert restored.accountability is not None
    bad=json.loads(ac.read_text());bad['key_file']=str(tmp_path/'workspace.key');write(ac,bad)
    with pytest.raises(Exception):configured(cfg)

def test_no_password_token_or_private_path_in_events(env):
    _,logs,c,*_=env
    c.request('/api/research/history','POST',{'officer_uid':'not-a-uuid-SECRET','effective_on':'PRIVATE_DATE','known_at':'PRIVATE_PATH'})
    text=json.dumps(events(logs))
    for forbidden in (PASSWORD,'PRIVATE_DATE','PRIVATE_PATH','not-a-uuid-SECRET',c.cookie):assert forbidden not in text

@pytest.mark.parametrize('kwargs',[{'scheme':'http'},{'host':'private-evil.test'},
    {'origin':'https://private-evil.test'},{'origin':None},{'query':b'NIC_PRIVATE_QUERY'},
    {'headers':[(b'authorization',b'Bearer PRIVATE_SECRET_TOKEN')]},
    {'headers':[(b'x-csrf-token',b'PRIVATE_SECOND_TOKEN')]}])
def test_boundary_denials_logged_without_header_or_query_leakage(env,kwargs):
    _,logs,c,*_=env
    assert c.request('/api/officers/search','POST',{'kind':'NAME','query':'PRIVATE_SEARCH_TEXT'},**kwargs)[0]>=400
    value=events(logs)[-1]
    assert value['phase']=='COMPLETED' and value['outcome']=='DENIED'
    text=json.dumps(events(logs))
    for secret in ('private-evil.test','NIC_PRIVATE_QUERY','PRIVATE_SECRET_TOKEN','PRIVATE_SECOND_TOKEN'):assert secret not in text

def test_concurrent_append_and_sequence_consistency(env):
    from concurrent.futures import ThreadPoolExecutor
    _,logs,*_=env
    value={'request_id':identifier(999),'action':'SESSION_CHECK','phase':'RECEIVED','outcome':'ATTEMPT'}
    with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda _:logs.append(value),range(20)))
    with logs.locked() as c:
        rows,head=logs.verify(c)
    assert len(rows)==22
    assert json.loads(logs.checkpoint.read_text())['head']==head

def test_permissions_changed_or_key_replaced_stops_access(env):
    _,logs,c,*_=env
    logs.key_path.chmod(0o644)
    assert c.request('/api/auth/session')[0]==503
    logs.key_path.chmod(0o600);logs.key_path.write_bytes(os.urandom(32))
    assert c.request('/api/auth/session')[0]==503

def test_legacy_integrity_failure_is_service_failure_not_invalid_filter(env):
    s,logs,c,*_=env
    with sqlite3.connect(s.access.path) as connection:
        connection.execute('DROP TRIGGER immutable_audit_update')
        connection.execute('UPDATE audit SET digest=? WHERE seq=1',('0'*64,))
    status,_,value=c.request('/api/accountability/legacy','POST',FILTERS)
    assert status==503 and value['error']!='INVALID_LOG_FILTERS'
    assert events(logs)[-1]['outcome']=='FAILED'
