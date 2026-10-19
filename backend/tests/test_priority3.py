"""Generated records only; real crypto, SQL and existing comparison algorithms."""
import base64,json,time,os
from copy import deepcopy
from uuid import uuid4
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.access import review_workflow as W,research_policy as P
from app.access.policy import encoded,AccessError
from app.access.research_service import ResearchService
from app.access.research_app import create_app
from research_workspace_fixture import initialize,disclosure,presentation,sign
from scoped_access_fixture import grant,identifier,PASSWORD,sign as access_sign
from test_scoped_access_api import Client

@pytest.fixture
def env(tmp_path):
    clock=[time.time()];s,k,cfg=initialize(tmp_path,clock=lambda:clock[0]);key=Ed25519PrivateKey.generate();s.review_keys={'review-test':key.public_key().public_bytes_raw()};tokens={};members=[]
    for n,(login,role,scope,sid) in enumerate([('dig','DIG','DIVISION','V1'),('igp','IGP','ALL',None),('hq','HQ_ADMIN','ALL',None)],110):
        a=grant(k,role,scope,sid,'research.'+login,now=clock[0])['payload'];a['user_id']=identifier(n);s.access.put_account(access_sign(k,a),PASSWORD)
        s.import_grant(disclosure(k,user=a['user_id'],now=clock[0],reviews=False));members.append({v:a[v] for v in ('user_id','role','scope_type','scope_id')});tokens[login]=s.access.login(a['username'],PASSWORD,'peer-'+login)
    p=presentation(k,now=clock[0],generation=2)['payload'];p.update(policy=P.RETAINED_POLICY,record_origin='GENERATED_RESEARCH_RECORDS',expires_at=None,full_records=[]);s.import_packet(sign(k,p))
    W.initialize(s);policy=dict(policy=W.POLICY,version=1,supersedes=None,issued_at=int(clock[0]),reason='Explicit generated research policy',accounts=members,request_roles=W.REQUEST,review_roles=W.REVIEW,inspect_roles=W.REQUEST,no_self_approval=True)
    def install(p):
        e=dict(key_id='review-test',payload=deepcopy(p),signature=base64.b64encode(key.sign(encoded(p))).decode());W.install_policy(s,e);return e
    install(policy)
    return dict(store=s,key=k,config=cfg,clock=clock,tokens=tokens,workflow=W.ReviewWorkflow(ResearchService(s)),policy=policy,install=install)

def saved(e):
    p=e['store'].get_packet(identifier(1));b=dict(officer_uid=identifier(1),operation_id=str(uuid4()),finding_id=str(uuid4()),effective_on='2024-12-31',known_at=p['history']['coverage_start'],reason='Retain reported comparison');r=e['workflow'].mutate(*e['tokens']['dig'],'SAVE',b);return b,r
def requested(e,b,r,kind='REVIEW',prior=None):
    p=e['store'].get_packet(identifier(1));q=dict(officer_uid=identifier(1),operation_id=str(uuid4()),finding_id=b['finding_id'],target_head=r['reference'],request_kind=kind,effective_on='2024-12-31' if kind=='CORRECTION' else None,known_at=p['history']['coverage_end'] if kind=='CORRECTION' else None,reason='Inspect evidence and explain',prior_request=prior);return q,e['workflow'].mutate(*e['tokens']['dig'],'REQUEST',q)
def decide(e,r,choice='APPROVE',who='igp'):
    d=dict(officer_uid=identifier(1),operation_id=str(uuid4()),request_reference=r['reference'],decision=choice,reason='Independent reviewer explanation');return d,e['workflow'].mutate(*e['tokens'][who],'DECIDE',d)
def inspect(e,who='hq'):
    return e['workflow'].inspect(*e['tokens'][who],dict(officer_uid=identifier(1),status='ALL',offset=0))

@pytest.mark.parametrize('choice',['APPROVE','REJECT','NEEDS_MORE_EVIDENCE'])
def test_independent_decisions_no_self_review_hq_inspects_only(env,choice):
    e=env;b,r=saved(e);q,req=requested(e,b,r)
    for who in ('dig','hq'):
        with pytest.raises(AccessError):decide(e,req,choice,who)
    d,done=decide(e,req,choice)
    assert inspect(e)['items'][0]['status']==choice and not inspect(e)['items'][0]['can_decide']
    assert e['workflow'].mutate(*e['tokens']['igp'],'DECIDE',d)==done
    assert e['workflow'].recover(e['tokens']['dig'][0],q['operation_id'])['status']==choice
    assert not done['chain_submitted'] and not done['police_authority_issued']

def test_correction_preserves_old_source_and_exact_lost_ack_recovery(env):
    e=env;packet=deepcopy(e['store'].get_packet(identifier(1)));b,r=saved(e);q,req=requested(e,b,r,'CORRECTION');d,done=decide(e,req)
    f=inspect(e)['findings'][0];assert len(f['versions'])==2 and f['versions'][0]['input']==b and f['versions'][1]['supersedes']==r['reference']
    assert e['store'].get_packet(identifier(1))==packet
    assert e['workflow'].mutate(*e['tokens']['dig'],'REQUEST',q)==req
    assert e['workflow'].recover(e['tokens']['igp'][0],d['operation_id'])==done
    assert b'Independent reviewer explanation' not in e['store'].path.read_bytes()
    with pytest.raises(AccessError):e['workflow'].mutate(*e['tokens']['dig'],'SAVE',{**b,'reason':'Changed same ID'})

def test_more_evidence_resubmission_preserves_prior_and_policy_update(env):
    e=env;b,r=saved(e);q,req=requested(e,b,r);decide(e,req,'NEEDS_MORE_EVIDENCE');requested(e,b,r,prior=req['reference'])
    assert len(inspect(e)['items'])==2
    with pytest.raises(AccessError):requested(e,b,r,prior=req['reference'])
    with e['store'].transaction() as c:prior=W.policies(e['store'],c)[-1]
    p={**e['policy'],'version':2,'supersedes':P.fingerprint(prior),'review_roles':[]};e['install'](p)
    with pytest.raises(AccessError):decide(e,req)
    with e['store'].transaction() as c:assert len(W.policies(e['store'],c))==2

def test_scope_csrf_head_source_and_revocation_fail_closed(env):
    e=env;b,r=saved(e);q,req=requested(e,b,r,'CORRECTION');_,other=requested(e,b,r)
    with pytest.raises(AccessError):e['workflow'].mutate(e['tokens']['dig'][0],'bad','SAVE',b)
    with pytest.raises(AccessError):e['workflow'].mutate(*e['tokens']['dig'],'SAVE',{**b,'officer_uid':identifier(4)})
    decide(e,req)
    with pytest.raises(AccessError):decide(e,other)
    p=deepcopy(e['store'].get_packet(identifier(1)));p['generation']+=1;e['store'].import_packet(sign(e['key'],p))
    assert inspect(e)['items'][0]['stale']
    e['clock'][0]+=1800
    with pytest.raises(AccessError):inspect(e)

def test_atomic_failure_blank_reason_invalid_client_role_and_unchanged_correction(env,monkeypatch):
    e=env;b,r=saved(e)
    for change in ({'reason':' '},{'role':'IGP'}):
        with pytest.raises(AccessError):e['workflow'].mutate(*e['tokens']['dig'],'SAVE',{**b,**change})
    q,req=requested(e,b,r)
    with pytest.raises(AccessError):e['workflow'].mutate(*e['tokens']['dig'],'REQUEST',{**q,'operation_id':str(uuid4()),'request_kind':'CORRECTION','effective_on':b['effective_on'],'known_at':b['known_at']})
    original=e['store'].event;monkeypatch.setattr(e['store'],'event',lambda *_:(_ for _ in ()).throw(RuntimeError('interrupted')))
    d=dict(officer_uid=identifier(1),operation_id=str(uuid4()),request_reference=req['reference'],decision='APPROVE',reason='Atomic decision')
    with pytest.raises(RuntimeError):e['workflow'].mutate(*e['tokens']['igp'],'DECIDE',d)
    monkeypatch.setattr(e['store'],'event',original);assert inspect(e)['items'][0]['status']=='PENDING'
    assert e['workflow'].mutate(*e['tokens']['igp'],'DECIDE',d)['status']=='APPROVE'

def test_http_boundaries_and_append_only_policy(env):
    e=env;client=Client(create_app(e['store'],origin='https://access.test:9443'));t,c=e['tokens']['dig'];client.cookie='ppi_session='+t;client.csrf=c
    from app.access.api import COOKIE
    client.cookie=COOKIE+'='+t
    b,r=saved(e)
    assert client.request('/api/research/reviews/save','POST',b)[2]==r
    assert client.request('/api/research/reviews/save','POST',b,csrf='')[0]==403
    assert client.request('/api/research/reviews/save','POST',{**b,'role':'IGP'})[0]==400
    assert client.request('/api/research/reviews/operations/'+b['operation_id'])[0]==200
    import sqlite3
    with e['store'].transaction() as c:
        with pytest.raises(sqlite3.IntegrityError):c.execute('DELETE FROM application_review_entries')
        with pytest.raises(sqlite3.IntegrityError):c.execute('UPDATE application_review_policies SET version=7')

def test_real_https_review_restart_recovery_and_hq_audit(env):
    e=env;s=e['store'];root=e['config'].parent
    from app.access.accountability import AccountabilityStore
    from test_accountability import reader_grant
    from research_workspace_https_fixture import server
    from scoped_access_http_fixture import request as http
    logs=root/'logs';logs.mkdir(mode=0o700);secret=root/'logs.key';secret.write_bytes(os.urandom(32));secret.chmod(0o600)
    AccountabilityStore(logs,secret,access=s.access,create=True)
    reader=root/'reader.json';reader.write_text(json.dumps(reader_grant(e['key'],user=identifier(112),now=e['clock'][0])));reader.chmod(0o600)
    logcfg=root/'logs.json';logcfg.write_text(json.dumps(dict(policy='ACCOUNTABILITY_CONFIG_V1',state_directory=str(logs),key_file=str(secret),reader_grants=[str(reader)])));logcfg.chmod(0o600)
    cfg=json.loads(e['config'].read_text());cfg.update(accountability_config=str(logcfg),review_workflow_keys={k:base64.b64encode(v).decode() for k,v in s.review_keys.items()});e['config'].write_text(json.dumps(cfg))
    b,result=saved(e);q,req=requested(e,b,result)
    with server(root,prepared=(s,e['key'],e['config'])) as (_,_,origin,context,_):
        def login(name):
            status,h,v=http(origin,context,'/api/auth/login',method='POST',body={'username':'research.'+name,'password':PASSWORD});assert status==200;return h['set-cookie'].split(';')[0],v['csrf_token']
        cookie,csrf=login('dig')
        assert http(origin,context,'/api/research/reviews/request',method='POST',body=q,cookie=cookie,csrf=csrf)[2]==req
        d=dict(officer_uid=identifier(1),operation_id=str(uuid4()),request_reference=req['reference'],decision='APPROVE',reason='Independent research approval')
        assert http(origin,context,'/api/research/reviews/decide',method='POST',body=d,cookie=cookie,csrf=csrf)[0]==403
        igp,proof=login('igp');status,_,done=http(origin,context,'/api/research/reviews/decide',method='POST',body=d,cookie=igp,csrf=proof);assert status==200
        assert http(origin,context,'/api/research/reviews/decide',method='POST',body=d,cookie=igp,csrf=proof)[2]==done
        hq,hqproof=login('hq');status,_,events=http(origin,context,'/api/accountability/logs',method='POST',body=dict(limit=100,before_sequence=None,action=None,outcome=None),cookie=hq,csrf=hqproof)
        assert status==200 and any(v['action']=='RESEARCH_REVIEW_DECIDE' and v['reason']=='RESEARCH_DECISION_APPROVE' for v in events['items'])
    with server(root,prepared=(s,e['key'],e['config'])) as (_,_,origin,context,_):
        assert http(origin,context,'/api/auth/session',cookie=igp)[0]==401
        _,h,v=http(origin,context,'/api/auth/login',method='POST',body={'username':'research.igp','password':PASSWORD});fresh=h['set-cookie'].split(';')[0]
        assert http(origin,context,'/api/research/reviews/operations/'+d['operation_id'],cookie=fresh)[2]==done
    log_store=AccountabilityStore(logs,secret,access=s.access)
    with log_store.locked() as database:
        events=log_store.verify(database)[0]
        assert any(v.get('action')=='RESEARCH_REVIEW_OPERATIONS' and v.get('operation_id')==d['operation_id'] for _,v in events)
