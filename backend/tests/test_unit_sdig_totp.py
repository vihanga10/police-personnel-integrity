import base64,hashlib,json,os,sqlite3,sys,time
from pathlib import Path
from copy import deepcopy
import pytest
from unit_totp_fixture import setup,REPO,M,PASSWORD,AccessStore,ResearchStore
sys.path.insert(0,str(REPO/'backend/scripts'))
import setup_unit_sdig_totp as U
from app.access import totp,full_source_profiles as F,review_workflow as W,policy as A,research_policy as P
from app.access.research_service import ResearchService
from app.access.unit_dashboard import dashboard
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def prepare(d):
    w=d['w'];w.clock=time.time;key=d['wsk'];now=int(time.time());profiles=[]
    for n,o in enumerate(d['members']):
        records=[dict(dataset='officer_personal_information.csv',raw_record_id=f'{n+1:064x}',fields={'full_name':f'Invented Unit Officer {n}'}),
          dict(dataset='officer_service_information.csv',raw_record_id=f'{n+20:064x}',fields={
          'current_rank':'Senior Deputy Inspector General of Police','current_unit_type':'CID' if n==0 else 'CCIB',
          'current_unit_name':'Criminal Investigation Department' if n==0 else 'Central Crime Investigation Bureau',
          'current_police_no':f'00{n}','service_status':'Active','current_division':'A' if n==0 else 'B'})]
        p=dict(policy=F.POLICY,kind='SOURCE_PROFILE',record_origin='GENERATED_RESEARCH_RECORDS',issued_at=now,generation=1,
            source_public_sha256='a'*64,source_context_sha256='c'*64,officer_uid=o['officer_uid'],full_records=records,reported_posting=F.posting(records))
        profiles.append(M.sign(key,'workspace-test',p))
    meta=M.sign(key,'workspace-test',dict(policy=F.POLICY,kind='SOURCE_SET',record_origin='GENERATED_RESEARCH_RECORDS',issued_at=now,
         generation=1,source_public_sha256='a'*64,source_context_sha256='c'*64,profiles={w.index('SOURCE_PROFILE',e['payload']['officer_uid']):F.P.fingerprint(e) for e in profiles}))
    with sqlite3.connect(w.path) as c:
        c.executescript(F.SCHEMA)
        c.execute('INSERT INTO source_profile_sets VALUES(?,?)',(1,w.seal('SOURCE_SET',1,meta)))
        for e in profiles:
            ident=w.index('SOURCE_PROFILE',e['payload']['officer_uid'])
            c.execute('INSERT INTO source_profiles VALUES(?,?,?)',(1,ident,w.seal('SOURCE_PROFILE',[1,ident],e)))
    signer=Ed25519PrivateKey.generate();seed=signer.private_bytes_raw()
    for folder in ('keys','key-backup'):
        p=d['app']/folder/'research-review-policy.key';p.write_bytes(seed);p.chmod(0o600)
    w.review_keys={'review-test':signer.public_key().public_bytes_raw()}
    cfg=json.loads((d['app']/'workspace-config.json').read_text());cfg['review_workflow_keys']={'review-test':base64.b64encode(signer.public_key().public_bytes_raw()).decode()}
    (d['app']/'workspace-config.json').write_bytes(A.encoded(cfg))
    W.install_policy(w,M.sign(signer,'review-test',dict(policy=W.POLICY,version=1,supersedes=None,issued_at=now,
        reason='Invented fixture policy',accounts=[{k:u[k] for k in ('user_id','role','scope_type','scope_id')} for u in d['accounts'] if u['active']],
        request_roles=W.REQUEST,review_roles=W.REVIEW,inspect_roles=W.REQUEST,no_self_approval=True)))

def rows(d):
    result={}
    for name,path in [('a',d['a'].path),('w',d['w'].path),('l',d['l'].db)]:
        with sqlite3.connect(path) as c:
            for table, in c.execute("SELECT name FROM sqlite_master WHERE type='table'"):
                result[name,table]=c.execute('SELECT * FROM '+table+' ORDER BY 1').fetchall()
    return result

def test_rfc6238_vector_and_invalid_format():
    seed=base64.b32encode(b'12345678901234567890').decode()
    assert totp.code(seed,59//30)=='287082'
    assert totp.code(seed,1111111109//30)=='081804'

def test_missing_required_totp_tables_do_not_disable_authentication(setup):
    d=setup;d['a'].require_totp=True
    with d['a'].transaction() as c:
        with pytest.raises(ValueError):totp.required(d['a'],c)

def test_preview_read_only_and_production_count_guard(setup):
    d=setup;prepare(d);before=rows(d);x=U.S.load(REPO,d['app']);c=U.S.connect(x,True)
    try:
        p=U.plan(x,c,expected=None);assert p['summary']['accounts']==12
        with pytest.raises(ValueError):U.plan(x,c)
    finally:c.close()
    assert before==rows(d) and not (d['app']/'totp-enrollment-private.json').exists()

def test_complete_scope_totp_dashboard_and_retained_evidence(setup):
    d=setup;prepare(d);before=rows(d);result=U.execute(U.S.load(REPO,d['app']),expected=None);after=rows(d)
    assert result['accounts']==12 and result['active_accounts']==11
    for table in [('w','presentations'),('w','source_profiles'),('w','source_profile_sets'),('w','application_review_entries'),('w','requests')]:assert after[table]==before[table]
    assert after['l','events'][:-1]==before['l','events']
    creds=json.loads((d['app']/'credentials.json').read_text());assert creds['research.sdig']==PASSWORD
    enroll={p['username']:p for p in json.loads((d['app']/'totp-enrollment-private.json').read_text())['accounts']}
    assert len(enroll)==11 and len({p['secret'] for p in enroll.values()})==11
    a=AccessStore(d['a'].root,d['a'].key_path,d['a'].keys,repo=REPO)
    w=ResearchStore(d['w'].root,d['app']/'keys/workspace.key',d['w'].keys,access=a)
    for login,target in [('research.sdig',0),('research.sdig.ccib',1)]:
        with pytest.raises(A.AccessError):a.login(login,creds[login],'fixture-no-code')
        token,csrf=a.login(login,creds[login],'fixture-'+login,totp_code=totp.code(enroll[login]['secret'],int(time.time())//30))
        assert a.session(token)['scope_type']=='UNIT'
        service=ResearchService(w);answer=dashboard(service,token);assert answer['officers']==1 and answer['status_counts']=={'Active':1}
        assert service.workspace(token,d['members'][target]['officer_uid'])['identity']['officer_uid']==d['members'][target]['officer_uid']
        with pytest.raises(A.AccessError):service.workspace(token,d['members'][1-target]['officer_uid'])
        with pytest.raises(A.AccessError):a.login(login,creds[login],'replay-'+login,totp_code=totp.code(enroll[login]['secret'],int(time.time())//30))
    inactive='research.dig.b.inactive'
    with pytest.raises(A.AccessError):a.login(inactive,creds[inactive],'inactive',totp_code='000000')
    # No factor or enrollment seed is written as plaintext into encrypted databases.
    assert all(p['secret'].encode() not in d['a'].path.read_bytes() for p in enroll.values())
    previous_manifest=json.loads((d['app']/'accounts.json').read_text())
    U.execute(U.S.load(REPO,d['app']),expected=None)
    renewed=json.loads((d['app']/'accounts.json').read_text())
    assert [(p['user_id'],p['scope_type'],p['scope_id'],p['active']) for p in renewed['accounts']]==[(p['user_id'],p['scope_type'],p['scope_id'],p['active']) for p in previous_manifest['accounts']]
    assert json.loads((d['app']/'credentials.json').read_text())==creds
    assert {p['username']:p['secret'] for p in json.loads((d['app']/'totp-enrollment-private.json').read_text())['accounts']}=={u:p['secret'] for u,p in enroll.items()}

def test_database_interruption_rolls_back(setup,monkeypatch):
    d=setup;prepare(d);before=rows(d)
    def fail(*a):raise OSError('Invented interruption')
    monkeypatch.setattr(AccessStore,'_audit',fail)
    with pytest.raises(OSError):U.execute(U.S.load(REPO,d['app']),expected=None)
    assert rows(d)==before
    attempt=next((d['app']/'unit-sdig-totp-attempts').iterdir())
    assert U.S.job_read(U.S.load(REPO,d['app']),attempt)['phase']=='ROLLED_BACK'

def test_private_file_interruption_recovers_without_duplicate_changes(setup,monkeypatch):
    d=setup;prepare(d);original=U.S.write_new
    def fail(path,data):
        if path.name.startswith('unit-setup-'):raise OSError('Invented output interruption')
        return original(path,data)
    monkeypatch.setattr(U.S,'write_new',fail)
    with pytest.raises(OSError):U.execute(U.S.load(REPO,d['app']),expected=None)
    committed=rows(d);attempt=next((d['app']/'unit-sdig-totp-attempts').iterdir())
    monkeypatch.setattr(U.S,'write_new',original)
    U.recover(U.S.load(REPO,d['app']),attempt)
    assert rows(d)==committed
    U.recover(U.S.load(REPO,d['app']),attempt);assert rows(d)==committed

def test_all_active_accounts_require_totp_through_https_boundary(setup):
    from app.access.api import create_app
    from test_scoped_access_api import Client
    d=setup;prepare(d);U.execute(U.S.load(REPO,d['app']),expected=None)
    creds=json.loads((d['app']/'credentials.json').read_text())
    enroll={p['username']:p for p in json.loads((d['app']/'totp-enrollment-private.json').read_text())['accounts']}
    a=AccessStore(d['a'].root,d['a'].key_path,d['a'].keys,repo=REPO)
    app=create_app(a,origin='https://access.test:9443')
    for login,item in enroll.items():
        client=Client(app)
        body=dict(username=login,password=creds[login])
        status,headers,result=client.request('/api/auth/login','POST',body)
        if status==429:
            a.clock=lambda:time.time()+61
            status,headers,result=client.request('/api/auth/login','POST',body)
        assert status==401 and not any(k=='set-cookie' for k,v in headers)
        body['totp_code']=totp.code(item['secret'],int(a.clock())//30)
        status,headers,result=client.request('/api/auth/login','POST',body)
        # Independent peer IDs in ASGI scope would hide the real shared-peer
        # throttle; advance its observation clock after each fixture pair.
        if status==429:
            a.clock=lambda:time.time()+61
            body['totp_code']=totp.code(item['secret'],int(a.clock())//30)
            status,headers,result=client.request('/api/auth/login','POST',body)
        assert status==200
        client.cookie=next(v for k,v in headers if k=='set-cookie').split(';')[0]
        assert client.request('/api/auth/session')[0]==200
        assert all(item['secret'] not in v for k,v in headers)

def test_https_unit_dashboard_browse_and_direct_query_isolation(setup):
    from app.access.research_app import create_app
    from test_scoped_access_api import Client
    d=setup;prepare(d);U.execute(U.S.load(REPO,d['app']),expected=None)
    enroll={p['username']:p for p in json.loads((d['app']/'totp-enrollment-private.json').read_text())['accounts']}
    a=AccessStore(d['a'].root,d['a'].key_path,d['a'].keys,repo=REPO)
    w=ResearchStore(d['w'].root,d['app']/'keys/workspace.key',d['w'].keys,access=a)
    w.accountability=None;w.workflow_keys={};w.review_keys={}
    client=Client(create_app(w,origin='https://access.test:9443',assets=REPO/'frontend/research'))
    status,headers,result=client.request('/api/auth/login','POST',dict(username='research.sdig',password=PASSWORD,
        totp_code=totp.code(enroll['research.sdig']['secret'],int(a.clock())//30)))
    assert status==200;client.cookie=next(v for k,v in headers if k=='set-cookie').split(';')[0];client.csrf=result['csrf_token']
    assert client.request('/api/research/unit-dashboard')[2]['officers']==1
    status,headers,result=client.request('/api/research/browse','POST',dict(kind='NAME',query='',availability='ALL',level='ALL',scope_id='',limit=25,offset=0))
    assert status==200 and result['total']==1 and result['items'][0]['unit_type']=='CID'
    assert result['items'][0]['officer_uid']==d['members'][0]['officer_uid']
    other=d['members'][1]['officer_uid']
    assert client.request('/api/research/officers/'+other)[0]==404
    assert client.request('/api/research/history','POST',dict(officer_uid=other,effective_on='2024-01-01',known_at='2026-10-14T00:00:00Z'))[0]==404

def test_real_tls_totp_login_dashboard_and_logout(setup):
    from research_workspace_https_fixture import server
    from scoped_access_http_fixture import request
    d=setup;prepare(d);U.execute(U.S.load(REPO,d['app']),expected=None)
    enroll={p['username']:p for p in json.loads((d['app']/'totp-enrollment-private.json').read_text())['accounts']}
    with server(d['app'],prepared=(d['w'],d['wsk'],d['app']/'workspace-config.json')) as (_,_,origin,context,_):
        status,headers,result=request(origin,context,'/api/auth/login',method='POST',body={'username':'research.sdig','password':PASSWORD})
        assert status==401
        body={'username':'research.sdig','password':PASSWORD,'totp_code':totp.code(enroll['research.sdig']['secret'],int(time.time())//30)}
        status,headers,result=request(origin,context,'/api/auth/login',method='POST',body=body)
        assert status==200
        cookie=headers['set-cookie'].split(';')[0];csrf=result['csrf_token']
        status,_,result=request(origin,context,'/api/research/unit-dashboard',cookie=cookie)
        assert status==200 and result['unit']=='CID' and result['officers']==1
        status,_,result=request(origin,context,'/api/auth/logout',method='POST',body={},cookie=cookie,csrf=csrf)
        assert status==200
        assert request(origin,context,'/api/research/unit-dashboard',cookie=cookie)[0]==401

def test_reviewed_full_unit_counts_and_all_criminal_divisions(setup):
    from uuid import uuid4
    d=setup;prepare(d);w=d['w'];a=d['a'];a.clock=time.time
    now=int(time.time());records=[];members=[]
    for unit,total in [('CID',150),('CCIB',149),('Criminal Division',705)]:
        for n in range(total):
            seq=len(members)+1;uid=str(uuid4())
            members.append(dict(officer_uid=uid,nic=f'{900000000+seq}V',names=[f'Invented {unit} Officer {n+1}'],source_raw_id=f'{seq:064x}',
                membership=dict(PROVINCE='P',DISTRICT='D',DIVISION='A' if seq%2 else 'B',STATION='SA' if seq%2 else 'SB')))
            rows0=[dict(dataset='officer_personal_information.csv',raw_record_id=f'{seq:064x}',fields={'full_name':members[-1]['names'][0]}),
                   dict(dataset='officer_service_information.csv',raw_record_id=f'{seq+2000:064x}',fields={'current_unit_type':unit,
                   'current_unit_name':unit,'current_rank':'Sub Inspector of Police','current_division':'A' if seq%2 else 'B','service_status':'Active'})]
            records.append(M.sign(d['wsk'],'workspace-test',dict(policy=F.POLICY,kind='SOURCE_PROFILE',record_origin='GENERATED_RESEARCH_RECORDS',
                issued_at=now,generation=2,source_public_sha256='a'*64,source_context_sha256='c'*64,officer_uid=uid,full_records=rows0,reported_posting=F.posting(rows0))))
    with a.transaction() as c:old=a._directory(c)
    a.put_directory(M.sign(d['ask'],'access-test',{**old,'generation':2,'issued_at':now,'officers':members}))
    meta=M.sign(d['wsk'],'workspace-test',dict(policy=F.POLICY,kind='SOURCE_SET',record_origin='GENERATED_RESEARCH_RECORDS',issued_at=now,
         generation=2,source_public_sha256='a'*64,source_context_sha256='c'*64,profiles={w.index('SOURCE_PROFILE',e['payload']['officer_uid']):F.P.fingerprint(e) for e in records}))
    from research_workspace_fixture import disclosure
    with w.transaction() as c:
        c.execute('INSERT INTO source_profile_sets VALUES(?,?)',(2,w.seal('SOURCE_SET',2,meta)))
        c.execute('DELETE FROM disclosures')
        for e in records:
            uid=e['payload']['officer_uid'];ident=w.index('SOURCE_PROFILE',uid)
            c.execute('INSERT INTO source_profiles VALUES(?,?,?)',(2,ident,w.seal('SOURCE_PROFILE',[2,ident],e)))
            g=disclosure(d['wsk'],user=d['accounts'][1]['user_id'],officer=uid,now=now,reviews=False)['payload']
            g.update(policy=P.RETAINED_POLICY,expires_at=now+86398)
            g=M.sign(d['wsk'],'workspace-test',g);ident=w.index('GRANT',d['accounts'][1]['user_id'],uid)
            c.execute('INSERT INTO disclosures VALUES(?,?,?)',(ident,g['payload']['issued_at'],w.seal('GRANT',ident,g)))
    U.execute(U.S.load(REPO,d['app']))
    creds=json.loads((d['app']/'credentials.json').read_text());seeds={u['username']:u['secret'] for u in json.loads((d['app']/'totp-enrollment-private.json').read_text())['accounts']}
    a=AccessStore(a.root,a.key_path,a.keys,repo=REPO);w=ResearchStore(w.root,d['app']/'keys/workspace.key',w.keys,access=a)
    for login,count in [('research.sdig',150),('research.sdig.ccib',149),('research.sdig.criminal',705)]:
        token,csrf=a.login(login,creds[login],login,totp_code=totp.code(seeds[login],int(a.clock())//30))
        result=dashboard(ResearchService(w),token)
        assert result['officers']==result['details_available']==count
        if login.endswith('criminal'):assert result['divisions']==2
