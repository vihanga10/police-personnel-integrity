"""Until-revoked access must never extend a browser session or weaken revocation."""
import json,sqlite3,sys,time
from copy import deepcopy
from pathlib import Path
import pytest
from cryptography.exceptions import InvalidSignature
from unit_totp_fixture import setup,REPO,M,PASSWORD,AccessStore,ResearchStore
from test_unit_sdig_totp import prepare,rows
sys.path.insert(0,str(REPO/'backend/scripts'))
import manage_persistent_access as N
import setup_unit_sdig_totp as U
from app.access import policy as A,research_policy as P,accountability as L,totp
from app.access.research_service import ResearchService

def configured(d):
    prepare(d);U.execute(U.S.load(REPO,d['app']),expected=None)
    x=U.S.load(REPO,d['app']);x.a.clock=lambda:time.time()+5
    return x

def test_migration_preview_preserves_every_database_and_private_file(setup):
    d=setup;x=configured(d);before=rows(d)
    files={p:p.read_bytes() for p in d['app'].rglob('*') if p.is_file()}
    c=N.S.connect(x,True)
    try:p=N.plan(x,c)
    finally:c.close()
    assert p['summary']['accounts']==12 and not p['already']
    assert rows(d)==before and all(p.read_bytes()==v for p,v in files.items())

def test_all_accounts_keep_identity_password_totp_scopes_and_evidence(setup):
    d=setup;x=configured(d);before=rows(d)
    saved={p:p.read_bytes() for p in (d['app']/'credentials.json',d['app']/'totp-enrollment-private.json')}
    old=json.loads((d['app']/'accounts.json').read_text())['accounts']
    result=N.execute(x);after=rows(d)
    assert result['status']=='SIGNED_UNTIL_REVOKED_ACCESS_ENABLED'
    new=json.loads((d['app']/'accounts.json').read_text())['accounts']
    for a,b in zip(old,new):
        assert b=={**a,'policy':A.PERSISTENT_ACCOUNT_POLICY,'issued_at':int(x.a.clock()),'expires_at':None,'version':a['version']+1}
    for table in before:
        if table not in [('a','users'),('a','sessions'),('a','audit'),('w','disclosures'),('w','events'),('l','events')]:assert before[table]==after[table],table
    for p,v in saved.items():assert p.read_bytes()==v
    for a,b in zip(before['a','users'],after['a','users']):
        assert d['a'].open('USER',a[0],a[2],a[3])['password']==d['a'].open('USER',b[0],b[2],b[3])['password']
    again=N.S.load(REPO,d['app']);again.a.clock=x.a.clock
    assert N.execute(again)['status'].endswith('ALREADY_CONFIGURED')
    assert rows(d)==after

def test_later_login_totp_scope_fixed_expiry_and_inactive_denial(setup):
    d=setup;N.execute(configured(d));clock=[time.time()+31*86400]
    a=AccessStore(d['a'].root,d['a'].key_path,d['a'].keys,repo=REPO,clock=lambda:clock[0])
    w=ResearchStore(d['w'].root,d['app']/'keys/workspace.key',d['w'].keys,access=a);w.clock=lambda:clock[0];s=ResearchService(w)
    seeds={p['username']:p['secret'] for p in json.loads((d['app']/'totp-enrollment-private.json').read_text())['accounts']}
    creds=json.loads((d['app']/'credentials.json').read_text())
    with pytest.raises(A.AccessError):a.login('research.sdig',PASSWORD,'missing-code')
    token,csrf=a.login('research.sdig',creds['research.sdig'],'valid-code',totp_code=totp.code(seeds['research.sdig'],int(clock[0])//30))
    start=clock[0];assert a.session(token)['expires_at']==start+1800
    assert s.workspace(token,d['members'][0]['officer_uid'])['identity']['officer_uid']==d['members'][0]['officer_uid']
    with pytest.raises(A.AccessError):s.workspace(token,d['members'][1]['officer_uid'])
    clock[0]=start+1799;assert a.session(token)['expires_at']==start+1800
    clock[0]=start+1800
    with pytest.raises(A.AccessError):a.session(token)
    with pytest.raises(A.AccessError):a.login('research.dig.b.inactive',creds['research.dig.b.inactive'],'inactive',totp_code='000000')

def test_signed_policy_domains_signature_and_legacy_expiry(setup):
    d=setup;x=configured(d);c=N.S.connect(x,True)
    try:p=N.plan(x,c)
    finally:c.close()
    fresh=p['updates'][0][3];env=M.sign(d['ask'],'access-test',fresh);now=fresh['issued_at']+365*86400
    assert A.account(env,x.a.keys,now=now)['expires_at'] is None
    for change in ({'policy':A.POLICY},{'kind':'DIRECTORY'},{'issued_at':now+1},{'expires_at':now+50}):
        with pytest.raises(ValueError):A.account(M.sign(d['ask'],'access-test',{**fresh,**change}),x.a.keys,now=now)
    bad=deepcopy(env);bad['payload']['role']='IGP' if fresh['role']!='IGP' else 'DIG'
    with pytest.raises(InvalidSignature):A.account(bad,x.a.keys,now=now)
    legacy={**fresh,'policy':A.POLICY,'expires_at':fresh['issued_at']+100}
    with pytest.raises(ValueError):A.account(M.sign(d['ask'],'access-test',legacy),x.a.keys,now=now)
    g=p['grants'][0][1];assert P.grant(g,x.w.keys,now)['expires_at'] is None
    with pytest.raises(ValueError):P.grant(M.sign(d['wsk'],'workspace-test',{**g['payload'],'policy':P.RETAINED_POLICY}),x.w.keys,now)

def test_database_failure_rolls_back_and_private_file_failure_recovers(setup,monkeypatch):
    d=setup;x=configured(d);before=rows(d);audit=AccessStore._audit
    def fail(*args):raise OSError('isolated write failure')
    monkeypatch.setattr(AccessStore,'_audit',fail)
    with pytest.raises(OSError):N.execute(x)
    assert rows(d)==before
    monkeypatch.setattr(AccessStore,'_audit',audit);write=N.S.write_new
    def fail_file(path,data):
        if path.name.startswith('unit-setup-'):raise OSError('isolated rename interruption')
        return write(path,data)
    monkeypatch.setattr(N.S,'write_new',fail_file)
    with pytest.raises(OSError):N.execute(x)
    committed=rows(d);attempt=next(p for p in (d['app']/'persistent-access-attempts').iterdir() if N.S.job_read(x,p)['phase']=='DATABASES_COMMITTED')
    monkeypatch.setattr(N.S,'write_new',write)
    N.recover(N.S.load(REPO,d['app']),attempt);assert rows(d)==committed
    N.recover(N.S.load(REPO,d['app']),attempt);assert rows(d)==committed

def test_persistent_log_reader_remains_version_bound(setup):
    d=setup;N.execute(configured(d));x=N.S.load(REPO,d['app']);x.a=AccessStore(d['a'].root,d['a'].key_path,d['a'].keys,repo=REPO,clock=lambda:time.time()+400*86400);x.l.access=x.a;x.l.clock=x.a.clock
    for file in x.l.grant_files:
        g=x.l.load_grant(file);assert g['expires_at'] is None and g['policy']==L.PERSISTENT_READER_POLICY
        with x.a.transaction() as c:u=next(x.a.open('USER',i,v,b)['grant']['payload'] for i,v,b in c.execute('SELECT id,version,value FROM users') if x.a.open('USER',i,v,b)['grant']['payload']['user_id']==g['user_id'])
        token,csrf=x.a.login(u['username'],PASSWORD,'log-reader',totp_code=totp.code(next(p['secret'] for p in json.loads((d['app']/'totp-enrollment-private.json').read_text())['accounts'] if p['username']==u['username']),int(x.a.clock())//30))
        assert x.l.reader(token)['user_id']==u['user_id']
        ident=x.a.index('USER',u['username'])
        with x.a.transaction() as c:
            v,b=c.execute('SELECT version,value FROM users WHERE id=?',(ident,)).fetchone();value=x.a.open('USER',ident,v,b);fresh={**u,'version':v+1};value['grant']=M.sign(d['ask'],'access-test',fresh)
            c.execute('UPDATE users SET version=?,value=? WHERE id=?',(v+1,x.a.seal('USER',ident,v+1,value),ident))
        with pytest.raises(A.AccessError):x.l.reader(token)

def test_future_import_lifetime_matches_account_policy():
    assert P.disclosure_lifetime({'policy':A.PERSISTENT_ACCOUNT_POLICY,'expires_at':None},100,150)=={'policy':P.PERSISTENT_DISCLOSURE_POLICY,'expires_at':None}
    assert P.disclosure_lifetime({'policy':A.POLICY,'expires_at':140},100,150)=={'policy':P.RETAINED_POLICY,'expires_at':140}

def test_https_login_countdown_and_log_metadata_after_daily_boundary(setup):
    from app.access.research_app import create_app
    from test_scoped_access_api import Client
    d=setup;N.execute(configured(d));clock=[time.time()+2*86400]
    a=AccessStore(d['a'].root,d['a'].key_path,d['a'].keys,repo=REPO,clock=lambda:clock[0])
    w=ResearchStore(d['w'].root,d['app']/'keys/workspace.key',d['w'].keys,access=a)
    logs=L.AccountabilityStore(d['l'].root,d['app']/'keys/log.key',access=a);logs.grant_files=d['l'].grant_files;w.accountability=logs;w.workflow_keys={};w.review_keys={}
    client=Client(create_app(w,origin='https://access.test:9443',assets=REPO/'frontend/research'))
    seed=next(p['secret'] for p in json.loads((d['app']/'totp-enrollment-private.json').read_text())['accounts'] if p['username']=='research.hq')
    status,headers,result=client.request('/api/auth/login','POST',dict(username='research.hq',password=PASSWORD,totp_code=totp.code(seed,int(clock[0])//30)))
    assert status==200
    client.cookie=next(v for k,v in headers if k=='set-cookie').split(';')[0];client.csrf=result['csrf_token']
    assert client.request('/api/auth/session')[2]['expires_at']==clock[0]+1800
    status,_,result=client.request('/api/accountability/logs','POST',dict(limit=25,before_sequence=None,action=None,outcome=None))
    assert status==200 and result['items']
    assert logs.login_metadata(client.cookie.split('=',1)[1])['deadline_reason']=='FIXED_30_MINUTE_LIMIT'
    clock[0]+=1800
    assert client.request('/api/auth/session')[0]==401

def test_later_administrative_unit_setup_preserves_until_revoked_policy(setup):
    d=setup;N.execute(configured(d))
    x=U.S.load(REPO,d['app']);c=U.S.connect(x,True)
    try:p=U.plan(x,c,expected=None)
    finally:c.close()
    assert p['summary']['authorization_expires_at_utc'] is None
    assert all(u['expires_at'] is None and u['policy']==A.PERSISTENT_ACCOUNT_POLICY for _,_,_,u,_ in p['updates'])
    assert all(e['payload']['expires_at'] is None and e['payload']['policy']==P.PERSISTENT_DISCLOSURE_POLICY for e in p['grants'].values())
    assert all(e['payload']['expires_at'] is None and e['payload']['policy']==L.PERSISTENT_READER_POLICY for e in [j['new'] for j in p['files']] if isinstance(e,dict) and 'payload' in e)

def test_all_twelve_accounts_after_thirty_one_days(setup):
    d=setup;N.execute(configured(d));now=time.time()+31*86400
    a=AccessStore(d['a'].root,d['a'].key_path,d['a'].keys,repo=REPO,clock=lambda:now)
    accounts=json.loads((d['app']/'accounts.json').read_text())['accounts']
    seeds={p['username']:p['secret'] for p in json.loads((d['app']/'totp-enrollment-private.json').read_text())['accounts']}
    passwords=json.loads((d['app']/'credentials.json').read_text());success=0
    for user in accounts:
        login=user['username'];code=totp.code(seeds[login],int(now)//30) if user['active'] else '000000'
        if not user['active']:
            with pytest.raises(A.AccessError):a.login(login,passwords[login],login,totp_code=code)
            continue
        token,_=a.login(login,passwords[login],login,totp_code=code);session=a.session(token)
        assert all(session[k]==user[k] for k in ('username','role','scope_type','scope_id'))
        assert session['expires_at']==now+1800;success+=1
    assert success==11 and len(accounts)==12
