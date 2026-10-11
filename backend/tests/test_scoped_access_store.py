import json
import os
import sqlite3
import time
import pytest
from app.access.policy import AccessError
from app.access.store import AccessStore,password_hash
from scoped_access_fixture import PASSWORD,grant,catalog,setup,identifier,sign

@pytest.fixture
def enrolled(tmp_path):
    now=[time.time()];s,key,config=setup(tmp_path,clock=lambda:now[0])
    s.put_account(grant(key,now=now[0]),PASSWORD);s.put_directory(catalog(key,now=now[0]))
    token,csrf=s.login('station.one',PASSWORD,'test-peer')
    return s,key,config,token,csrf,now

def test_scoped_count_pagination_name_nic(enrolled):
    s,k,c,t,csrf,now=enrolled
    r=s.search(t,csrf,'NAME','reported name',1,0)
    assert r['total']==1 and r['items'][0]['officer_uid']==identifier(1)
    assert s.search(t,csrf,'NAME','විහඟ')['total']==1
    assert s.search(t,csrf,'NAME','reported name',1,1)['items']==[]
    assert s.search(t,csrf,'NIC','000000001V')['total']==1
    assert s.search(t,csrf,'NIC','000000005V')['total']==0
    assert s.search(t,csrf,'NIC','000000001v')['total']==0
    assert s.search(t,csrf,'NIC','000000001')['total']==0
    assert s.search(t,csrf,'NIC','  000000001V  ')['total']==1

@pytest.mark.parametrize('target',[2,5,6,999])
def test_direct_officer_hidden_same_as_absent(enrolled,target):
    s,k,c,t,csrf,now=enrolled
    with pytest.raises(AccessError) as e:s.officer(t,identifier(target))
    assert (e.value.status,e.value.code)==(404,'NOT_FOUND')

def test_identity_projection_has_no_details(enrolled):
    s,k,c,t,csrf,now=enrolled
    r=s.officer(t,identifier(1))
    assert set(r)=={'officer_uid','names','nic','identity_status','source_raw_id','projection'}
    assert r['identity_status']=='REPORTED_CANDIDATE_NOT_ACCEPTED'

@pytest.mark.parametrize('change',['revoke','scope','password'])
def test_live_account_version_invalidates_old_session(enrolled,change):
    s,k,c,t,csrf,now=enrolled
    g=grant(k,version=2,active=change!='revoke',scope_id='S2' if change=='scope' else 'S1',now=now[0])
    s.put_account(g,PASSWORD+'-new' if change=='password' else None)
    with pytest.raises(AccessError) as e:s.session(t)
    assert e.value.status==401
    if change=='scope':
        fresh,csrf=s.login('station.one',PASSWORD,'test-peer')
        assert s.search(fresh,csrf,'NAME','reported name')['items'][0]['officer_uid']==identifier(2)

def test_logout_and_session_fixation(enrolled):
    s,k,c,t,csrf,now=enrolled
    fresh,newcsrf=s.login('station.one',PASSWORD,'test-peer',previous=t)
    assert fresh!=t and newcsrf!=csrf
    with pytest.raises(AccessError):s.session(t)
    s.logout(fresh,newcsrf)
    with pytest.raises(AccessError):s.session(fresh)

@pytest.mark.parametrize('delta',[601,1801,-10])
def test_server_clock_timeout_and_reversal(enrolled,delta):
    s,k,c,t,csrf,now=enrolled;now[0]+=delta
    with pytest.raises(AccessError):s.session(t)

def test_grant_expiry_denied_while_session_still_live(enrolled):
    s,k,c,t,csrf,now=enrolled
    g=grant(k,version=2,now=now[0]);g['payload']['expires_at']=int(now[0])+5;s.put_account(sign(k,g['payload']))
    fresh,csrf=s.login('station.one',PASSWORD,'test-peer');now[0]+=6
    with pytest.raises(AccessError) as e:s.session(fresh)
    assert e.value.status==403

def test_directory_expiry_and_generation_update(enrolled):
    s,k,c,t,csrf,now=enrolled
    d=catalog(k,now[0],generation=2);d['payload']['expires_at']=int(now[0])+5;s.put_directory(sign(k,d['payload']))
    now[0]+=6
    with pytest.raises(AccessError) as e:s.search(t,csrf,'NAME','reported name')
    assert e.value.status==503
    s.put_directory(catalog(k,now[0],generation=3))
    assert s.search(t,csrf,'NAME','reported name')['directory_generation']==3

def test_no_generation_or_account_downgrade(enrolled):
    s,k,c,t,csrf,now=enrolled
    with pytest.raises(ValueError):s.put_directory(catalog(k,now[0]))
    with pytest.raises(ValueError):s.put_account(grant(k,now=now[0]))

@pytest.mark.parametrize('csrf',['',None,'wrong'])
def test_csrf_required(enrolled,csrf):
    s,k,c,t,correct,now=enrolled
    with pytest.raises(AccessError) as e:s.search(t,csrf,'NIC','000000001V')
    assert e.value.status==403

def test_uniform_bad_password_unknown_and_disabled(enrolled):
    s,k,c,t,csrf,now=enrolled
    for login,password in [('station.one','wrong-password-long'),('unknown.login',PASSWORD)]:
        with pytest.raises(AccessError) as e:s.login(login,password,'other-peer')
        assert (e.value.status,e.value.code)==(401,'INVALID_CREDENTIALS')
    s.put_account(grant(k,version=2,active=False,now=now[0]))
    with pytest.raises(AccessError) as e:s.login('station.one',PASSWORD,'other-peer')
    assert (e.value.status,e.value.code)==(401,'INVALID_CREDENTIALS')

def test_throttle_survives_restart(enrolled):
    s,k,c,t,csrf,now=enrolled
    for _ in range(4):
        with pytest.raises(AccessError):s.login('station.one','wrong-password-long','peer2')
    s2=AccessStore(s.root,s.key_path,s.keys,repo=s.repo,clock=lambda:now[0])
    with pytest.raises(AccessError) as e:s2.login('station.one',PASSWORD,'peer2')
    assert e.value.status==429
    now[0]+=61
    assert s2.login('station.one',PASSWORD,'peer2')

def test_restart_restored_cookie_cannot_authenticate(enrolled):
    s,k,c,t,csrf,now=enrolled
    s2=AccessStore(s.root,s.key_path,s.keys,repo=s.repo,clock=lambda:now[0])
    with pytest.raises(AccessError):s2.session(t)
    fresh,csrf=s2.login('station.one',PASSWORD,'peer2');assert fresh!=t

def test_persistent_store_contains_no_plaintext_identity_or_session(enrolled):
    s,k,c,t,csrf,now=enrolled
    data=s.path.read_bytes()
    for text in ('Same Reported Name','000000001V',PASSWORD,'station.one',t,csrf):assert text.encode() not in data
    with sqlite3.connect(s.path) as db:
        for table in ('users','directory','sessions','audit'):
            value=db.execute('SELECT value FROM '+table+' LIMIT 1').fetchone()[0]
            assert type(value) is bytes

def test_ciphertext_tampering_is_not_disclosed(enrolled):
    s,k,c,t,csrf,now=enrolled
    with sqlite3.connect(s.path) as db:db.execute("UPDATE directory SET value=X'0000'")
    with pytest.raises(AccessError) as e:s.search(t,csrf,'NAME','reported name')
    assert e.value.status==503

@pytest.mark.parametrize('fault',['symlink','mode','repository','hardlink'])
def test_private_store_refuses_unsafe_paths(enrolled,tmp_path,fault):
    s,k,c,t,csrf,now=enrolled
    if fault=='symlink':
        link=tmp_path/'alias';link.symlink_to(s.root);root=link
    else:root=s.root
    if fault=='mode':os.chmod(root,0o755)
    if fault=='hardlink':os.link(s.path,tmp_path/'db-copy')
    with pytest.raises(ValueError):AccessStore(root,s.key_path,s.keys,repo=tmp_path if fault=='repository' else s.repo)

def test_append_only_audit_triggers(enrolled):
    s,k,c,t,csrf,now=enrolled
    with sqlite3.connect(s.path) as db:
        with pytest.raises(sqlite3.IntegrityError):db.execute('DELETE FROM audit')
        with pytest.raises(sqlite3.IntegrityError):db.execute("UPDATE audit SET digest='x'")

def test_password_salt_is_unique_and_never_plaintext():
    a=password_hash(PASSWORD);b=password_hash(PASSWORD)
    assert a!=b and PASSWORD not in json.dumps(a)

def test_one_canonical_login_per_user_identity(enrolled):
    s,k,c,t,csrf,now=enrolled
    with pytest.raises(sqlite3.IntegrityError):s.put_account(grant(k,login='other.login',now=now[0]),PASSWORD)
    assert s.session(t)['username']=='station.one'


def test_directory_membership_refresh_applies_to_existing_session(enrolled):
    s,k,c,t,csrf,now=enrolled
    d=catalog(k,now[0],generation=2)
    d['payload']['officers'][0]['membership']['STATION']='S2'
    s.put_directory(sign(k,d['payload']))
    assert s.search(t,csrf,'NIC','000000001V')['total']==0
    with pytest.raises(AccessError) as e:s.officer(t,identifier(1))
    assert e.value.status==404


def test_search_parameterization_and_no_out_of_scope_match_count(enrolled):
    s,k,c,t,csrf,now=enrolled
    assert s.search(t,csrf,'NAME',"%' OR 1=1 --")['total']==0
    assert s.search(t,csrf,'NAME','name 5')['total']==0


def test_later_auth_key_mismatch_fails_closed(enrolled):
    s,k,c,t,csrf,now=enrolled
    wrong=s.root.parent/'wrong.key';wrong.write_bytes(b'Z'*32);wrong.chmod(0o600)
    with pytest.raises(Exception):AccessStore(s.root,wrong,s.keys,repo=s.repo)
