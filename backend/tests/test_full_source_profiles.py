from copy import deepcopy
import time
import pytest
from app.access import full_source_profiles as F
from app.access.policy import AccessError
from app.access.research_service import ResearchService
from research_workspace_fixture import initialize, sign, identifier, PASSWORD, disclosure
from scoped_access_fixture import grant as account
from test_scoped_officer_browser import request

@pytest.fixture
def env(tmp_path):
    clock=[time.time()]
    store,key,_=initialize(tmp_path,clock=lambda:clock[0]);clock[0]+=2
    return store,key

def payloads(store,key):
    now=int(store.clock());profiles=[];grants=[]
    for n in range(1,7):
        rows=[dict(dataset='officer_personal_information.csv',raw_record_id=f'{n:064x}',fields={'full_name':f'Officer {n}'}),
              dict(dataset='officer_service_information.csv',raw_record_id=f'{n+10:064x}',fields={'current_division':f'Reported Division {n}','current_station':f'Reported Station {n}','current_station_code':f'SRC{n}'})]
        profiles.append(sign(key,dict(policy=F.POLICY,kind='SOURCE_PROFILE',record_origin='GENERATED_RESEARCH_RECORDS',issued_at=now,generation=1,source_public_sha256='a'*64,source_context_sha256='c'*64,officer_uid=identifier(n),full_records=rows,reported_posting=F.posting(rows))))
        grants.append(disclosure(key,officer=identifier(n),now=now,reviews=False))
    meta=sign(key,dict(policy=F.POLICY,kind='SOURCE_SET',record_origin='GENERATED_RESEARCH_RECORDS',issued_at=now,generation=1,source_public_sha256='a'*64,source_context_sha256='c'*64,profiles={store.index('SOURCE_PROFILE',e['payload']['officer_uid']):F.P.fingerprint(e) for e in profiles}))
    return profiles,meta,grants

def test_full_source_records_encrypted_and_existing_histories_preserved(env):
    store,key=env;profiles,meta,grants=payloads(store,key);old=store.get_packet(identifier(1))
    F.publish(store,profiles,meta,grants)
    assert store.get_packet(identifier(1))==old
    assert store.get_grant(identifier(100),identifier(1))['request_reviews'] is True
    assert F.profile(store,identifier(2),'a'*64)['reported_posting']['station']=='Reported Station 2'
    assert b'Reported Station' not in store.path.read_bytes()

def test_hq_opens_all_profiles_but_no_fake_historical_coverage(env):
    store,key=env;store.access.put_account(account(key,'HQ_ADMIN','ALL',None,version=2))
    profiles,meta,grants=payloads(store,key);grants=[sign(key,{**g['payload'],'account_version':2}) for g in grants]
    F.publish(store,profiles,meta,grants);token,csrf=store.access.login('station.one',PASSWORD,'fixture-peer');service=ResearchService(store)
    answer=service.browse(token,csrf,request());assert answer['total']==6 and all(o['details_available'] for o in answer['items'])
    assert all(o['reported_posting']['station'].startswith('Reported Station') for o in answer['items'])
    for n in range(2,7):
        w=service.workspace(token,identifier(n));assert len(w['full_records'])==2 and w['evidence_view']=='SIGNED_FULL_SOURCE_PROFILE'
        assert w['coverage_start'] is None and not w['can_request_review']
        with pytest.raises(AccessError) as e:service.history(token,csrf,identifier(n),'2024-12-31','2026-10-13T00:00:00Z')
        assert e.value.code=='HISTORICAL_WORKSPACE_NOT_CONNECTED'
    assert service.workspace(token,identifier(1))['evidence_view']=='SIGNED_OBSERVED_COPY'

def test_scope_first_and_missing_disclosure_still_deny(env):
    store,key=env;profiles,meta,grants=payloads(store,key);F.publish(store,profiles,meta,[])
    token,csrf=store.access.login('station.one',PASSWORD,'fixture-peer')
    with pytest.raises(AccessError) as e:ResearchService(store).workspace(token,identifier(2))
    assert e.value.status==404
    store.access.put_account(account(key,'HQ_ADMIN','ALL',None,version=2))
    token,csrf=store.access.login('station.one',PASSWORD,'fixture-peer')
    with pytest.raises(AccessError):ResearchService(store).workspace(token,identifier(2))

def test_tampering_missing_rows_and_atomic_failure(env):
    store,key=env;profiles,meta,grants=payloads(store,key);bad=deepcopy(profiles);bad[0]['payload']['officer_uid']=identifier(999)
    with pytest.raises(Exception):F.publish(store,bad,meta,grants)
    with pytest.raises(Exception):F.publish(store,profiles[:-1],meta,grants)
    checks=[0]
    def fail_end():
        checks[0]+=1
        if checks[0]==2:raise ValueError('Expired permit fixture')
    with pytest.raises(ValueError):F.publish(store,profiles,meta,grants,check=fail_end)
    assert F.active_set(store) is None and store.get_packet(identifier(1))['generation']==1
    F.publish(store,profiles,meta,grants)
    with store.transaction() as c:c.execute('UPDATE source_profiles SET value=? WHERE id=?',(b'corrupt',store.index('SOURCE_PROFILE',identifier(2))))
    with pytest.raises(Exception):F.profile(store,identifier(2),'a'*64)

def test_reported_posting_not_scope_and_multiple_source_rows_unresolved(env):
    store,key=env;profiles,meta,grants=payloads(store,key);p=deepcopy(profiles[0]['payload']);p['reported_posting']['station']='RESEARCH_STATION_A'
    with pytest.raises(Exception):F.validate_profile(sign(key,p),store.keys,store.clock())
    rows=profiles[0]['payload']['full_records'];assert F.posting(rows+[deepcopy(rows[1])])['station'] is None

def test_one_pass_subject_index_excludes_authority_only_mentions(env):
    store,key=env;profiles,meta,grants=payloads(store,key);catalog={};bindings={}
    for e in profiles:
        for row in e['payload']['full_records']:
            raw=row['raw_record_id'];catalog[raw]=dict(filename=row['dataset'],raw_record_id=raw,delivery={'complete':True},original={'columns':list(row['fields']),'values':list(row['fields'].values())},candidate_links=[{'role':'officer_nic_no','state':'CANDIDATE_NOT_ACCEPTED','officer_uid':e['payload']['officer_uid']},{'role':'recorded_by_officer_nic','state':'CANDIDATE_NOT_ACCEPTED','officer_uid':identifier(999)}]);bindings[raw]={'bound':True}
    snapshot={'catalog':catalog,'bindings':{'raw_bindings':bindings}};officers=[identifier(n) for n in range(1,7)]
    grouped=F.group_records(snapshot,officers);assert sum(map(len,grouped.values()))==12 and identifier(999) not in grouped
    del bindings[next(iter(bindings))]
    with pytest.raises(Exception):F.group_records(snapshot,officers)

from test_generated_connection import deployment, prepare
from research_connection_fixture import connected, setup, verified, keys

def test_operator_bulk_connection_uses_replay_and_all_ten_account_scopes(deployment):
    from app.access import generated_connection as G, full_source_connection as B
    from app.access.directory import _from_loaded_snapshot
    from app.access.policy import POLICY, RETAINED_DIRECTORY_POLICY
    from app.access import research_connection_runtime as R
    from app.access.research_app import configured
    from hashlib import sha256
    d=deployment;prepare(d);snapshot=d['t']['snapshot'];officers=sorted(G.C.Connection._identities(snapshot))
    for officer in officers:
        raw=sha256((officer+'service-fixture').encode()).hexdigest()
        snapshot['catalog'][raw]=dict(raw_record_id=raw,filename='officer_service_information.csv',delivery={'complete':True},
            candidate_links=[dict(officer_uid=officer,role='officer_nic_no',state='CANDIDATE_NOT_ACCEPTED')],
            original=dict(columns=['current_division','current_station'],values=['Source Division','Source Station']))
        snapshot['bindings']['raw_bindings'][raw]=[{'fixture':'bound-service-row'}]
    signer=R.signer(d['app']/'keys/research-access-signer.key',d['repo']);now=int(time.time())
    membership=G.signed(signer,G.ACCESS_ID,dict(policy=POLICY,kind='MEMBERSHIP',issued_at=now-1,expires_at=now+300,
        source_public_sha256=G.C.PUBLIC_SHA,officers=G.memberships(officers),review_reference=G.REVIEW))
    directory=_from_loaded_snapshot(snapshot,membership,d['store'].access.keys,generation=1)
    directory.update(policy=RETAINED_DIRECTORY_POLICY,expires_at=None,record_origin='GENERATED_RESEARCH_RECORDS')
    d['store'].access.put_directory(G.signed(signer,G.ACCESS_ID,directory))
    before={raw:deepcopy(item) for raw,item in snapshot['catalog'].items()}
    result=B.connect_all(d['repo'],d['root'],d['app'],d['t']['config']['source']['audit_gate_attempt'])
    assert result['full_source_profiles_connected']==2 and result['recorded_history_workspaces_connected']==0
    assert snapshot['catalog']==before and result['source_or_chain_modified'] is False
    store,_=configured(d['app']/'workspace-config.json');service=ResearchService(store)
    for login,total in [('research.igp',2),('research.hq',2),('research.sdig',2),('research.dig.a',1),('research.dig.b',1),('research.ssp',1),('research.sp',1),('research.oic.a',1),('research.oic.b',1)]:
        token,csrf=store.access.login(login,PASSWORD,'fixture-peer');page=service.browse(token,csrf,request())
        assert page['total']==total and all(row['details_available'] for row in page['items'])
        for row in page['items']:assert service.workspace(token,row['officer_uid'])['full_records']
    with pytest.raises(AccessError):store.access.login('research.inactive',PASSWORD,'fixture-peer')

def test_atomic_publication_covers_full_6596_profile_count(env):
    store,key=env;now=int(store.clock());profiles=[]
    for n in range(1,6597):
        records=[dict(dataset='officer_personal_information.csv',raw_record_id=f'{n:064x}',fields={'full_name':'Scale fixture '+str(n)}),dict(dataset='officer_service_information.csv',raw_record_id=f'{n+10000:064x}',fields={'current_station':'Scale fixture station'})]
        profiles.append(sign(key,dict(policy=F.POLICY,kind='SOURCE_PROFILE',record_origin='GENERATED_RESEARCH_RECORDS',issued_at=now,generation=1,source_public_sha256='a'*64,source_context_sha256='c'*64,officer_uid=identifier(n),full_records=records,reported_posting=F.posting(records))))
    meta=sign(key,dict(policy=F.POLICY,kind='SOURCE_SET',record_origin='GENERATED_RESEARCH_RECORDS',issued_at=now,generation=1,source_public_sha256='a'*64,source_context_sha256='c'*64,profiles={store.index('SOURCE_PROFILE',e['payload']['officer_uid']):F.P.fingerprint(e) for e in profiles}))
    F.publish(store,profiles,meta,[])
    assert len(F.active_set(store)['profiles'])==6596
    assert F.profile(store,identifier(6596),'a'*64)['full_records'][0]['fields']['full_name']=='Scale fixture 6596'
    assert store.get_packet(identifier(1))['generation']==1
