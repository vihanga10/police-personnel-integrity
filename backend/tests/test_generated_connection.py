"""Generated deployment fixtures: actual crypto, journals and mTLS; loader replaced only in tests."""
import base64
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import time
from uuid import UUID
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.access import generated_connection as G, research_connection as C
from app.access import research_connection_runtime as R
from app.access.policy import AccessError, POLICY, encoded
from app.access.store import AccessStore
from app.access.research_store import ResearchStore
from app.access.research_service import ResearchService
from app.access.accountability import configured as logs_configured
from app.identity import observed_recording_journal as J
from app.identity.protected_commitment import digest
from research_connection_fixture import connected, setup, verified, keys, write, public, pins, seed, OFFICER, PASSWORD
from scoped_access_fixture import identifier

SECOND=str(UUID(int=3))

@pytest.fixture
def deployment(connected, tmp_path, monkeypatch):
    t=connected;repo=t['s']['repo'];app=tmp_path/'generated-app';app.mkdir(mode=0o700)
    for directory in ('keys','key-backup','access-state','workspace-state','accountability-state'):(app/directory).mkdir(mode=0o700)
    access_signer=Ed25519PrivateKey.generate();presentation_signer=Ed25519PrivateKey.generate()
    write(app/'keys/research-access-signer.key',seed(access_signer));write(app/'keys/research-presentation-signer.key',seed(presentation_signer))
    write(app/'keys/access.key',__import__('os').urandom(32));write(app/'keys/workspace.key',__import__('os').urandom(32));write(app/'keys/log.key',__import__('os').urandom(32))
    access_cfg=dict(policy='SCOPED_ACCESS_CONFIG_V1',repository=str(repo),state_directory=str(app/'access-state'),
        key_file=str(app/'keys/access.key'),authority_keys=pins({G.ACCESS_ID:public(access_signer)}),origin='https://127.0.0.1:8443')
    write(app/'access-config.json',access_cfg)
    workspace_cfg=dict(policy='RESEARCH_WEB_CONFIG_V1',access_config=str(app/'access-config.json'),state_directory=str(app/'workspace-state'),
        key_file=str(app/'keys/workspace.key'),presentation_keys=pins({G.PRESENTATION_ID:public(presentation_signer)}))
    access=AccessStore(app/'access-state',app/'keys/access.key',{G.ACCESS_ID:public(access_signer)},repo=repo,create=True)
    store=ResearchStore(app/'workspace-state',app/'keys/workspace.key',{G.PRESENTATION_ID:public(presentation_signer)},access=access,create=True)
    now=int(time.time());accounts=[]
    roles=[('research.igp','IGP','ALL',None),('research.hq','HQ_ADMIN','ALL',None),
        ('research.sdig','SDIG','PROVINCE','RESEARCH_PROVINCE_A'),('research.dig.a','DIG','DIVISION','RESEARCH_DIVISION_A'),
        ('research.dig.b','DIG','DIVISION','RESEARCH_DIVISION_B'),('research.ssp','SSP','DIVISION','RESEARCH_DIVISION_A'),
        ('research.sp','SP','DIVISION','RESEARCH_DIVISION_A'),('research.oic.a','STATION_OIC','STATION','RESEARCH_STATION_A'),
        ('research.oic.b','STATION_OIC','STATION','RESEARCH_STATION_B'),('research.inactive','DIG','DIVISION','RESEARCH_DIVISION_A')]
    for index,(login,role,scope,scope_id) in enumerate(roles,100):
        account=dict(policy=POLICY,kind='ACCOUNT',issued_at=now-1,expires_at=now+86400-1,user_id=identifier(index),username=login,
            role=role,scope_type=scope,scope_id=scope_id,version=1,active=login!='research.inactive',review_reference='TEST_GENERATED_SCOPE')
        accounts.append(account);access.put_account(G.signed(access_signer,G.ACCESS_ID,account),PASSWORD)
    write(app/'accounts.json',dict(record_origin='GENERATED_RESEARCH_RECORDS',accounts=accounts))
    from app.access.accountability import POLICY as LOG_POLICY
    write(app/'log-reader-grant.json',G.signed(access_signer,G.ACCESS_ID,dict(policy=LOG_POLICY,kind='READ_ACCESS_LOGS',
        user_id=accounts[1]['user_id'],account_version=1,issued_at=now-1,expires_at=now+1800,review_reference='FIXTURE_LOG_INSPECTION')))
    log_cfg=dict(policy='ACCOUNTABILITY_CONFIG_V1',state_directory=str(app/'accountability-state'),key_file=str(app/'keys/log.key'),reader_grants=[str(app/'log-reader-grant.json')])
    write(app/'accountability-config.json',log_cfg)
    store.accountability=logs_configured(app/'accountability-config.json',access=access,workspace_key=workspace_cfg['key_file'],workspace_root=store.root,create=True)
    write(app/'workspace-config.json',{**workspace_cfg, 'accountability_config':str(app/'accountability-config.json')})
    snapshot=t['snapshot'];snapshot['manifest']['bundles'].append(dict(officer_uid=SECOND))
    for raw,item in list(snapshot['catalog'].items()):
        item2=deepcopy(item);raw2=hashlib.sha256((raw+'second-fixture').encode()).hexdigest();item2['raw_record_id']=raw2
        item2['candidate_links'][0]['officer_uid']=SECOND
        if item['filename']=='officer_personal_information.csv':item2['original']['values']=['000000002V','Second generated name','S. Generated']
        snapshot['catalog'][raw2]=item2;snapshot['bindings']['raw_bindings'][raw2]=deepcopy(snapshot['bindings']['raw_bindings'][raw])
    # Fixture clock is real for new baseline/protocol validity, never copied from CSV dates.
    monkeypatch.setattr(J,'_now',lambda:datetime.now(timezone.utc))
    root=tmp_path/'generated-deployment'
    source={k:v for k,v in t['config']['source'].items() if k!='audit_gate_attempt'}
    return dict(t=t,repo=repo,root=root,app=app,source=source,store=store)


def prepare(d):return G.prepare(d['repo'],d['root'],d['app'],d['source'],effective_on=date(2024,12,31))
def connect(d):return G.connect(d['repo'],d['root'],d['app'],d['t']['config']['source']['audit_gate_attempt'])


def test_prepare_private_exact_copy_separate_domains_no_loader_or_rpc(deployment):
    d=deployment;result=prepare(d)
    assert result['source_rows_read'] is False and result['ui_connected'] is False and d['t']['calls']==[]
    assert (d['root']/'keys/original-identity-copy.json').read_bytes()==Path(d['source']['key_file']).read_bytes()
    secrets=[R.signer(d['root']/'keys'/ (name+'.key'),d['repo']).private_bytes_raw() for name in G.DOMAINS]
    assert len(set(secrets))==len(secrets)
    for file in d['root'].rglob('*'):
        assert file.stat().st_mode&0o077==0
    with pytest.raises(ValueError):prepare(d)


def test_full_generated_pipeline_connects_names_scopes_history_findings_and_logs(deployment):
    d=deployment;prepare(d);before=deepcopy(d['t']['snapshot']['catalog']);source_hashes={k:Path(v).read_bytes() for k,v in d['source'].items() if not k.endswith('_attempt')}
    result=connect(d)
    assert result['status']=='SIGNED_UI_CACHE_IMPORTED' and result['directory_officers']==2 and result['connected_detail_officers']==2
    assert result['original_source_replay'] and not result['blockchain_submission'] and not result['independently_administered_witnesses']
    assert len(d['t']['calls'])==1 and d['t']['snapshot']['catalog']==before
    assert all(Path(d['source'][k]).read_bytes()==value for k,value in source_hashes.items())
    service=ResearchService(d['store']);a,csrf=d['store'].access.login('research.dig.a',PASSWORD,'test-peer-a');b,bcsrf=d['store'].access.login('research.dig.b',PASSWORD,'test-peer-b')
    available=service.available(a);assert [item['officer_uid'] for item in available['items']]==[OFFICER]
    assert available['scope_basis']=='EXPLICIT_RESEARCH_SIMULATION'
    assert [item['officer_uid'] for item in service.available(b)['items']]==[SECOND]
    workspace=service.workspace(a,OFFICER);assert workspace['findings'] and not workspace['can_request_review']
    assert workspace['coverage_start']==workspace['coverage_end']
    answer=service.history(a,csrf,OFFICER,'2024-12-31',workspace['coverage_end'])
    assert any(p['fields'].get('police_no')=='fixture-100' for group in answer['projections'] for p in group['candidates'])
    assert all(v['recorded_at'].startswith(datetime.now(timezone.utc).date().isoformat()) for v in answer['versions'])
    with pytest.raises(AccessError) as exc:service.workspace(a,SECOND)
    assert exc.value.status==404
    with pytest.raises(AccessError):d['store'].access.login('research.inactive',PASSWORD,'test-peer-inactive')
    with pytest.raises(AccessError):service.history(a,csrf,OFFICER,'2024-12-31','2024-12-31T00:00:00Z')
    # Encrypted log bytes do not expose generated names or NICs.
    assert b'Second generated name' not in (d['app']/'accountability-state/accountability.sqlite3').read_bytes()
    # Actual TLS server reloads the produced stores, rather than fixture UI packets.
    from research_workspace_https_fixture import server
    from scoped_access_http_fixture import request
    with server(d['app'],prepared=(d['store'],None,d['app']/'workspace-config.json')) as (_,_,origin,context,_):
        def call(path,**kwargs):return request(origin,context,path,**kwargs)
        assert call('/api/research/available')[0]==401
        status,headers,body=call('/api/auth/login',method='POST',body={'username':'research.dig.a','password':PASSWORD})
        assert status==200
        cookie=headers['set-cookie'].split(';')[0];csrf=body['csrf_token']
        def auth(path,**kwargs):return call(path,cookie=cookie,csrf=csrf,**kwargs)
        status,_,available=auth('/api/research/available')
        assert status==200 and [item['officer_uid'] for item in available['items']]==[OFFICER]
        assert auth('/api/research/officers/'+SECOND)[0]==404
        status,_,workspace=auth('/api/research/officers/'+OFFICER)
        assert status==200 and workspace['identity']['names'][0]=='Reported Connection Name'
        status,_,answer=auth('/api/research/history',method='POST',body=dict(officer_uid=OFFICER,effective_on='2024-12-31',known_at=workspace['coverage_end']))
        assert status==200 and answer['versions']
        assert call('/api/research/history',method='POST',cookie=cookie,body=dict(officer_uid=OFFICER,effective_on='2024-12-31',known_at=workspace['coverage_end']))[0]==403
        assert auth('/api/accountability/capabilities')[0]==403
        auth('/api/auth/logout',method='POST',body={})
        _,headers,body=call('/api/auth/login',method='POST',body={'username':'research.hq','password':PASSWORD})
        cookie=headers['set-cookie'].split(';')[0];csrf=body['csrf_token']
        assert len(auth('/api/research/available')[2]['items'])==2
        status,_,logs=auth('/api/accountability/logs',method='POST',body=dict(limit=100,before_sequence=None,action=None,outcome=None))
        assert status==200 and any(event['action']=='DATASET_CONNECTION' and event['outcome']=='ALLOWED' for event in logs['items'])
        assert any(event['action']=='CONNECTED_VIEWS_READ' and event.get('returned_officer_uids') for event in logs['items'])



def test_refresh_reuses_recorded_times_and_finding_ids_advances_only_ui_generation(deployment):
    d=deployment;prepare(d);first=connect(d);config=R.read_json(d['root']/'connection-config.json',d['repo'])
    first_runtime=R.read_json(d['root']/'officers'/OFFICER/'runtime.json',d['repo'])
    baseline=(d['root']/'officers'/OFFICER/'recording-journal/baseline.encrypted.json').read_bytes()
    time.sleep(1.05)
    second=connect(d)
    assert len(d['t']['calls'])==2 and second['directory_officers']==first['directory_officers']
    assert R.read_json(d['root']/'officers'/OFFICER/'runtime.json',d['repo'])==first_runtime
    assert (d['root']/'officers'/OFFICER/'recording-journal/baseline.encrypted.json').read_bytes()==baseline
    assert len(list((d['root']/'officers'/OFFICER/'findings-journal').glob('entry-*')))==1
    token,_=d['store'].access.login('research.dig.a',PASSWORD,'test-peer-a')
    assert ResearchService(d['store']).workspace(token,OFFICER)['generation']==2


@pytest.mark.parametrize('kind',['non_generated','missing_logs','public_source_key','bad_copy','uncommitted','limit'])
def test_prepare_denies_incompatible_or_unsafe_inputs_without_provisioning(deployment,kind):
    d=deployment
    if kind=='non_generated':
        value=R.read_json(d['app']/'accounts.json',d['repo']);value['record_origin']='UNKNOWN';write(d['app']/'accounts.json',value)
    elif kind=='missing_logs':
        value=R.read_json(d['app']/'workspace-config.json',d['repo']);del value['accountability_config'];write(d['app']/'workspace-config.json',value)
    elif kind=='public_source_key':Path(d['source']['backup_key_file']).chmod(0o644)
    elif kind=='bad_copy':write(d['source']['backup_key_file'],dict(active_encryption_key_version='a',active_lookup_key_version='a',encryption_keys={'a':base64.b64encode(b'a'*32).decode()},lookup_keys={'a':base64.b64encode(b'b'*32).decode()}))
    elif kind=='uncommitted':(d['repo']/'source.py').write_text('# Changed fixture source')
    with pytest.raises(ValueError):
        G.prepare(d['repo'],d['root'],d['app'],d['source'],detail_limit=1 if kind=='limit' else 2)
    assert not d['root'].exists() and d['t']['calls']==[]


def test_expired_permit_prevents_recording_or_ui_import(deployment,monkeypatch):
    d=deployment;prepare(d)
    from app.identity import audit_gate as A
    from app.identity.evidence_bundle_v2 import open_artifact
    snapshot=d['t']['snapshot'];permit=open_artifact(snapshot['crypto'],snapshot['envelope'],A.binding(snapshot['context']))
    for field in ('checked_at','issued_at','expires_at'):permit[field]=(datetime.fromisoformat(permit[field])-timedelta(days=1)).isoformat()
    snapshot['envelope']=A.seal_permit(snapshot['crypto'],snapshot['backup'],permit)
    write(Path(d['t']['config']['source']['audit_gate_attempt'])/'audit-permit.encrypted.json',snapshot['envelope'])
    with pytest.raises(ValueError):connect(d)
    assert not list((d['root']/'officers').iterdir())
    with d['store'].access.transaction() as c:assert c.execute('SELECT COUNT(*) FROM directory').fetchone()[0]==0


def test_missing_witness_enrollment_never_reinitializes_and_preserves_previous_import(deployment):
    d=deployment;prepare(d);connect(d)
    root=d['root']/'officers'/OFFICER/'recording-witness-store'
    (root/'enrollment.encrypted.json').unlink()
    with pytest.raises(ValueError):connect(d)
    assert not (root/'enrollment.encrypted.json').exists()
    assert len(list((d['root']/'officers'/OFFICER/'findings-journal').glob('entry-*')))==1


def test_selected_batch_connects_only_requested_original_officer_and_expires_closed(deployment):
    d=deployment;prepare(d)
    result=G.connect(d['repo'],d['root'],d['app'],d['t']['config']['source']['audit_gate_attempt'],selected_officers=[SECOND])
    assert result['directory_officers']==2 and result['connected_detail_officers']==1 and not result['all_officer_details_connected']
    service=ResearchService(d['store'])
    a,_=d['store'].access.login('research.dig.a',PASSWORD,'selected-peer-a')
    b,_=d['store'].access.login('research.dig.b',PASSWORD,'selected-peer-b')
    assert service.available(a)['items']==[] and [item['officer_uid'] for item in service.available(b)['items']]==[SECOND]
    d['store'].clock=lambda:result['detail_copy_expires_at']+1
    with pytest.raises(AccessError) as exc:service.workspace(b,SECOND)
    assert exc.value.code=='PRESENTATION_EXPIRED_OR_INVALID'
    assert service.available(b)['items']==[]


@pytest.mark.parametrize('fault',['audit_failed','ready_wrong_revision','profile_changed'])
def test_audit_launcher_never_connects_after_failed_or_changed_readiness(deployment,monkeypatch,fault):
    import importlib.util
    d=deployment
    file=Path(__file__).resolve().parents[1]/'scripts/provision_generated_connection.py'
    spec=importlib.util.spec_from_file_location('generated_operator_test',file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    home=d['t']['control']/'fixture-home';home.mkdir(mode=0o700)
    evidence=home/'ResearchEvidence/police-personnel-integrity/audit-gate-attempts';evidence.mkdir(parents=True,mode=0o700)
    attempt=evidence/str(UUID(int=50));attempt.mkdir(mode=0o700)
    revision=C.revision(d['repo']);write(attempt/'READY.json',dict(status='READY',code_revision='f'*40 if fault=='ready_wrong_revision' else revision))
    profile=write(home/'profile.json',{'fixture_profile':True})
    monkeypatch.setattr(Path,'home',classmethod(lambda cls:home))
    monkeypatch.setattr(G,'validate_plan',lambda *args:dict(source=d['source']))
    from app.identity import audit_read_rpc_profile as AR
    monkeypatch.setattr(AR,'load',lambda *args:None)
    monkeypatch.setattr(C,'revision',lambda *args:revision)
    seen=[];monkeypatch.setattr(G,'connect',lambda *args,**kwargs:seen.append('connection'))
    class Process:
        def __init__(self,*args,**kwargs):
            self.stdout=['Audit gate attempt directory: '+str(attempt)+'\n'];self.command=args[0]
            assert '--key-file' in self.command and '--read-profile' in self.command
            assert self.command[self.command.index('--publication-fee-budget-eth')+1]=='2.30'
            assert not any(flag in self.command for flag in ('--execute','--publish','--send'))
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def wait(self):
            if fault=='profile_changed':write(profile,{'changed':True})
            return 1 if fault=='audit_failed' else 0
        def terminate(self):pass
    monkeypatch.setattr(module.subprocess,'Popen',Process)
    with pytest.raises(ValueError):module.audit_and_connect(d['repo'],d['root'],d['app'],profile)
    assert seen==[]
