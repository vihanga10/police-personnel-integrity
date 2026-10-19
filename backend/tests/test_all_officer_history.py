"""Generated fixtures; real journal crypto, recovery keys and mTLS witness."""
from copy import deepcopy
from datetime import date,datetime,timedelta,timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import time
import pytest
from app.access import all_history_connection as H, full_source_connection as F
from app.access import generated_connection as G, research_policy as P
from app.access import research_connection_runtime as R
from app.access.policy import AccessError,account
from app.access.research_service import ResearchService
from app.identity import observed_recording_journal as J
from app.identity.bulk_history_journal import VerifiedBaselineBatch
from app.identity.bitemporal_reconstruction import query
from app.identity.protected_commitment import digest
from test_generated_connection import deployment,prepare,SECOND
from research_connection_fixture import connected,setup,verified,keys,OFFICER,PASSWORD
from test_scoped_officer_browser import request

def service_rows(d):
    snapshot=d['t']['snapshot']
    for officer in G.C.Connection._identities(snapshot):
        raw=hashlib.sha256((officer+'valid-service').encode()).hexdigest()
        row={k:'' for k in J.HEADERS['officer_service_information.csv']}
        row.update(current_division='Original reported division',current_station='Original reported station',
            date_of_enlistment='2020-01-01',entry_rank='PC',current_rank='SP',service_status='IN_SERVICE')
        snapshot['catalog'][raw]=dict(raw_record_id=raw,filename='officer_service_information.csv',classification='UNASSESSED',
            delivery={'complete':True},candidate_links=[dict(officer_uid=officer,role='officer_nic_no',state='CANDIDATE_NOT_ACCEPTED')],
            original=dict(columns=sorted(row),values=[row[k] for k in sorted(row)]),provenance={'fixture':'service'},assertion={'fixture':'service'})
        snapshot['bindings']['raw_bindings'][raw]=[{'fixture':'original-service-binding'}]

def provision(d,preserve=True):
    prepare(d);service_rows(d)
    if preserve:G.connect(d['repo'],d['root'],d['app'],d['t']['config']['source']['audit_gate_attempt'],selected_officers=[OFFICER])
    else:
        from app.access.directory import _from_loaded_snapshot
        from app.access.policy import POLICY,RETAINED_DIRECTORY_POLICY
        snapshot=d['t']['snapshot'];now=int(time.time())
        signer=R.signer(d['app']/'keys/research-access-signer.key',d['repo'])
        membership=G.signed(signer,G.ACCESS_ID,dict(policy=POLICY,kind='MEMBERSHIP',issued_at=now-1,expires_at=now+300,
            source_public_sha256=G.C.PUBLIC_SHA,officers=G.memberships(G.C.Connection._identities(snapshot)),review_reference=G.REVIEW))
        directory=_from_loaded_snapshot(snapshot,membership,d['store'].access.keys,generation=1)
        directory.update(policy=RETAINED_DIRECTORY_POLICY,expires_at=None,record_origin='GENERATED_RESEARCH_RECORDS')
        d['store'].access.put_directory(G.signed(signer,G.ACCESS_ID,directory))
    F.connect_all(d['repo'],d['root'],d['app'],d['t']['config']['source']['audit_gate_attempt'])

def connect(d):return H.connect_all(d['repo'],d['root'],d['app'],d['t']['config']['source']['audit_gate_attempt'])

def test_all_history_pipeline_preserves_existing_findings_names_posting_and_all_ten_scopes(deployment):
    d=deployment;provision(d);before=H.packets(d['store']);original=deepcopy(d['t']['snapshot']['catalog'])
    oldfiles={p:p.read_bytes() for p in (d['root']/'officers'/OFFICER).rglob('*.encrypted.json')}
    result=connect(d)
    assert result['all_recorded_history_workspaces_connected'] and result['recorded_history_workspaces_connected']==2
    assert result['preserved_existing_histories']==1 and result['new_recorded_baselines']==1
    assert H.packets(d['store'])[OFFICER]==before[OFFICER] and d['t']['snapshot']['catalog']==original
    assert all(p.read_bytes()==data for p,data in oldfiles.items())
    assert not result['source_or_chain_modified'] and not result['new_findings_created']
    service=ResearchService(d['store'])
    for login,total in [('research.igp',2),('research.hq',2),('research.sdig',2),('research.dig.a',1),
        ('research.dig.b',1),('research.ssp',1),('research.sp',1),('research.oic.a',1),('research.oic.b',1)]:
        token,csrf=d['store'].access.login(login,PASSWORD,'history-fixture-'+login)
        rows=service.browse(token,csrf,request());assert rows['total']==total and all(o['historical_workspace_available'] for o in rows['items'])
        for o in rows['items']:
            workspace=service.workspace(token,o['officer_uid']);assert workspace['historical_workspace_available'] and workspace['full_records']
            answer=service.history(token,csrf,o['officer_uid'],'2024-12-31',workspace['coverage_end'])
            assert answer['accepted_state'] is None and answer['versions']
            assert any(v['claim']['fields'].get('police_no')=='fixture-100' for v in answer['versions'])
            assert all(v['recorded_at'].startswith(datetime.now(timezone.utc).date().isoformat()) for v in answer['versions'])
            with pytest.raises(AccessError):service.history(token,csrf,o['officer_uid'],'2024-12-31','2020-01-01T00:00:00Z')
        if total==1:
            other=SECOND if rows['items'][0]['officer_uid']==OFFICER else OFFICER
            with pytest.raises(AccessError) as error:service.history(token,csrf,other,'2024-12-31',workspace['coverage_end'])
            assert error.value.status==404
        with pytest.raises(AccessError):service.history(token,'invalid-csrf',rows['items'][0]['officer_uid'],'2024-12-31',workspace['coverage_end'])
    with pytest.raises(AccessError):d['store'].access.login('research.inactive',PASSWORD,'history-inactive')
    assert b'Original reported station' not in d['store'].path.read_bytes()
    # A second complete replay resumes the same journal time, same set and packet.
    before=H.packets(d['store']);again=connect(d)
    assert again['checkpoint_set_sha256']==result['checkpoint_set_sha256'] and H.packets(d['store'])==before
    with d['store'].transaction() as database:
        assert database.execute('SELECT COUNT(*) FROM recorded_history_sets').fetchone()[0]==1
        with pytest.raises(Exception):database.execute('DELETE FROM recorded_history_sets')

@pytest.mark.parametrize('failure',['publish','lost_ack','expired_before_publish'])
def test_interrupted_run_preserves_sources_and_resumes_without_changing_observation_times(deployment,monkeypatch,failure):
    d=deployment;provision(d,False);original=deepcopy(d['t']['snapshot']['catalog']);old=H.packets(d['store'])
    if failure=='lost_ack':
        from app.identity.recording_tip_witness import WitnessClient
        original_advance=WitnessClient.advance
        def lost(self,*args):original_advance(self,*args);raise ConnectionError('Fixture lost acknowledgment')
        monkeypatch.setattr(WitnessClient,'advance',lost)
    else:
        original_publish=H.publish
        def stopped(*args,**kwargs):
            if failure=='publish':raise OSError('Fixture stopped before publication')
            original_check=kwargs['check'];calls=[0]
            def check(database=None):
                calls[0]+=1
                if database is not None:raise ValueError('Fixture expired permit at commit')
                original_check(database)
            kwargs['check']=check;return original_publish(*args,**kwargs)
        monkeypatch.setattr(H,'publish',stopped)
    with pytest.raises((ConnectionError,OSError,ValueError)):connect(d)
    assert H.packets(d['store'])==old and d['t']['snapshot']['catalog']==original
    journal_bytes={p:p.read_bytes() for p in (d['root']/'all-history-v1/journals').rglob('*.encrypted.json')}
    if failure=='lost_ack':monkeypatch.setattr(WitnessClient,'advance',original_advance)
    else:monkeypatch.setattr(H,'publish',original_publish)
    result=connect(d);assert result['recorded_history_workspaces_connected']==2
    assert all(p.read_bytes()==data for p,data in journal_bytes.items())

@pytest.mark.parametrize('target',['baseline','checkpoint','descriptor','manifest','witness'])
def test_tampered_published_state_never_reenrolls_or_overwrites_workspace(deployment,target):
    d=deployment;provision(d,False);connect(d);old=H.packets(d['store']);bank=d['root']/'all-history-v1'
    if target=='baseline':file=bank/'journals'/OFFICER/'baseline.encrypted.json'
    elif target=='checkpoint':file=next((bank/'journals'/OFFICER).glob('checkpoint-*.encrypted.json'))
    elif target=='descriptor':file=bank/'journals'/OFFICER/'record.json'
    elif target=='manifest':file=bank/'checkpoint-set.encrypted.json'
    else:file=bank/'recording-witness-store/enrollment.encrypted.json'
    file.write_bytes(b'{}');file.chmod(0o600)
    with pytest.raises(Exception):connect(d)
    assert file.read_bytes()==b'{}' and H.packets(d['store'])==old

def test_batched_original_format_supports_corrections_withdrawal_and_exact_knowledge_boundary(setup):
    s=setup;snapshot=s['snapshot'];batch=VerifiedBaselineBatch(snapshot,[OFFICER],s['signer'],'recorder',s['recorder_keys'])
    pin,state=batch.record(s['root'],s['repo'],OFFICER);start=state['history'].coverage_start
    assert start==s['clock'][0] and state['history'].coverage_end==start
    with pytest.raises(ValueError):query(state['history'],effective_on=date(2024,12,31),known_at=start-timedelta(microseconds=1))
    from test_observed_recording_journal import authorize,append,load,numbers
    token=authorize(s,pin);s['clock'][0]+=timedelta(seconds=1);new=append(s,pin,token);updated=load(s,new)
    assert numbers(updated,start)==['fixture-100'] and numbers(updated,s['clock'][0])==['fixture-200']
    token=authorize(s,new,withdrawn=True);s['clock'][0]+=timedelta(seconds=1);withdrawn=append(s,new,token)
    assert numbers(load(s,withdrawn),s['clock'][0])==[] and numbers(load(s,withdrawn),start)==['fixture-100']
    # A bulk resume must not discard a correction or relabel its checkpoint as baseline.
    with pytest.raises(ValueError):batch.record(s['root'],s['repo'],OFFICER)

def test_partial_baseline_recovery_is_exact_and_does_not_extend_coverage(setup,monkeypatch):
    s=setup;batch=VerifiedBaselineBatch(s['snapshot'],[OFFICER],s['signer'],'recorder',s['recorder_keys'])
    original=J._publish
    def stop(path,*args):
        if path.name.startswith('checkpoint-'):raise OSError('fixture interrupted checkpoint')
        return original(path,*args)
    monkeypatch.setattr(J,'_publish',stop)
    with pytest.raises(OSError):batch.record(s['root'],s['repo'],OFFICER)
    before=(s['root']/'baseline.encrypted.json').read_bytes();recorded=J._read(s['root']/'baseline.encrypted.json',s['crypto'],s['backup'],J._binding('BASELINE'))[1]['payload']['observed_at']
    monkeypatch.setattr(J,'_publish',original);s['clock'][0]+=timedelta(seconds=1)
    _,state=batch.record(s['root'],s['repo'],OFFICER)
    assert state['history'].coverage_end.isoformat()==recorded and (s['root']/'baseline.encrypted.json').read_bytes()==before

def test_authenticated_source_mutation_and_expired_permit_prevent_new_journal(setup):
    s=setup;batch=VerifiedBaselineBatch(s['snapshot'],[OFFICER],s['signer'],'recorder',s['recorder_keys'])
    s['snapshot']['catalog'][next(iter(s['snapshot']['catalog']))]['original']['values'][0]='changed'
    with pytest.raises(ValueError):batch.check(full=True)
    from app.identity import audit_gate as A
    from app.identity.evidence_bundle_v2 import open_artifact
    permit=open_artifact(s['crypto'],s['snapshot']['envelope'],A.binding(s['snapshot']['context']))
    for k in ('checked_at','issued_at','expires_at'):permit[k]=(datetime.fromisoformat(permit[k])-timedelta(days=1)).isoformat()
    s['snapshot']['envelope']=A.seal_permit(s['crypto'],s['backup'],permit)
    with pytest.raises(ValueError):batch.record(s['root'],s['repo'],OFFICER)
    assert not list(s['root'].iterdir())

def test_renewal_keeps_passwords_roles_scopes_inactive_account_and_hq_only_logs(deployment,monkeypatch):
    d=deployment;provision(d,False)
    scripts=Path(__file__).resolve().parents[1]/'scripts';monkeypatch.syspath_prepend(str(scripts))
    import renew_generated_access as operator
    before={}
    with d['store'].access.transaction() as database:
        for ident,version,blob in database.execute('SELECT id,version,value FROM users'):before[ident]=d['store'].access.open('USER',ident,version,blob)
    result=operator.renew(d['repo'],d['app']);assert not result['passwords_changed'] and result['accounts']==10
    with d['store'].access.transaction() as database:
        for ident,version,blob in database.execute('SELECT id,version,value FROM users'):
            new=d['store'].access.open('USER',ident,version,blob);old=before[ident]
            assert new['password']==old['password'] and version==old['grant']['payload']['version']+1
            assert all(new['grant']['payload'][k]==old['grant']['payload'][k] for k in ('username','user_id','role','scope_type','scope_id','active'))
    connect(d)
    from app.access.research_app import configured
    store,_=configured(d['app']/'workspace-config.json')
    token,csrf=store.access.login('research.hq',PASSWORD,'renew-hq');assert store.accountability.reader(token,csrf)['role']=='HQ_ADMIN'
    token,csrf=store.access.login('research.dig.a',PASSWORD,'renew-dig')
    with pytest.raises(AccessError):store.accountability.reader(token,csrf)
    assert ResearchService(store).browse(token,csrf,request())['total']==1

def test_6596_original_format_baselines_and_atomic_workspace_publication(setup,tmp_path):
    """Scale fixture: all IDs recorded and queried, no live original dataset/RPC."""
    from uuid import UUID
    s=setup;snapshot=s['snapshot'];original=next(iter(snapshot['catalog'].values()))
    catalog={};bindings={};officers=[]
    for n in range(1,6597):
        officer=str(UUID(int=n+10000));officers.append(officer);raw=hashlib.sha256(('scale-history-'+str(n)).encode()).hexdigest()
        item=deepcopy(original);item['raw_record_id']=raw;item['candidate_links'][0]['officer_uid']=officer
        catalog[raw]=item;bindings[raw]=[{'fixture_destination':raw}]
    snapshot['catalog']=catalog;snapshot['bindings']['raw_bindings']=bindings
    start=time.monotonic();batch=VerifiedBaselineBatch(snapshot,officers,s['signer'],'recorder',s['recorder_keys'])
    states={}
    for n,officer in enumerate(officers):
        if n%100==0:batch.check()
        root=s['root']/officer;root.mkdir(mode=0o700)
        _,state=batch.record(root,s['repo'],officer);states[officer]=H.wire(state['history'])
        answer=query(state['history'],effective_on=date(2024,12,31),known_at=state['history'].coverage_end)
        assert any(p.candidates for p in answer.projections)
    batch.check(full=True)
    from research_workspace_fixture import initialize,sign
    container=tmp_path/'scale-web';container.mkdir(mode=0o700);store,key,_=initialize(container)
    envelopes=[];selected={};now=int(time.time())
    for officer,h in states.items():
        selected[officer]=dict(kind='BASELINE',generation=1,history_sha256=digest(h),source_records_sha256=digest([]))
        envelopes.append(sign(key,dict(policy=P.RETAINED_POLICY,kind='PRESENTATION',issued_at=now,expires_at=None,
            officer_uid=officer,generation=1,source_public_sha256='a'*64,observed_at=datetime.fromtimestamp(now,timezone.utc).isoformat(),
            recording_tip_sha256='b'*64,history=h,findings=[],authority=[],record_origin='GENERATED_RESEARCH_RECORDS',full_records=[],
            anchoring={k:dict(status='NOT_CONFIGURED',receipt_sha256=None) for k in ('fabric','public','recovery')})))
    manifest=dict(officers=selected,source_public_sha256='a'*64,issued_at=now)
    calls=[0]
    def check(database=None):calls[0]+=1
    H.publish(store,manifest,'b'*64,envelopes,[],check=check)
    with store.transaction() as database:
        assert database.execute('SELECT COUNT(*) FROM recorded_history_packets').fetchone()[0]==6596
    assert len(states)==6596 and calls[0]==2
    assert store.get_packet(str(UUID(int=16596)))['history']['versions']
    print('6596 baseline recording plus atomic cache fixture seconds:',round(time.monotonic()-start,2))

def test_bulk_authority_summaries_equal_existing_algorithm_without_promoting_reported_ranks(deployment):
    d=deployment;service_rows(d);snapshot=d['t']['snapshot'];snapshot['captured_at']=datetime.now(timezone.utc)
    from app.identity.reported_authority_actions import HEADERS
    row={k:'' for k in HEADERS['promotion_history.csv']}
    row.update(to_rank='DIG',effective_date='2024-01-01',promotion_authority='000000002V',promotion_authority_signed_date='2023-12-31')
    raw='e'*64;snapshot['catalog'][raw]=dict(raw_record_id=raw,filename='promotion_history.csv',classification='UNASSESSED',
        delivery={'complete':True},candidate_links=[dict(officer_uid=OFFICER,role='officer_nic_no',state='CANDIDATE_NOT_ACCEPTED'),
            dict(officer_uid=SECOND,role='promotion_authority',state='CANDIDATE_NOT_ACCEPTED')],
        original=dict(columns=sorted(row),values=[row[k] for k in sorted(row)]),provenance={'fixture':'promotion'},assertion={'fixture':'promotion'})
    snapshot['bindings']['raw_bindings'][raw]=[{'fixture':'promotion'}]
    indexed=H.authority_index(snapshot,[OFFICER,SECOND])
    assert indexed[OFFICER]==H.B._reported_authority(snapshot,OFFICER) and indexed[SECOND]==[]
    assert all(a['status']=='CANNOT_VERIFY' and a['assessment_receipt_sha256'] is None for a in indexed[OFFICER])

def test_real_https_new_history_query_scope_csrf_and_logout(deployment):
    d=deployment;provision(d,False);connect(d)
    from research_workspace_https_fixture import server
    from scoped_access_http_fixture import request as http
    with server(d['app'],prepared=(d['store'],None,d['app']/'workspace-config.json')) as (_,_,origin,context,_):
        def call(path,**kwargs):return http(origin,context,path,**kwargs)
        assert call('/api/research/officers/'+SECOND)[0]==401
        status,headers,body=call('/api/auth/login',method='POST',body={'username':'research.dig.b','password':PASSWORD})
        assert status==200;cookie=headers['set-cookie'].split(';')[0];csrf=body['csrf_token']
        def auth(path,**kwargs):return call(path,cookie=cookie,csrf=csrf,**kwargs)
        workspace=auth('/api/research/officers/'+SECOND)[2]
        assert workspace['historical_workspace_available'] and workspace['history_baseline_only']
        body=dict(officer_uid=SECOND,effective_on='2024-12-31',known_at=workspace['coverage_end'])
        status,headers,answer=auth('/api/research/history',method='POST',body=body)
        assert status==200 and answer['versions'] and answer['accepted_state'] is None and headers['cache-control']=='no-store'
        assert call('/api/research/history',method='POST',body=body,cookie=cookie)[0]==403
        assert auth('/api/research/history',method='POST',body={**body,'officer_uid':OFFICER})[0]==404
        assert auth('/api/auth/logout',method='POST',body={})[0]==200
        assert auth('/api/research/history',method='POST',body=body)[0]==401

def test_bulk_enrollment_preserves_withheld_disclosure_even_for_igp(deployment):
    d=deployment;provision(d,False);store=d['store']
    user=R.read_json(d['app']/'accounts.json',d['repo'])['accounts'][0]
    old=store.get_grant(user['user_id'],OFFICER)
    time.sleep(max(0,old['issued_at']+1-time.time()));issued=int(time.time())
    signer=R.signer(d['app']/'keys/research-presentation-signer.key',d['repo'])
    grant={**old,'issued_at':issued,'expires_at':issued+600,'assignment':'UNRESOLVED'}
    store.import_grant(G.signed(signer,G.PRESENTATION_ID,grant));connect(d)
    assert store.get_grant(user['user_id'],OFFICER)==grant
    token,csrf=store.access.login('research.igp',PASSWORD,'withheld-history');service=ResearchService(store)
    with pytest.raises(AccessError) as error:service.workspace(token,OFFICER)
    assert error.value.code=='DETAILS_WITHHELD'
    workspace=service.workspace(token,SECOND)
    assert service.history(token,csrf,SECOND,'2024-12-31',workspace['coverage_end'])['versions']

