"""Generated fixtures, real signed accounts/assessments and production algorithms; no live chains."""
from copy import deepcopy
from dataclasses import asdict
from datetime import date,datetime,timezone
import hashlib,json,sqlite3
from types import SimpleNamespace
from uuid import uuid4
import pytest
from app.access import full_source_profiles as F,research_policy as P,operational_authority as A,authority_case_store as S
from app.access.generated_connection import signed
from app.access.policy import AccessError
from app.intake.promotion_pipeline.approvals import ApprovalEngine,POLICY,batch_binding
from app.intake.promotion_pipeline.core import IntakeError,validate_rows
from app.intake.promotion_pipeline.service import PromotionService
from app.intake.promotion_pipeline.delivery import process
from app.identity.action_authority_integration import AuthorityAssessment
from app.identity.temporal_authority import Rule
from app.identity.run_research_algorithms import json_value
from test_promotion_analysis import connected,publish
from test_full_source_profiles import payloads
from test_promotion_pipeline import source,csv_bytes,Destination,Chains
from test_priority2_workflows import env,fact,state,REF,DATA
from research_workspace_fixture import identifier,sign,PASSWORD,disclosure
from scoped_access_fixture import grant,sign as account_sign

@pytest.fixture
def e(connected,tmp_path):
    e=connected;w=e['store'];now=int(e['clock'][0]);profiles,meta,grants=payloads(w,e['key'])
    for profile in profiles:
        p=profile['payload'];p['full_records'][1]['fields'].update(current_rank='Sub Inspector of Police',current_unit_type='CID',service_status='Active');p['reported_posting']=F.posting(p['full_records']);profile.update(sign(e['key'],p))
    meta['payload']['profiles']={w.index('SOURCE_PROFILE',p['payload']['officer_uid']):P.fingerprint(p) for p in profiles};meta=sign(e['key'],meta['payload']);F.publish(w,profiles,meta,grants)
    w.access.put_account(grant(e['key'],'HQ_ADMIN','ALL',None,version=2,now=now));e['hq']=w.access.login('station.one',PASSWORD,'hq')
    # Separate explicitly signed IGP identity, never a second role on the uploader ID.
    igp=grant(e['key'],'IGP','ALL',None,login='igp.one',now=now);igp['payload']['user_id']=identifier(101);w.access.put_account(account_sign(e['key'],igp['payload']),PASSWORD)
    e['igp']=w.access.login('igp.one',PASSWORD,'igp')
    e['clock'][0]+=2;now=int(e['clock'][0])
    for who,version in ((100,2),(101,1)):
        for n in range(1,7):
            d=disclosure(e['key'],officer=identifier(n),version=version,now=now);d['payload']['user_id']=identifier(who);w.import_grant(sign(e['key'],d['payload']))
    root=tmp_path/'decisions';root.mkdir(mode=0o700);file=tmp_path/'approval.json';file.write_text(json.dumps(dict(policy=POLICY,decision_root=str(root),reviewer_ids=[identifier(101)],legacy_queued={})));file.chmod(0o600)
    engine=ApprovalEngine(w,e['analysis'],file,create=True);e['engine']=engine;e['analysis'].runtime={};e['service'].promotion_acceptance=engine;w.promotion_acceptance=engine
    e['promotion']=PromotionService(e['service'],e['intake'],{'importer_ids':[identifier(100)],'baseline_source_set_sha256':'a'*64})
    e['promotion'].source_state=lambda:e['directory'];return e

def batch(e,**changes):
    now=min(datetime.fromtimestamp(e['clock'][0],timezone.utc),datetime.now(timezone.utc));values=dict(officer_nic_no='000000001V',effective_date='2026-10-01',promotion_authority='000000001V',promotion_authority_signed_date='2024-01-01',promotion_id=str(uuid4()));values.update(changes);row=source(**values)
    rows=validate_rows([row],lambda nic:[identifier(1)],e['intake'].duplicate,now=now)
    return e['intake'].create(csv_bytes([row]),dict(actor={'user_id':identifier(100),'username':'station.one','account_version':2},received_at=now.isoformat(),source_reference='Documented fixture',filename='promotions.csv',baseline_source_set_sha256='a'*64,rows=rows),str(uuid4()))

def body(b,decision='APPROVE',version=1):return dict(batch_id=b['batch_id'],file_sha256=b['file_sha256'],operation_id=str(uuid4()),expected_version=version,decision=decision,reason='Independently inspected exact fixture upload')
def submit(e,b):return e['promotion'].commit(*e['hq'],{k:b[k] for k in ('batch_id','file_sha256')})
def approve(e,b):submit(e,b);return e['promotion'].decide(*e['igp'],body(b))
def visible(e,b):
    approve(e,b);process(e['intake'],b['batch_id'],Destination(),Destination(),Chains(),e['engine'].processing_allowed)
    receipt=e['intake'].phase(b['batch_id'],'CHAINS_VERIFIED');e['clock'][0]=max(e['clock'][0]+2,P.instant(receipt['verification_observed_at']).timestamp()+2);e['analysis'].activate_visible();e['clock'][0]+=1

def assess(e,b,rank='SP'):
    reports=e['analysis'].reports(identifier(1));report=next(r for r in reports if r['batch_id']==b['batch_id']);ref,action=next(iter(e['analysis'].actions(e['packet'],e['directory'],[report]).items()));known=datetime.fromtimestamp(e['clock'][0],timezone.utc)
    h,pins,missing=A.actor_history(e['store'],e['packet'],e['directory'],[action],known);assert not missing
    rule=Rule('explicit-fixture-rule',(action.action_kind,),('SP',),('ASSESSOR_ROLE',),('EXPLICIT_SCOPE',),('EXPLICIT_TARGET',),date(2010,1,1),None,False,'ASSESSED',(REF,))
    typed=AuthorityAssessment(e['packet']['source_public_sha256'],A.digest(json_value(asdict(action))),action.destination_digest,identifier(1),'EXPLICIT_TARGET',fact(True),fact(True),fact(True),(state(h,rank=rank),),(rule,),(),((REF,hashlib.sha256(DATA).hexdigest()),))
    prior=next((r for r in reversed(S.rows(e['store'],identifier(1))) if r['payload']['action_reference']==ref),None)
    e['clock'][0]+=1
    p=dict(policy=S.POLICY,kind='AUTHORITY_ASSESSMENT',record_origin='GENERATED_RESEARCH_RECORDS',officer_uid=identifier(1),action_reference=ref,workspace_sha256=P.fingerprint(e['packet']),source_public_sha256=e['packet']['source_public_sha256'],assessment=json_value(asdict(typed)),actor_packets=pins,recorded_at=datetime.fromtimestamp(e['clock'][0],timezone.utc).isoformat(),version=prior['payload']['version']+1 if prior else 1,supersedes=P.fingerprint(prior) if prior else None,operation_id=str(uuid4()),review_reference='CONTROLLED_DOCUMENTED_TEST')
    envelope=signed(e['assessor'],'fixture-assessor',p);S.append(e['store'],envelope,lambda database=None:None,evidence={REF:DATA});return envelope

def test_hq_submit_pauses_without_storage_or_queue_then_independent_approval_queues(e):
    b=batch(e);result=submit(e,b);assert result['status']=='AWAITING_IGP_APPROVAL' and not e['intake'].pending()
    with pytest.raises(IntakeError,match='BATCH_NOT_QUEUED'):e['engine'].processing_allowed(b)
    q=body(b);result=e['promotion'].decide(*e['igp'],q);assert result['status']=='QUEUED'
    assert e['intake'].phase(b['batch_id'],'DOCUMENTS_PREPARED') is None
    assert e['promotion'].decide(*e['igp'],q)==result
    e['engine'].processing_allowed(b)

@pytest.mark.parametrize('decision,status',[('REJECT','REJECTED'),('REQUEST_CHANGES','CHANGES_REQUESTED')])
def test_negative_decision_preserves_bytes_and_never_queues(e,decision,status):
    b=batch(e);before=deepcopy(b);submit(e,b);result=e['promotion'].decide(*e['igp'],body(b,decision))
    assert result['status']==status and not e['intake'].pending() and e['intake'].get(b['batch_id'])==before
    with pytest.raises(IntakeError,match='APPROVAL_ALREADY_DECIDED'):e['promotion'].decide(*e['igp'],body(b))

def test_hq_cannot_approve_or_self_approve_even_if_configured(e):
    b=batch(e);submit(e,b)
    with pytest.raises(AccessError,match='IGP_APPROVAL_FORBIDDEN'):e['promotion'].decide(*e['hq'],body(b))
    user=e['promotion'].actor(e['hq'][0]);e['engine'].reviewer=lambda user:True
    with pytest.raises(IntakeError,match='SELF_APPROVAL_FORBIDDEN'):e['engine'].decide(b,user,body(b))

def test_exact_file_revision_reason_and_csrf_required(e):
    b=batch(e);submit(e,b)
    for changes,code in [({'file_sha256':'0'*64},'APPROVAL_FILE_CHANGED'),({'expected_version':0},'DECISION_ADVANCED'),({'reason':' '},'APPROVAL_REASON_REQUIRED')]:
        with pytest.raises(IntakeError,match=code):e['promotion'].decide(*e['igp'],dict(body(b),**changes))
    with pytest.raises(AccessError):e['promotion'].decide(e['igp'][0],'forged',body(b))
    assert not e['intake'].pending()

def test_lost_queue_acknowledgement_recovers_the_retained_approval(e,monkeypatch):
    b=batch(e);submit(e,b);q=body(b);original=e['intake'].queue
    monkeypatch.setattr(e['intake'],'queue',lambda *args:(_ for _ in ()).throw(OSError('interrupted')))
    with pytest.raises(OSError):e['promotion'].decide(*e['igp'],q)
    assert e['engine'].approval(b)['kind']=='APPROVE' and not e['intake'].pending()
    monkeypatch.setattr(e['intake'],'queue',original);e['engine'].synchronize();assert e['intake'].pending()==[b['batch_id']]
    assert len(e['engine'].journal.rows('BATCH:'+b['batch_id']))==2

def test_approval_does_not_accept_missing_authority_or_change_current_rank(e):
    b=batch(e);visible(e,b);e['engine'].synchronize();result=e['engine'].current(identifier(1))
    assert result['accepted_promotion'] is None and result['pending_promotions']==1
    head=e['engine'].journal.head('ROW:'+b['batch_id']+':1');assert head['result']['status']=='PENDING_REVIEW'
    assert 'AUTHORITY_CANNOT_VERIFY' in head['result']['reasons']

@pytest.mark.parametrize('rank,expected',[('SP','ACCEPTED'),('PC','NOT_ACCEPTED')])
def test_real_authority_algorithm_controls_acceptance_and_current_projection(e,rank,expected):
    before=deepcopy(e['store'].get_packet(identifier(1)));b=batch(e);visible(e,b);assess(e,b,rank);e['engine'].synchronize()
    head=e['engine'].journal.head('ROW:'+b['batch_id']+':1');assert head['result']['status']==expected,head['result']['reasons']
    w=e['service'].workspace(e['hq'][0],identifier(1));accepted=w['current_assignment']['accepted_promotion']
    assert (accepted is not None)==(expected=='ACCEPTED')
    if accepted:assert accepted['to_rank']=='Inspector of Police' and accepted['publication']['fabric_transaction_id']=='b'*64
    assert e['store'].get_packet(identifier(1))==before
    assert e['promotion'].summary(b)['accepted_current_rank_changed']==(expected=='ACCEPTED')
    e['engine'].synchronize();assert len(e['engine'].journal.rows(head['subject']))==1

def test_future_accepted_promotion_waits_until_effective_date(e):
    b=batch(e,effective_date='2027-01-01');visible(e,b);assess(e,b);e['engine'].synchronize()
    assert e['engine'].journal.head('ROW:'+b['batch_id']+':1')['result']['status']=='ACCEPTED'
    assert e['engine'].current(identifier(1))['accepted_promotion'] is None

def test_assessment_correction_invalidates_rank_projection_and_appends_decision(e):
    b=batch(e);visible(e,b);assess(e,b);e['engine'].synchronize();assert e['engine'].current(identifier(1))['accepted_promotion']
    assess(e,b,'PC');assert e['engine'].current(identifier(1))['accepted_promotion'] is None
    e['engine'].synchronize();rows=e['engine'].journal.rows('ROW:'+b['batch_id']+':1')
    assert [r['result']['status'] for r in rows]==['ACCEPTED','NOT_ACCEPTED']

@pytest.mark.parametrize('changes,reason',[({'from_rank':'Police Constable'},'FROM_RANK_DIFFERS'),({'to_rank':'Police Constable'},'PROMOTION_MUST_INCREASE')])
def test_rank_sequence_and_direction_are_not_bypassed_by_valid_authority(e,changes,reason):
    b=batch(e,**changes)
    if b['rows'][0]['status']=='NEEDS_REVIEW':
        with pytest.raises(IntakeError):submit(e,b)
        return
    visible(e,b);assess(e,b);e['engine'].synchronize();assert e['engine'].current(identifier(1))['accepted_promotion'] is None
    assert any(reason in r for r in e['engine'].journal.head('ROW:'+b['batch_id']+':1')['result']['reasons'])

def test_scope_denial_precedes_current_acceptance_disclosure(e):
    e['service'].promotion_acceptance.current=lambda officer:(_ for _ in ()).throw(AssertionError('must not read'))
    with pytest.raises(AccessError):e['service'].workspace(e['hq'][0],identifier(999))

def test_immutable_decision_journal_and_operation_conflict(e):
    b=batch(e);submit(e,b);q=body(b);e['promotion'].decide(*e['igp'],q)
    with e['engine'].journal.transaction() as c:
        with pytest.raises(sqlite3.IntegrityError):c.execute('DELETE FROM events')
    with pytest.raises(IntakeError,match='DECISION_OPERATION_CONFLICT'):e['promotion'].decide(*e['igp'],dict(q,reason='Changed reason'))

def test_dashboard_reflects_accepted_rank_without_touching_source(e):
    from app.access.personnel_dashboard import dashboard
    before=F.profile(e['store'],identifier(1),'a'*64);b=batch(e);visible(e,b);assess(e,b);e['engine'].synchronize()
    result=dashboard(e['service'],e['hq'][0]);row=next(r for r in result['officers'] if r['officer_uid']==identifier(1))
    assert row['rank_code']=='IP' and row['rank_basis']=='ACCEPTED_PROMOTION_EFFECTIVE_NOW'
    assert row['station']==before['reported_posting']['station']
    assert F.profile(e['store'],identifier(1),'a'*64)==before

def test_conflicting_same_date_promotions_remain_pending_even_with_valid_authority(e):
    b=batch(e);visible(e,b);assess(e,b)
    other=batch(e,to_rank='Chief Inspector of Police');visible(e,other);assess(e,other);e['engine'].synchronize()
    assert e['engine'].current(identifier(1))['accepted_promotion'] is None
    for ident in (b['batch_id'],other['batch_id']):assert 'MULTIPLE_UPLOADED_PROMOTIONS_AT_SAME_EFFECTIVE_DATE' in e['engine'].journal.head('ROW:'+ident+':1')['result']['reasons']
    answer=e['workflow'].authority(*e['hq'],dict(officer_uid=identifier(1),known_at=None,action_on=None,status='ALL',limit=50,offset=0))
    assert any('ASSESSMENT_ACTOR_EVIDENCE_CHANGED_OR_UNAVAILABLE' in item['reasons'] for item in answer['items'] if item['uploaded_promotion'])

def test_review_permission_revoked_after_approval_stops_new_processing(e):
    b=batch(e);approve(e,b)
    user=grant(e['key'],'IGP','ALL',None,login='igp.one',now=int(e['clock'][0]),version=2);user['payload']['user_id']=identifier(101);e['store'].access.put_account(account_sign(e['key'],user['payload']))
    with pytest.raises(IntakeError,match='REVIEWER_AUTHORIZATION_CHANGED'):e['engine'].processing_allowed(b)
    assert e['intake'].phase(b['batch_id'],'DOCUMENTS_PREPARED') is None

def test_legacy_published_batch_is_not_republished_or_automatically_accepted(e):
    b=publish(e);e['analysis'].activate_visible();original=e['intake'].phase(b['batch_id'],'QUEUED');binding=batch_binding(b)
    e['engine'].config['legacy_queued'][b['batch_id']]=binding
    # Fixture mutates the in-memory migration inventory only, not production config bytes.
    e['engine'].synchronize();assert e['engine'].current(identifier(1))['accepted_promotion'] is None
    q=body(b,version=0);e['promotion'].decide(*e['igp'],q)
    assert e['intake'].phase(b['batch_id'],'QUEUED')==original and not e['intake'].pending()
    assert e['intake'].phase(b['batch_id'],'VISIBLE') is not None

def test_before_igp_approval_cannot_queue_via_forged_legacy_phase(e):
    b=batch(e);e['intake'].queue(b['batch_id'],{'approved':True})
    with pytest.raises(IntakeError,match='IGP_APPROVAL_REQUIRED'):e['engine'].processing_allowed(b)

def test_expired_session_cannot_approve(e):
    b=batch(e);submit(e,b);e['clock'][0]+=1801
    with pytest.raises(AccessError):e['promotion'].decide(*e['igp'],body(b))
    assert not e['intake'].pending()

def test_real_http_igp_decision_and_hq_forbidden(e):
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from app.access.api import COOKIE,RequestBoundary,_json_object
    from app.intake.promotion_pipeline.http import register
    from test_scoped_access_api import Client
    app=FastAPI()
    @app.exception_handler(AccessError)
    async def denied(request,error):return JSONResponse({'error':error.code},status_code=error.status)
    async def read(request,fields):
        value=json.loads(await request.body(),object_pairs_hook=_json_object)
        if set(value)!=fields:raise AccessError(400,'INVALID_REQUEST')
        return value
    runtime=SimpleNamespace(service=e['promotion'],check_pins=lambda:None,errors={});register(app,runtime,lambda request:request.cookies.get(COOKIE),read)
    client=Client(RequestBoundary(app,'https://access.test:9443'));b=batch(e);submit(e,b)
    client.cookie=COOKIE+'='+e['hq'][0];client.csrf=e['hq'][1]
    assert client.request('/api/research/promotions/decide','POST',body(b))[0]==403
    client.cookie=COOKIE+'='+e['igp'][0];client.csrf=e['igp'][1]
    code,_,caps=client.request('/api/research/promotions/capabilities');assert code==200 and caps['can_approve'] and caps['pending_approval_count']==1
    assert client.request('/api/research/promotions/decide','POST',body(b),origin='https://evil.test')[0]==403
    code,_,result=client.request('/api/research/promotions/decide','POST',body(b));assert code==200 and result['status']=='QUEUED'

def test_private_setup_is_idempotent_and_never_approves_existing_published_data(e,tmp_path,monkeypatch):
    import importlib.util,sys
    from pathlib import Path
    scripts=Path(__file__).resolve().parents[1]/'scripts';monkeypatch.syspath_prepend(str(scripts))
    spec=importlib.util.spec_from_file_location('approval_setup',scripts/'manage_promotion_approvals.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    analysis=e['analysis'];root=e['intake'].root;runtime_file=root/'runtime.json';settings=dict(policy='PROMOTION_PIPELINE_RUNTIME_V1',state_root=str(root),importer_ids=[identifier(100)],source_pins={'reviewed':'pin'})
    runtime_file.write_text(json.dumps(settings));runtime_file.chmod(0o600);analysis.runtime_file=runtime_file;analysis.runtime=settings;analysis.runtime_raw=runtime_file.read_bytes()
    monkeypatch.setattr(module,'configured_analysis',lambda workspace:analysis);monkeypatch.setattr(module,'source_pins',lambda repo:{'reviewed':'pin'});monkeypatch.setattr(module.subprocess,'check_output',lambda *args,**kwargs:'')
    class Socket:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,*args):pass
        def connect_ex(self,*args):return 1
    monkeypatch.setattr(module.socket,'socket',Socket)
    one=module.initialize(e['store'],'https://127.0.0.1:8443');assert one['new_uploads_require_igp_approval'] and not one['existing_batches_automatically_accepted']
    raw=runtime_file.read_bytes();analysis.runtime=json.loads(raw);analysis.runtime_raw=raw
    two=module.initialize(e['store'],'https://127.0.0.1:8443');assert one==two and runtime_file.read_bytes()==raw
    assert len(list(root.glob('runtime-before-igp-approval-*.json')))==1

def test_explicit_igp_renewal_preserves_original_queue_and_source(e):
    b=batch(e);approve(e,b);queued=e['intake'].phase(b['batch_id'],'QUEUED');before=deepcopy(b);e['clock'][0]+=2
    fresh=grant(e['key'],'IGP','ALL',None,login='igp.one',now=int(e['clock'][0]),version=2);fresh['payload']['user_id']=identifier(101);e['store'].access.put_account(account_sign(e['key'],fresh['payload']))
    token,csrf=e['store'].access.login('igp.one',PASSWORD,'renewed-igp')
    d=disclosure(e['key'],officer=identifier(1),version=2,now=int(e['clock'][0]));d['payload']['user_id']=identifier(101);e['store'].import_grant(sign(e['key'],d['payload']))
    with pytest.raises(IntakeError,match='REVIEWER_AUTHORIZATION_CHANGED'):e['engine'].processing_allowed(b)
    result=e['promotion'].decide(token,csrf,body(b,version=2));assert result['processing_approval_version']==3
    e['engine'].processing_allowed(b)
    assert e['intake'].phase(b['batch_id'],'QUEUED')==queued and e['intake'].get(b['batch_id'])==before

def test_decision_audit_outbox_retains_actor_and_exact_event_reference(e):
    events=[]
    class Logs:
        def append(self,event):events.append(deepcopy(event));return len(events)
    e['store'].accountability=Logs();b=batch(e)
    user=e['promotion'].actor(e['hq'][0],e['hq'][1]);e['engine'].request(b,user)
    igp=e['promotion'].actor(*e['igp']);e['engine'].decide(b,igp,body(b));e['engine'].audit_outbox();e['engine'].audit_outbox()
    assert len(events)==2 and events[0]['actor']['username']=='station.one' and events[1]['actor']['username']=='igp.one'
    assert all(v['promotion_batch_id']==b['batch_id'] and len(v['promotion_decision_reference'])==64 for v in events)

def test_approval_config_change_stops_before_queue_and_evidence_processing(e):
    b=batch(e);submit(e,b);e['engine'].file.write_text('{}')
    with pytest.raises(IntakeError,match='APPROVAL_CONFIGURATION_CHANGED'):e['promotion'].decide(*e['igp'],body(b))
    assert not e['intake'].pending()

def test_analysis_enabled_runtime_cannot_fall_back_to_direct_hq_processing(e,tmp_path):
    from app.intake.promotion_pipeline.runtime import Runtime
    keys=('policy','state_root','key_file','backup_key_file','importer_ids','baseline_source_set_sha256','postgres_credentials','mongo_credentials','chains','source_pins')
    config=dict.fromkeys(keys,'fixture');config.update(policy='PROMOTION_PIPELINE_RUNTIME_V1',analysis_config='existing-analysis',importer_ids=[identifier(100)])
    file=tmp_path/'incomplete-runtime.json';file.write_text(json.dumps(config));file.chmod(0o600)
    with pytest.raises(IntakeError,match='IGP_APPROVAL_SETUP_REQUIRED'):Runtime(e['store'],e['service'],file)
