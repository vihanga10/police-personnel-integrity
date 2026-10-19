"""Isolated generated analysis scenarios; chain/destination fixtures, real auth and algorithms."""
from copy import deepcopy
from datetime import date,datetime,timedelta,timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
import json
import sqlite3
import pytest
from app.access.policy import AccessError
from app.access import research_policy as P
from app.identity.bitemporal_reconstruction import query
from app.identity.bitemporal_contradictions import compare_history
from app.intake.promotion_pipeline.analysis import AvailabilityJournal,PromotionAnalysis,verified_batch
from app.intake.promotion_pipeline.core import IntakeError,validate_rows
from app.intake.promotion_pipeline.store import IntakeStore
from app.intake.promotion_pipeline.delivery import process
from test_priority2_workflows import env
from test_priority3 import env as review_env
from test_promotion_pipeline import source,csv_bytes,Destination,Chains
from research_workspace_fixture import identifier

def attach(env,tmp_path):
    root=tmp_path/'intake';root.mkdir(mode=0o700)
    keys=[]
    for name in ('intake-key','intake-backup'):
        file=tmp_path/name;file.write_bytes(b'x'*32);file.chmod(0o600);keys.append(file)
    intake=IntakeStore(root,*keys,repo=env['store'].repo,create=True)
    journal_root=tmp_path/'analysis';journal_root.mkdir(mode=0o700)
    analysis=PromotionAnalysis.__new__(PromotionAnalysis)
    analysis.workspace=env['store'];analysis.intake=intake
    analysis.journal=AvailabilityJournal(journal_root,intake.key,repo=env['store'].repo,create=True)
    analysis.guard=lambda:None
    if 'service' not in env:env['service']=env['workflow'].service
    env['service'].promotion_analysis=analysis;env['store'].promotion_analysis=analysis
    env.update(analysis=analysis,intake=intake)
    return env

@pytest.fixture
def connected(env,tmp_path):return attach(env,tmp_path)

def publish(e,*,officer=None,**changes):
    officer=officer or identifier(1)
    now=min(datetime.fromtimestamp(e['clock'][0],timezone.utc),datetime.now(timezone.utc))
    values=dict(promotion_id='CONTROLLED-'+str(uuid4()),officer_nic_no='000000001V',
        effective_date='2024-01-01',to_rank='Inspector of Police');values.update(changes)
    row=source(**values)
    rows=validate_rows([row],lambda nic:[officer],e['intake'].duplicate,now=now)
    assert rows[0]['status']=='READY'
    batch=e['intake'].create(csv_bytes([row]),{'actor':{'user_id':identifier(100),'username':'station.one','account_version':1},
        'received_at':now.isoformat(),'source_reference':'Controlled generated evaluation input',
        'filename':'promotions.csv','baseline_source_set_sha256':'a'*64,'rows':rows},str(uuid4()))
    e['intake'].queue(batch['batch_id'],{'approved':True})
    process(e['intake'],batch['batch_id'],Destination(),Destination(),Chains(),lambda batch:None)
    receipt=e['intake'].phase(batch['batch_id'],'CHAINS_VERIFIED')
    e['clock'][0]=max(e['clock'][0]+2,P.instant(receipt['verification_observed_at']).timestamp()+2)
    return batch

def test_only_visible_verified_batches_activate_and_activation_is_not_backdated(connected):
    e=connected;b=publish(e);a=e['analysis']
    assert a.reports(identifier(1))==[]
    activations=a.activate_visible();assert len(activations)==1
    activation=activations[0]
    assert P.instant(activation['available_at'])>P.instant(b['received_at'])
    e['clock'][0]+=10;assert a.activate_visible()==[]
    assert a.journal.get(b['batch_id'])==activation

def test_plain_preview_and_pending_chain_batches_never_enter_analysis(connected):
    e=connected;now=datetime.fromtimestamp(e['clock'][0],timezone.utc)
    row=source(officer_nic_no='000000001V')
    rows=validate_rows([row],lambda nic:[identifier(1)],e['intake'].duplicate,now=now)
    batch=e['intake'].create(csv_bytes([row]),{'actor':{'user_id':identifier(100),'username':'station.one','account_version':1},
        'received_at':now.isoformat(),'source_reference':'Fixture pending','filename':'promotions.csv',
        'baseline_source_set_sha256':'a'*64,'rows':rows},str(uuid4()))
    e['intake'].queue(batch['batch_id'],{'approved':True});chains=Chains();chains.pending=True
    process(e['intake'],batch['batch_id'],Destination(),Destination(),chains,lambda b:None)
    assert e['analysis'].activate_visible()==[]
    assert e['analysis'].reports(identifier(1))==[]

def test_original_history_and_query_digest_preserved_for_earlier_knowledge(connected):
    e=connected;packet=deepcopy(e['packet']);h=P.history(packet['history'],identifier(1))
    before=query(h,effective_on=date(2024,1,1),known_at=h.coverage_end)
    publish(e);e['analysis'].activate_visible()
    reports=e['analysis'].reports(identifier(1));combined=e['analysis'].recording(packet,identifier(1),reports)
    after=query(combined,effective_on=date(2024,1,1),known_at=h.coverage_end)
    assert after.query_digest==before.query_digest
    assert e['store'].get_packet(identifier(1))==packet

def test_new_report_enters_the_existing_history_engine_after_actual_availability(connected):
    e=connected;publish(e);e['analysis'].activate_visible()
    workspace=e['service'].workspace(e['token'],identifier(1))
    assert workspace['promotion_analysis']['reported_promotions']==1
    answer=e['service'].history(e['token'],e['csrf'],identifier(1),'2024-01-01',workspace['coverage_end'])
    assert answer['promotion_analysis']['reported_promotions']==1
    assert len(answer['promotion_evidence'])==1
    assert any(v['claim']['fields'].get('to_rank')=='Inspector of Police' for v in answer['versions'])
    assert answer['accepted_state'] is None
    assert answer['promotion_evidence'][0]['publication']['fabric_transaction_id']=='b'*64

def test_same_date_different_rank_uses_existing_contradiction_engine(connected):
    e=connected
    publish(e);e['analysis'].activate_visible()
    reports=e['analysis'].reports(identifier(1));h=e['analysis'].recording(e['packet'],identifier(1),reports)
    # The base fixture has a reported rank claim at this same effective date.
    result=compare_history(h,effective_on=date(2024,1,1),known_at=h.coverage_end)
    assert result.comparisons
    answer=e['workflow'].contradictions(e['token'],e['csrf'],dict(officer_uid=identifier(1),
        effective_on='2024-01-01',known_at=h.coverage_end.isoformat(),dimension='ALL',status='ALL',relationship='ALL',limit=50,offset=0))
    assert answer['promotion_analysis']['reported_promotions']==1
    assert answer['comparison_digest']==result.comparison_digest
    assert answer['accepted_contradiction'] is False

def test_missing_approver_remains_a_visible_explained_authority_case(connected):
    e=connected;publish(e);e['analysis'].activate_visible()
    answer=e['workflow'].authority(e['token'],e['csrf'],dict(officer_uid=identifier(1),known_at=None,
        action_on=None,status='ALL',limit=50,offset=0))
    uploaded=[r for r in answer['items'] if r['uploaded_promotion']]
    assert len(uploaded)==1 and uploaded[0]['status']=='CANNOT_VERIFY'
    assert uploaded[0]['action_on'] is None
    assert uploaded[0]['reasons']

def test_earlier_authority_query_excludes_later_upload(connected):
    e=connected;known=datetime.fromtimestamp(e['clock'][0],timezone.utc).isoformat()
    publish(e);e['analysis'].activate_visible()
    answer=e['workflow'].authority(e['token'],e['csrf'],dict(officer_uid=identifier(1),known_at=known,
        action_on=None,status='ALL',limit=50,offset=0))
    assert not any(r['uploaded_promotion'] for r in answer['items'])

def test_scope_is_checked_before_any_promotion_report_is_loaded(connected):
    e=connected
    e['analysis'].reports=lambda *args: (_ for _ in ()).throw(AssertionError('must not read evidence'))
    with pytest.raises(AccessError):e['service'].workspace(e['token'],identifier(999))

def test_activation_journal_forbids_overwrite_delete_and_changed_binding(connected):
    e=connected;b=publish(e);a=e['analysis'];activation=a.activate_visible()[0]
    with a.journal.connection() as c:
        with pytest.raises(sqlite3.IntegrityError):c.execute('DELETE FROM activations')
    with pytest.raises(IntakeError,match='ANALYSIS_RECEIPT_CHANGED'):
        a.journal.append(b['batch_id'],{'changed':True},P.instant(activation['available_at']))

def test_another_officers_report_is_not_returned(connected):
    e=connected;publish(e);e['analysis'].activate_visible()
    assert e['analysis'].reports(identifier(2))==[]

def test_future_effective_promotion_remains_future_not_current_rank(connected):
    e=connected;publish(e,effective_date='2099-01-01');e['analysis'].activate_visible()
    w=e['service'].workspace(e['token'],identifier(1))
    answer=e['service'].history(e['token'],e['csrf'],identifier(1),'2024-01-01',w['coverage_end'])
    rank=next(p for p in answer['projections'] if p['dimension']=='rank')
    assert any(r['effective_from']=='2099-01-01' for r in rank['future'])
    assert answer['accepted_state'] is None

@pytest.mark.parametrize('rank,expected',[('Inspector of Police','REPORTED_AGREEMENT'),('Chief Inspector of Police','REPORTED_CONTRADICTION_CANDIDATE')])
def test_two_independent_uploaded_rows_use_same_date_comparison_rules(connected,rank,expected):
    e=connected;publish(e);e['analysis'].activate_visible()
    e['clock'][0]+=2
    publish(e,to_rank=rank);e['analysis'].activate_visible()
    reports=e['analysis'].reports(identifier(1));h=e['analysis'].recording(e['packet'],identifier(1),reports)
    result=compare_history(h,effective_on=date(2024,1,1),known_at=h.coverage_end)
    ids={r['raw_record_id'] for r in reports}
    comparisons=[c for c in result.comparisons if c.dimension=='rank' and
        all(any(claim.startswith(raw+':') for raw in ids) for claim in c.claim_ids)]
    assert len(comparisons)==1 and comparisons[0].status==expected

@pytest.mark.parametrize('rank,expected',[('SP','VALID'),('PC','INVALID')])
def test_uploaded_action_uses_documented_signed_assessment_not_its_anchoring_status(connected,rank,expected):
    from dataclasses import asdict
    import hashlib
    from app.access import operational_authority as A,authority_case_store as S
    from app.access.generated_connection import signed
    from app.identity.action_authority_integration import AuthorityAssessment
    from app.identity.temporal_authority import Rule
    from app.identity.run_research_algorithms import json_value
    from test_priority2_workflows import fact,state,REF,DATA
    e=connected
    publish(e,promotion_authority='000000001V',promotion_authority_signed_date='2024-01-01')
    e['analysis'].activate_visible();e['clock'][0]+=1
    reports=e['analysis'].reports(identifier(1))
    ref,action=next(iter(e['analysis'].actions(e['packet'],e['directory'],reports).items()))
    h,pins,missing=A.actor_history(e['store'],e['packet'],e['directory'],[action],datetime.fromtimestamp(e['clock'][0],timezone.utc))
    assert not missing
    rule=Rule('explicit-test-rule',(action.action_kind,),('SP',),('ASSESSOR_ROLE',),('EXPLICIT_SCOPE',),('EXPLICIT_TARGET',),date(2010,1,1),None,False,'ASSESSED',(REF,))
    assessed=AuthorityAssessment(e['packet']['source_public_sha256'],A.digest(json_value(asdict(action))),action.destination_digest,
        identifier(1),'EXPLICIT_TARGET',fact(True),fact(True),fact(True),(state(h,rank=rank),),(rule,),(),((REF,hashlib.sha256(DATA).hexdigest()),))
    body=dict(policy=S.POLICY,kind='AUTHORITY_ASSESSMENT',record_origin='GENERATED_RESEARCH_RECORDS',officer_uid=identifier(1),
        action_reference=ref,workspace_sha256=P.fingerprint(e['packet']),source_public_sha256=e['packet']['source_public_sha256'],
        assessment=json_value(asdict(assessed)),actor_packets=pins,recorded_at=datetime.fromtimestamp(e['clock'][0],timezone.utc).isoformat(),
        version=1,supersedes=None,operation_id=str(uuid4()),review_reference='CONTROLLED_DOCUMENTED_TEST')
    envelope=signed(e['assessor'],'fixture-assessor',body)
    S.append(e['store'],envelope,lambda database=None:None,evidence={REF:DATA})
    answer=e['workflow'].authority(e['token'],e['csrf'],dict(officer_uid=identifier(1),known_at=None,
        action_on=None,status='ALL',limit=50,offset=0))
    item=next(r for r in answer['items'] if r['action_reference']==ref)
    assert item['status']==expected and item['assessment_reference']==P.fingerprint(envelope)
    assert not item['police_action_authorized']

def test_enriched_comparison_can_be_saved_reviewed_and_recovered_without_changing_personnel(review_env,tmp_path):
    from app.access import review_workflow as W
    from test_priority3 import requested,decide,inspect
    e=attach(review_env,tmp_path);before=deepcopy(e['store'].get_packet(identifier(1)))
    publish(e);e['analysis'].activate_visible()
    w=e['service'].workspace(e['tokens']['dig'][0],identifier(1))
    body=dict(officer_uid=identifier(1),operation_id=str(uuid4()),finding_id=str(uuid4()),
        effective_on='2024-01-01',known_at=w['coverage_end'],reason='Review the newly observed promotion evidence')
    saved=e['workflow'].mutate(*e['tokens']['dig'],'SAVE',body)
    assert e['workflow'].mutate(*e['tokens']['dig'],'SAVE',body)==saved
    q,request=requested(e,body,saved)
    with pytest.raises(AccessError):decide(e,request,who='dig')
    _,decision=decide(e,request)
    view=inspect(e)
    comparison=view['findings'][0]['versions'][0]['comparison']
    assert comparison['promotion_analysis']['reported_promotions']==1
    assert comparison['promotion_evidence'][0]['publication']['fabric_transaction_id']=='b'*64
    assert e['workflow'].recover(e['tokens']['dig'][0],q['operation_id'])['status']=='APPROVE'
    assert e['store'].get_packet(identifier(1))==before
