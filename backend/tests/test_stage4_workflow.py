"""Generated-fixture tests with actual encryption and local authenticated witnesses."""
from datetime import date
import json
from pathlib import Path
from uuid import uuid4
import pytest
from test_generated_connection import deployment, prepare, connect, OFFICER, SECOND, PASSWORD
from research_connection_fixture import connected, setup, verified, keys
from app.access import stage4_workflow as S, generated_connection as G, research_connection_runtime as R
from app.access.research_service import ResearchService
from app.access.research_app import configured
from app.access.policy import AccessError
from app.identity.protected_commitment import digest

@pytest.fixture
def ready(deployment):
    d=deployment;prepare(d);connect(d)
    d['stage4']=d['root'].parent/'stage4'
    S.prepare(d['repo'],d['stage4'],d['app'],d['root'])
    G.connect(d['repo'],d['root'],d['app'],d['t']['config']['source']['audit_gate_attempt'],review_policy=d['stage4']/'request-policy.json')
    return d

def login(d,name='research.dig.a'):
    store,_=configured(d['app']/'workspace-config.json')
    token,csrf=store.access.login(name,PASSWORD,'fixture-stage4')
    return store,ResearchService(store),token,csrf

def request(d,kind='CORRECTION'):
    store,service,token,csrf=login(d);w=service.workspace(token,OFFICER);f=w['findings'][0]
    body=dict(officer_uid=OFFICER,operation_id=str(uuid4()),finding_id=f['finding_id'],target_head_sha256=f['head_sha256'],
        generation=w['generation'],kind=kind,decision='NEEDS_MORE_EVIDENCE',
        reason='Re-evaluate on the following effective date',evidence_references=[f['head_sha256']])
    result=service.request_review(token,csrf,body)
    return store,body,w,result

def test_signed_request_policy_scope_roles_and_recovery(ready):
    d=ready;store,service,t,c=login(d)
    assert service.workspace(t,OFFICER)['can_request_review']
    with pytest.raises(AccessError):service.workspace(t,SECOND)
    _,oic,ot,oc=login(d,'research.oic.a')
    assert not oic.workspace(ot,OFFICER)['can_request_review']
    store,body,w,result=request(d)
    assert result['status']=='PENDING_AUTHORITY'
    assert store.get_request(body['operation_id'])['request']['reviewer_uid'] not in (OFFICER,SECOND)
    assert service is not None
    _,service,t,c=login(d)
    assert service.request_review(t,c,body)==service.request_status(t,body['operation_id'])
    changed={**body,'reason':'Different intent'}
    with pytest.raises(AccessError):service.request_review(t,c,changed)

def test_policy_tamper_and_account_version_are_rejected(ready):
    d=ready;p=d['stage4']/'request-policy.json';envelope=R.read_json(p,d['repo']);accounts=R.read_json(d['app']/'accounts.json',d['repo'])['accounts']
    rev=G.C.revision(d['repo'])
    assert S.request_policy(p,d['repo'],d['app'],rev,accounts)
    changed=json.loads(json.dumps(accounts));changed[3]['version']+=1
    with pytest.raises(ValueError):S.request_policy(p,d['repo'],d['app'],rev,changed)
    envelope['payload']['request_roles'].append('STATION_OIC');G.write(p,envelope,replace=True)
    with pytest.raises(ValueError):S.request_policy(p,d['repo'],d['app'],rev,accounts)

def test_correction_preserves_prior_finding_and_exact_retry(ready):
    d=ready;store,body,w,result=request(d)
    attempt=d['t']['config']['source']['audit_gate_attempt']
    result=S.correction(d['repo'],d['stage4'],attempt,body['operation_id'],effective_on=date(2025,1,1),known_at=w['coverage_end'])
    assert result['status']=='CORRECTION_RECORDED' and result['earlier_finding_preserved'] and not result['source_records_changed']
    same=S.correction(d['repo'],d['stage4'],attempt,body['operation_id'],effective_on=date(2025,1,1),known_at=w['coverage_end'])
    assert same==result
    with store.accountability.locked() as log_db:
        logged,_=store.accountability.verify(log_db)
    events=[value for _,value in logged if value.get('stage4_action')=='correction']
    assert [e['outcome'] for e in events]==['ATTEMPT','ALLOWED','ATTEMPT','ALLOWED']
    assert all(e['actor']['identity_basis']=='LOCAL_OS_OPERATOR' for e in events)
    with pytest.raises(ValueError):
        S.correction(d['repo'],d['stage4'],attempt,body['operation_id'],effective_on=date(2025,1,2),known_at=w['coverage_end'])
    assert store.get_request(body['operation_id'])['status']=='CORRECTION_RECORDED'
    from contextlib import ExitStack
    with ExitStack() as stack:
        _,_,_,_,findings,_,_=S.open_context(stack,d['repo'],d['stage4'],attempt,OFFICER)
        entries=findings.select()['entries']
        assert len(entries)==2 and entries[0]['entry_sha256']==body['target_head_sha256']
        assert entries[1]['entry']['supersedes']==body['target_head_sha256']

def test_identical_query_correction_is_not_fabricated(ready):
    d=ready;store,body,w,_=request(d)
    with pytest.raises(ValueError,match='duplicate'):
        S.correction(d['repo'],d['stage4'],d['t']['config']['source']['audit_gate_attempt'],body['operation_id'],
            effective_on=date(2024,12,31),known_at=w['coverage_end'])
    with store.accountability.locked() as log_db:
        logged,_=store.accountability.verify(log_db)
    assert logged[-1][1]['outcome']=='FAILED'
    assert logged[-1][1]['reason']=='OPERATION_OUTCOME_UNCERTAIN'

def test_review_requires_temporal_trust_not_login_role(ready):
    d=ready;store,body,w,_=request(d,'REVIEW')
    with pytest.raises(ValueError,match='not configured'):
        S.review(d['repo'],d['stage4'],d['t']['config']['source']['audit_gate_attempt'],body['operation_id'],
            intent_file=d['stage4']/'absent.json',authority_sha256='0'*64,receipt_file=d['stage4']/'absent-receipt.json')
    assert store.get_request(body['operation_id'])['status']=='PENDING_AUTHORITY'

def test_complete_findings_commitments_are_not_chain_receipts(ready):
    d=ready;result=S.prepare_anchor(d['repo'],d['stage4'],d['t']['config']['source']['audit_gate_attempt'],OFFICER)
    assert result['status']=='COMMITMENTS_PREPARED' and not result['chain_submitted'] and not result['both_chains_anchored']
    public=(Path(result['directory'])/'public-findings-commitments.json').read_text()
    assert OFFICER not in public and 'Reported Connection Name' not in public
    assert result['summary']['latest_history_checked']


def test_readiness_does_not_claim_live_checks(ready):
    d=ready;status=S.readiness(d['repo'],d['stage4'])
    assert all(not o['review_trust_configured'] for o in status['officers'])
    assert not status['review_trust_checked_live'] and not status['both_chains_anchored']
    assert status['live_findings_public_adapter']=='NOT_IMPLEMENTED'
