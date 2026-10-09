"""Runner boundaries use real synthetic AEAD, receipts and expiring permits."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import pytest
import app.identity.audit_gate as A
import app.identity.saved_research_algorithms as S
import app.identity.verify_saved_research_algorithms as V
import app.identity.review_action_actor_history as R
from app.identity.evidence_bundle_v2 import open_artifact, seal_artifact
from app.intake.registration_receipt import save_receipt
from test_audit_gate import verified
from test_saved_research_algorithms import run_fixture,write_run,OFFICER


def argv(tmp_path,run,actor=False):
    parts=[]
    for name in ('key-file','backup-key-file','commitment-key-file','backup-commitment-key-file',
        'bundle-attempt','binding-attempt','commitment-attempt','algorithm-attempt','output-root'):
        value=run if name=='algorithm-attempt' else tmp_path/('actor-output' if actor and name=='output-root' else name)
        parts.extend(['--'+name,str(value)])
    if actor:
        parts.extend(['--audit-gate-attempt',str(tmp_path/'gate'),'--saved-review-attempt',str(tmp_path/'verification')])
    return parts


def git_fixture(monkeypatch,module,revision):
    monkeypatch.setattr(module.subprocess,'check_output',lambda command,**kw:
        '' if 'status' in command else revision)
    monkeypatch.setattr(module,'private_output',lambda p,repo: (p.mkdir(mode=0o700) or p))


def test_offline_cli_verifies_and_authenticates_receipt_without_permit(run_fixture,tmp_path,monkeypatch,capsys):
    snapshot,run=run_fixture
    monkeypatch.setattr(V,'load_saved_snapshot',lambda *a:snapshot)
    git_fixture(monkeypatch,V,'c'*40)
    assert V.main(argv(tmp_path,run))==0
    directory=next((tmp_path/'output-root').iterdir())
    summary=json.loads((directory/'PASSED.json').read_text())
    envelope=json.loads((directory/'verification.encrypted.json').read_text())
    assert open_artifact(snapshot['crypto'],envelope,envelope['binding'])==summary
    assert not summary['new_audit_executed'] and not summary['live_readiness_claim']
    assert OFFICER not in capsys.readouterr().out


def test_offline_failure_cannot_issue_verification(run_fixture,tmp_path,monkeypatch):
    snapshot,run=run_fixture;(run/'actions-0000.encrypted.json').unlink()
    monkeypatch.setattr(V,'load_saved_snapshot',lambda *a:snapshot);git_fixture(monkeypatch,V,'c'*40)
    assert V.main(argv(tmp_path,run))==1 and not (tmp_path/'output-root').exists()


@pytest.fixture
def actor_run(run_fixture,verified,tmp_path,monkeypatch):
    snapshot,_=run_fixture
    public,live,fabric,sepolia,context,now=verified
    snapshot.update(public=public,context=context)
    monkeypatch.setattr(S,'PUBLIC_SHA',A.PUBLIC_SHA)
    run=tmp_path/'fresh-source-run';write_run(run,snapshot)
    permit=A.verify_inputs(public,live,fabric,sepolia,context,now=now)
    snapshot['envelope']=A.seal_permit(snapshot['crypto'],snapshot['backup'],permit)
    saved=S.SavedRun(run,snapshot);report=S.replay(saved);report['review_revision']='c'*40
    directory=tmp_path/'verification';directory.mkdir(mode=0o700)
    binding=dict(policy=S.POLICY,artifact='SAVED_ALGORITHM_VERIFICATION',review_revision='c'*40,
        algorithm_attempt_id=run.name,completion_artifact_sha256=saved.completion_sha,source_context=saved.report['context'])
    save_receipt(seal_artifact(snapshot['crypto'],snapshot['backup'],report,binding),directory/'verification.encrypted.json')
    save_receipt(report,directory/'PASSED.json')
    monkeypatch.setattr(R,'load_verified_snapshot',lambda *a:snapshot)
    git_fixture(monkeypatch,R,context['code_revision'])
    return snapshot,run,directory


def test_fresh_actor_runner_saves_linked_claim_and_state_inventories(actor_run,tmp_path,capsys):
    snapshot,run,_=actor_run
    assert R.main(argv(tmp_path,run,actor=True))==0
    directory=next((tmp_path/'actor-output').iterdir())
    summary=json.loads((directory/'PASSED.json').read_text())
    assert summary['authority_action_records']==1 and summary['distinct_actor_dates']==1
    assert summary['claim_artifacts']==summary['state_artifacts']==summary['action_artifacts']==1
    records={}
    for kind in ('claims','states','actions'):
        envelope=json.loads(next(directory.glob(kind+'-*.encrypted.json')).read_text())
        records[kind]=open_artifact(snapshot['crypto'],envelope,envelope['binding'])['results']
    assert records['actions'][0]['actor_state_links'][0]['state_id']==records['states'][0]['state_id']
    assert records['states'][0]['claim_inventory_id']==records['claims'][0]['claim_inventory_id']
    completion=json.loads((directory/'completion.encrypted.json').read_text())
    index=open_artifact(snapshot['crypto'],completion,completion['binding'])
    assert len(index['artifacts'])==3 and not summary['accepted_authority_claim']
    assert OFFICER not in capsys.readouterr().out and OFFICER not in json.dumps(summary)


@pytest.mark.parametrize('failure',['expired','ciphertext','wrong_verification','changed_original','verification_hint'])
def test_actor_runner_blocks_invalid_permit_or_review_before_outputs(actor_run,tmp_path,failure):
    snapshot,run,verification=actor_run
    if failure=='expired':
        value=open_artifact(snapshot['crypto'],snapshot['envelope'],snapshot['envelope']['binding'])
        value['expires_at']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        snapshot['envelope']=A.seal_permit(snapshot['crypto'],snapshot['backup'],value)
    elif failure=='ciphertext':snapshot['envelope']['ciphertext']='AAAA'+snapshot['envelope']['ciphertext'][4:]
    elif failure=='wrong_verification':
        path=verification/'verification.encrypted.json';value=json.loads(path.read_text());value['binding']['algorithm_attempt_id']='another-run'
        path.write_text(json.dumps(value))
    elif failure=='changed_original':
        path=run/'actions-0000.encrypted.json';path.write_bytes(path.read_bytes()+b' ')
    else:
        path=verification/'PASSED.json';value=json.loads(path.read_text());value['officers']=2;path.write_text(json.dumps(value))
    assert R.main(argv(tmp_path,run,actor=True))==1 and not (tmp_path/'actor-output').exists()


def test_actor_interruption_after_attempt_cannot_issue_completion(actor_run,tmp_path,monkeypatch):
    _,run,_=actor_run
    monkeypatch.setattr(R.ActorHistory,'review',lambda *a: (_ for _ in ()).throw(ValueError('fixture failure')))
    assert R.main(argv(tmp_path,run,actor=True))==1
    attempt=next((tmp_path/'actor-output').iterdir())
    assert (attempt/'STOPPED.json').exists() and not (attempt/'PASSED.json').exists()


def test_actor_write_expiry_stops_without_releasing_encrypted_result(actor_run,tmp_path,monkeypatch):
    snapshot,run,_=actor_run
    clock=[datetime.now(timezone.utc)]
    from app.identity.algorithm_permit import AlgorithmPermit
    original_check=AlgorithmPermit.check
    monkeypatch.setattr(AlgorithmPermit,'check',lambda self,snapshot: original_check(self,snapshot,now=clock[0]))
    original_review=R.ActorHistory.review
    def review(self,action):
        result=original_review(self,action);clock[0]+=timedelta(minutes=20);return result
    monkeypatch.setattr(R.ActorHistory,'review',review)
    assert R.main(argv(tmp_path,run,actor=True))==1
    attempt=next((tmp_path/'actor-output').iterdir())
    assert (attempt/'STOPPED.json').exists() and not list(attempt.glob('*.encrypted.json'))
