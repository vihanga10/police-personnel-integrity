"""Controlled snapshots only; real permit authentication and encrypted recovery.

Heavy all-row snapshot collection is stubbed in runner tests. Loader tests below
exercise its checks separately. Nothing contacts research databases or chains.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
import hashlib
import json
import pytest
import app.identity.audit_gate as A
import app.identity.algorithm_snapshot as L
import app.identity.run_research_algorithms as R
from app.identity.evidence_bundle_v2 import seal_artifact, open_artifact
from app.identity.historical_officer_selection import Selection
from test_audit_gate import verified
from test_protected_commitment import identity_crypto
from test_temporal_contradictions import c, OFFICER, ON


@pytest.fixture
def snapshot(verified, tmp_path, monkeypatch):
    public, live, fabric, sepolia, context, now = deepcopy(verified)
    crypto = identity_crypto(tmp_path)
    permit = A.verify_inputs(public, live, fabric, sepolia, context, now=now)
    envelope = A.seal_permit(crypto, crypto, permit)
    monkeypatch.setattr(R, 'PUBLIC_SHA', A.PUBLIC_SHA)
    return dict(crypto=crypto, backup=crypto, public=public, context=context,
        envelope=envelope, manifest={}, catalog={}, bindings={'raw_bindings': {}},
        captured_at=now)


def argv(tmp_path):
    args=[]
    for name in ('key-file','backup-key-file','commitment-key-file','backup-commitment-key-file',
        'bundle-attempt','binding-attempt','commitment-attempt','audit-gate-attempt','output-root'):
        args.extend(['--'+name, str(tmp_path/name)])
    return args+['--on', ON.isoformat(), '--select-nic']


def controlled_runner(snapshot, tmp_path, monkeypatch):
    monkeypatch.setattr(R, 'load_verified_snapshot', lambda *a: snapshot)
    monkeypatch.setattr(R.subprocess, 'check_output', lambda a, **kw:
        '' if 'status' in a else snapshot['context']['code_revision'])
    buckets={str(uuid4()): {} for _ in range(6595)}; buckets[OFFICER]={}
    monkeypatch.setattr(R, 'subject_index', lambda *a: buckets)
    monkeypatch.setattr(R, 'read_private_nic', lambda: 'hidden-test-nic')
    monkeypatch.setattr(R, 'select_from_sql', lambda *a: Selection(OFFICER, ('a'*64,)))
    monkeypatch.setattr(R, 'source_claims', lambda *a: (c(), c('b',value={'to_rank':'private-fixture-B'})))
    monkeypatch.setattr(R, 'private_output', lambda p,repo: (p.mkdir(mode=0o700) or p))
    return buckets


def test_selected_combined_run_has_recoverable_encrypted_details_only(snapshot,tmp_path,monkeypatch,capsys):
    controlled_runner(snapshot,tmp_path,monkeypatch)
    assert R.main(argv(tmp_path))==0
    attempt=next((tmp_path/'output-root').iterdir())
    summary=json.loads((attempt/'PASSED.json').read_text())
    assert summary['officers']==1 and summary['comparison_counts']=={'rank:REPORTED_CONTRADICTION_CANDIDATE':1}
    assert not summary['accepted_state_claim'] and not summary['findings_database_written']
    envelope=json.loads((attempt/'officers-000.encrypted.json').read_text())
    payload=open_artifact(snapshot['crypto'],envelope,envelope['binding'])
    assert payload['results'][0]['officer_uid']==OFFICER
    assert len(payload['results'][0]['history'])==5
    assert payload['results'][0]['comparisons'][0]['claim_ids']==['a','b']
    completion=json.loads((attempt/'completion.encrypted.json').read_text())
    index=open_artifact(snapshot['crypto'],completion,completion['binding'])
    assert index['artifacts']=={'officers-000.encrypted.json':
        hashlib.sha256((attempt/'officers-000.encrypted.json').read_bytes()).hexdigest()}
    for public_text in (capsys.readouterr().out,json.dumps(summary),json.dumps(envelope)):
        assert OFFICER not in public_text and 'hidden-test-nic' not in public_text and 'private-fixture-B' not in public_text
    assert not attempt.stat().st_mode & 0o077
    assert all(not p.stat().st_mode & 0o077 for p in attempt.iterdir())


@pytest.mark.parametrize('failure',['expired','context','ciphertext','publication'])
def test_invalid_permit_stops_before_selection_or_output(snapshot,tmp_path,monkeypatch,failure):
    controlled_runner(snapshot,tmp_path,monkeypatch)
    if failure=='expired':
        permit=open_artifact(snapshot['crypto'],snapshot['envelope'],snapshot['envelope']['binding'])
        permit['expires_at']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        snapshot['envelope']=A.seal_permit(snapshot['crypto'],snapshot['backup'],permit)
    elif failure=='context':snapshot['context']['code_revision']='f'*40
    elif failure=='ciphertext':snapshot['envelope']['ciphertext']='AAAA'+snapshot['envelope']['ciphertext'][4:]
    else:snapshot['public']['officers'][0]['commitment']='f'*64
    monkeypatch.setattr(R,'read_private_nic',lambda: pytest.fail('Blocked permit must not request NIC'))
    assert R.main(argv(tmp_path))==1
    assert not (tmp_path/'output-root').exists()


def test_partial_officer_universe_cannot_be_selected(snapshot,tmp_path,monkeypatch):
    buckets=controlled_runner(snapshot,tmp_path,monkeypatch);buckets.pop(next(iter(buckets)))
    assert R.main(argv(tmp_path))==1 and not (tmp_path/'output-root').exists()


def test_failure_after_encrypted_chunk_leaves_stopped_not_passed(snapshot,tmp_path,monkeypatch):
    controlled_runner(snapshot,tmp_path,monkeypatch)
    monkeypatch.setattr(R,'review_actions',lambda *a,**k: (_ for _ in ()).throw(ValueError('fixture interruption')))
    assert R.main(argv(tmp_path))==1
    attempt=next((tmp_path/'output-root').iterdir())
    assert (attempt/'officers-000.encrypted.json').exists()
    assert (attempt/'STOPPED.json').exists() and not (attempt/'PASSED.json').exists()


def test_expiry_during_encryption_prevents_result_release(snapshot,monkeypatch):
    original=R.seal_artifact
    clock=[datetime.now(timezone.utc)]
    monkeypatch.setattr(R,'require_audit_permit',lambda *args: A.require_audit_permit(*args,now=clock[0]))
    def seal(*args):
        result=original(*args)
        clock[0]+=timedelta(minutes=20)
        return result
    monkeypatch.setattr(R,'seal_artifact',seal)
    with pytest.raises(ValueError):R.protected_result(snapshot,{'detail':'private-fixture'}, {'test':'binding'})


@pytest.fixture
def loader(snapshot,tmp_path,monkeypatch):
    # Exact file fingerprints and genuine AEAD opening remain enabled.
    paths={name:tmp_path/name for name in ('bundle','binding','commitment','gate')}
    for p in paths.values():p.mkdir(mode=0o700)
    def write(path,value):
        path.write_text(json.dumps(value));path.chmod(0o600)
    binding_path=paths['binding']/'destination-bindings.encrypted.json'
    write(binding_path,{'fixture':'captured binding'})
    sha=hashlib.sha256(binding_path.read_bytes()).hexdigest()
    context=deepcopy(snapshot['context']);context.update(bundle_attempt_id='bundle',binding_attempt_id='binding',
        commitment_attempt_id='commitment',binding_artifact_sha256=sha)
    permit=open_artifact(snapshot['crypto'],snapshot['envelope'],snapshot['envelope']['binding'])
    permit['context']=context
    snapshot['envelope']=A.seal_permit(snapshot['crypto'],snapshot['backup'],permit)
    write(paths['gate']/'audit-permit.encrypted.json',snapshot['envelope'])
    write(paths['commitment']/'public-commitments.json',snapshot['public'])
    saved=seal_artifact(snapshot['crypto'],snapshot['backup'],{'context':{'generator_revision':'b'*40}}, {'fixture':'original'})
    write(paths['commitment']/'commitments.encrypted.json',saved)
    primary=tmp_path/'primary';backup=tmp_path/'backup'
    primary.write_text('fixture');backup.write_text('fixture')
    primary.chmod(0o600);backup.chmod(0o600)
    args=SimpleNamespace(key_file=primary,backup_key_file=backup,commitment_key_file=tmp_path/'dedicated',
        backup_commitment_key_file=tmp_path/'dedicated-backup',bundle_attempt=paths['bundle'],
        binding_attempt=paths['binding'],commitment_attempt=paths['commitment'],audit_gate_attempt=paths['gate'])
    monkeypatch.setattr(L,'PUBLIC_SHA',A.PUBLIC_SHA)
    monkeypatch.setattr(L,'private_key_file',lambda *a: snapshot['crypto'])
    monkeypatch.setattr(L,'verify_recovery',lambda *a: None)
    monkeypatch.setattr(L,'load_keys',lambda *a: SimpleNamespace(assert_separate=lambda *a: None))
    manifest={'snapshot':{'collection_started_at':datetime.now(timezone.utc).isoformat()}}
    monkeypatch.setattr(L,'load_attempt',lambda *a: (manifest, {}))
    monkeypatch.setattr(L,'load_binding',lambda *a: ({}, sha))
    monkeypatch.setattr(L,'generate',lambda *a,**k: (snapshot['public'],{}))
    checks=[]
    monkeypatch.setattr(L,'verify_saved',lambda *a: checks.append(a))
    return args,paths,checks


def test_loader_replays_original_generation_and_checks_saved_completion(snapshot,loader,tmp_path):
    args,paths,checks=loader
    loaded=L.load_verified_snapshot(args,tmp_path,snapshot['context']['code_revision'])
    assert len(checks)==1 and loaded['public']==snapshot['public']
    assert checks[0][-1]['code_revision']=='b'*40


@pytest.mark.parametrize('failure',['changed_binding','changed_commitments','changed_saved','same_key_copy'])
def test_loader_integrity_failure_never_releases_snapshot(snapshot,loader,tmp_path,monkeypatch,failure):
    args,paths,checks=loader
    if failure=='changed_binding':monkeypatch.setattr(L,'load_binding',lambda *a: ({},'f'*64))
    elif failure=='changed_commitments':
        altered=deepcopy(snapshot['public']);altered['officers'][0]['commitment']='f'*64
        monkeypatch.setattr(L,'generate',lambda *a,**k: (altered,{}))
    elif failure=='changed_saved':
        p=paths['commitment']/'commitments.encrypted.json';value=json.loads(p.read_text())
        value['ciphertext']='AAAA'+value['ciphertext'][4:];p.write_text(json.dumps(value))
    else:args.backup_key_file=args.key_file
    with pytest.raises(Exception):L.load_verified_snapshot(args,tmp_path,snapshot['context']['code_revision'])
    assert not checks


@pytest.mark.parametrize('change',['publication','permit','context','expired'])
def test_session_rechecks_authenticated_identity_and_time(snapshot,change):
    from app.identity.algorithm_permit import AlgorithmPermit
    session=AlgorithmPermit(snapshot)
    now=datetime.now(timezone.utc)
    if change=='publication':snapshot['public']['officers'][0]['commitment']='f'*64
    elif change=='permit':snapshot['envelope']['ciphertext']='AAAA'+snapshot['envelope']['ciphertext'][4:]
    elif change=='context':snapshot['context']=dict(snapshot['context'],code_revision='f'*40)
    else:now+=timedelta(minutes=20)
    with pytest.raises(Exception):session.check(snapshot,now=now)


def test_session_rechecks_do_not_repeat_merkle_construction(snapshot,monkeypatch):
    from app.identity.algorithm_permit import AlgorithmPermit
    session=AlgorithmPermit(snapshot)
    monkeypatch.setattr(A,'publication_plan',lambda *a: pytest.fail('Unchanged digest already validated'))
    assert session.check(snapshot)['status']=='READY'


def test_complete_synthetic_officer_universe_has_66_recoverable_chunks(snapshot,tmp_path,monkeypatch):
    from dataclasses import replace
    import time
    buckets=controlled_runner(snapshot,tmp_path,monkeypatch)
    monkeypatch.setattr(R,'source_claims',lambda uid,*a: (replace(c(),officer_uid=uid),))
    start=time.monotonic()
    assert R.main(argv(tmp_path)[:-1])==0  # All officers; no private selection.
    attempt=next((tmp_path/'output-root').iterdir())
    summary=json.loads((attempt/'PASSED.json').read_text())
    assert summary['officers']==6596 and summary['officer_artifacts']==66
    recovered=[]
    for path in sorted(attempt.glob('officers-*.encrypted.json')):
        envelope=json.loads(path.read_text())
        recovered.extend(open_artifact(snapshot['crypto'],envelope,envelope['binding'])['results'])
    assert {r['officer_uid'] for r in recovered}==set(buckets)
    assert len(recovered)==6596
    print('Synthetic 6596-officer processing seconds:',round(time.monotonic()-start,2))
