"""Genuine encrypted synthetic run files; tampering never issues verification."""
from collections import Counter
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import hashlib
import json
import pytest

import app.identity.saved_research_algorithms as S
from app.identity.evidence_bundle_v2 import seal_artifact, open_artifact
from app.identity.historical_officer_selection import Selection
from app.identity.historical_reconstruction import reconstruct
from app.identity.historical_source_claims import source_claims
from app.identity.reconstruct_history import subject_index
from app.identity.reported_authority_actions import review_actions, ROUTES
from app.identity.temporal_contradictions import compare_claims
from app.identity.run_research_algorithms import json_value
from app.intake.registration_receipt import save_receipt
from test_historical_reconstruction import source, OFFICER, ON, CAPTURE
from test_protected_commitment import identity_crypto


def write_run(path,snapshot,*,all_officers=False,mutator=None):
    path.mkdir(mode=0o700)
    catalog=snapshot['catalog'];bindings=snapshot['bindings']['raw_bindings']
    buckets=subject_index(snapshot['manifest'],catalog)
    selected=buckets if all_officers else {OFFICER:buckets[OFFICER]}
    mode='ALL_OFFICERS' if all_officers else 'SINGLE_NIC_CANDIDATE'
    selection=None if all_officers else json_value(asdict(Selection(OFFICER,('a'*64,))))
    base=dict(policy=S.RUN,policies=S.POLICIES,context=dict(snapshot['context'],code_revision='b'*40),
        on=ON.isoformat(),public_payload_sha256=S.PUBLIC_SHA,selection_mode=mode)
    statuses,comparisons,reasons,actions=Counter(),Counter(),Counter(),Counter()
    records=[];claim_count=0
    for uid,rows in sorted(selected.items()):
        claims=source_claims(uid,rows,bindings);claim_count+=len(claims)
        values=reconstruct(uid,claims,on=ON,captured_at=CAPTURE)
        findings=compare_claims(uid,claims,on=ON)
        statuses.update(p.dimension+':'+p.status for p in values)
        comparisons.update(f.dimension+':'+f.status for f in findings)
        reasons.update('contradiction:'+r for f in findings for r in f.reasons)
        records.append(json_value(dict(officer_uid=uid,history=[asdict(p) for p in values],comparisons=[asdict(f) for f in findings])))
    action_catalog=catalog if all_officers else {raw:item for raw,item in catalog.items()
        if any(l['officer_uid']==OFFICER for l in item['candidate_links'])}
    action_values=review_actions(action_catalog,bindings,on=ON)
    actions.update(a.action_kind+':'+a.status for a in action_values)
    reasons.update('authority:'+r for a in action_values for r in a.reasons)
    def chunk(prefix,artifact,values,selection=False):
        for index,offset in enumerate(range(0,len(values),100)):
            payload=dict(base,results=values[offset:offset+100])
            if prefix=='officers':payload['selection']=selection
            if mutator:mutator(prefix,payload)
            binding=dict(base,artifact=artifact,chunk=index)
            name=('%s-%0*d.encrypted.json'%(prefix,3 if prefix=='officers' else 4,index))
            save_receipt(seal_artifact(snapshot['crypto'],snapshot['backup'],payload,binding),path/name)
    chunk('officers','OFFICER_ALGORITHM_RESULTS',records,selection)
    chunk('actions','REPORTED_AUTHORITY_ACTIONS',json_value([asdict(a) for a in action_values]))
    report=dict(base,status='PASSED',code_revision='b'*40,officers=len(selected),source_claims=claim_count,
        history_status_counts=dict(sorted(statuses.items())),comparison_counts=dict(sorted(comparisons.items())),
        authority_action_counts=dict(sorted(actions.items())),reason_counts=dict(sorted(reasons.items())),
        authority_action_records=len(action_values),officer_artifacts=(len(selected)+99)//100,
        action_artifacts=(len(action_values)+99)//100,
        action_inventory_rows=dict(sorted(Counter(v['filename'] for v in action_catalog.values()).items())),
        authority_route_files=sorted(ROUTES),classification='UNASSESSED',accepted_state_claim=False,
        accepted_authority_claim=False,accepted_contradiction_claim=False,governing_instruments_assessed=False,
        findings_database_written=False,findings_anchored=False)
    inventory={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in path.iterdir()}
    save_receipt(seal_artifact(snapshot['crypto'],snapshot['backup'],dict(report=report,artifacts=inventory),
        dict(base,artifact='ALGORITHM_COMPLETION')),path/'completion.encrypted.json')
    report['completion_artifact_sha256']=hashlib.sha256((path/'completion.encrypted.json').read_bytes()).hexdigest()
    save_receipt(report,path/'PASSED.json')
    return report


@pytest.fixture
def run_fixture(tmp_path,monkeypatch):
    crypto=identity_crypto(tmp_path)
    monkeypatch.setattr(S,'PUBLIC_SHA','e'*64)
    catalog,bindings=source('promotion_history.csv',dict(to_rank='fixture-rank',effective_date='2020-01-01',
        promotion_authority='fixture-authority',promotion_authority_signed_date='2020-01-02'))
    row=next(iter(catalog.values()));row['provenance']['reported_source']='PF_REGISTRY'
    row['candidate_links'].append(dict(officer_uid=OFFICER,role='promotion_authority',state='CANDIDATE_NOT_ACCEPTED'))
    catalog['a'*64]=dict(filename='officer_personal_information.csv',raw_record_id='a'*64,
        candidate_links=[dict(officer_uid=OFFICER,role='officer_nic_no',state='CANDIDATE_NOT_ACCEPTED')])
    uids=[OFFICER]+[str(uuid4()) for _ in range(6595)]
    manifest=dict(bundles=[dict(officer_uid=u) for u in uids],snapshot=dict(collection_started_at=CAPTURE.isoformat()))
    snapshot=dict(crypto=crypto,backup=crypto,catalog=catalog,manifest=manifest,
        bindings={'raw_bindings':bindings},captured_at=CAPTURE,context=dict(code_revision='c'*40,
        bundle_attempt_id='bundle',binding_attempt_id='binding',commitment_attempt_id='commitment',
        binding_artifact_sha256='d'*64))
    directory=tmp_path/'run';write_run(directory,snapshot)
    return snapshot,directory


def test_saved_single_officer_run_replays_old_revision_without_fresh_permit(run_fixture):
    snapshot,path=run_fixture
    saved=S.SavedRun(path,snapshot);report=S.replay(saved)
    assert report['officers']==1 and report['authority_action_records']==1
    assert report['artifact_count']==2 and report['source_context']['code_revision']=='b'*40
    assert not report['new_audit_executed'] and not report['live_readiness_claim']
    assert OFFICER not in json.dumps(report)


@pytest.mark.parametrize('change',['missing','extra','ciphertext','summary','context','stopped','symlink','permissions','completion'])
def test_missing_or_changed_saved_files_are_rejected(run_fixture,change,tmp_path):
    snapshot,path=run_fixture;p=path/'officers-000.encrypted.json'
    if change=='missing':p.unlink()
    elif change=='extra':save_receipt({},path/'unexpected.encrypted.json')
    elif change=='ciphertext':p.write_bytes(p.read_bytes()+b' ')
    elif change=='summary':
        v=json.loads((path/'PASSED.json').read_text());v['officers']=2;(path/'PASSED.json').write_text(json.dumps(v))
    elif change=='context':snapshot['context']['binding_artifact_sha256']='f'*64
    elif change=='stopped':save_receipt({},path/'STOPPED.json')
    elif change=='symlink':
        destination=tmp_path/'moved';p.rename(destination);p.symlink_to(destination)
    elif change=='permissions':p.chmod(0o644)
    else:
        p=path/'completion.encrypted.json';v=json.loads(p.read_text());v['ciphertext']='AAAA'+v['ciphertext'][4:];p.write_text(json.dumps(v))
    with pytest.raises(Exception):S.SavedRun(path,snapshot)


@pytest.mark.parametrize('kind',['history','action','selection','order','scope'])
def test_authentic_but_incorrect_result_content_fails_source_replay(run_fixture,tmp_path,kind):
    snapshot,_=run_fixture
    def mutate(prefix,payload):
        if kind=='history' and prefix=='officers':payload['results'][0]['history'][0]['status']='VALID'
        elif kind=='action' and prefix=='actions':payload['results'][0]['reported_date']='2019-01-01'
        elif kind=='selection' and prefix=='officers':payload['selection']['linkage_accepted']=True
        elif kind=='order' and prefix=='officers':payload['results'][0]['officer_uid']=str(uuid4())
        elif kind=='scope' and prefix=='actions':payload['on']='2019-01-01'
    path=tmp_path/'changed-run';write_run(path,snapshot,mutator=mutate)
    with pytest.raises(ValueError):S.replay(S.SavedRun(path,snapshot))


def test_changed_anchored_source_replay_is_detected(run_fixture):
    snapshot,path=run_fixture;saved=S.SavedRun(path,snapshot)
    original=snapshot['catalog']['b'*64]['original']
    index=original['columns'].index('to_rank');original['values'][index]='different-private-rank'
    with pytest.raises(ValueError):S.replay(saved)


def test_file_changed_after_inventory_check_is_rejected_on_read(run_fixture):
    snapshot,path=run_fixture;saved=S.SavedRun(path,snapshot)
    p=path/'actions-0000.encrypted.json';p.write_bytes(p.read_bytes()+b' ')
    with pytest.raises(ValueError):list(saved.chunks('actions'))


def test_full_6596_fixture_replays_every_officer_chunk(run_fixture,tmp_path):
    snapshot,_=run_fixture;path=tmp_path/'all-run';write_run(path,snapshot,all_officers=True)
    saved=S.SavedRun(path,snapshot);report=S.replay(saved)
    assert report['officers']==6596 and report['artifact_count']==67 and len(saved.officer_names)==66


def test_duplicate_json_fields_are_refused():
    with pytest.raises(ValueError):S.read_json_bytes('{"status":"PASSED","status":"FAILED"}')
