"""Synthetic archive fixtures only; no live identity, database, permit or blockchain."""
from collections import Counter
from copy import deepcopy
from dataclasses import asdict,replace
from datetime import date,datetime,timezone
import json
from uuid import uuid4
import pytest
from app.identity.historical_reconstruction import reconstruct
from app.identity.historical_source_claims import source_claims,HEADERS
from app.identity.historical_officer_selection import Selection
from app.identity.historical_explanation import explain,REASONS
from app.identity.historical_result_review import replay_saved,json_value
import app.identity.review_history_explanations as R
from app.identity.evidence_bundle_v2 import seal_artifact,open_artifact
from app.intake.registration_receipt import save_receipt
from test_protected_commitment import identity_crypto

SHA='d'*64
ON=date(2024,12,31)
CAPTURE=datetime(2026,10,9,4,0,tzinfo=timezone.utc)


@pytest.fixture
def archive():
    officer=str(uuid4());catalog={};bindings=dict(raw_bindings={})
    def add(filename,updates):
        raw=format(len(catalog)+1,'064x')
        columns=sorted(HEADERS[filename]) if filename in HEADERS else ['officer_nic_no']
        row={c:'' for c in columns};row.update(updates)
        catalog[raw]=dict(raw_record_id=raw,filename=filename,original=dict(columns=columns,values=[row[c] for c in columns]),
            classification='UNASSESSED',candidate_links=[dict(officer_uid=officer,role='officer_nic_no',state='CANDIDATE_NOT_ACCEPTED')],
            delivery=dict(complete=True),assertion=dict(id='fixture-assertion'),provenance=dict(source_row_number=1))
        bindings['raw_bindings'][raw]=[dict(row_sha256='b'*64)]
        return raw
    profile=add('officer_personal_information.csv',dict(officer_nic_no='fixture-sensitive-nic'))
    add('promotion_history.csv',dict(to_rank='fixture-sensitive-rank',effective_date='2020-01-01'))
    add('officer_service_information.csv',dict(current_rank='fixture-sensitive-rank',service_status='fixture-sensitive-status'))
    add('officer_police_numbers.csv',dict(police_no='fixture-number-A',number_type='fixture-type-A',valid_from='2020-01-01'))
    add('officer_police_numbers.csv',dict(police_no='fixture-number-B',number_type='fixture-type-A',valid_from='2020-01-01'))
    add('officer_restrictions.csv',dict(restriction_id='fixture-sensitive-restriction',restriction_start_date='2020-01-01'))
    manifest=dict(bundles=[dict(officer_uid=officer)],snapshot=dict(collection_started_at=CAPTURE.isoformat()))
    values=reconstruct(officer,source_claims(officer,{k:v for k,v in catalog.items() if v['filename'] in HEADERS},bindings['raw_bindings']),on=ON,captured_at=CAPTURE)
    context=dict(code_revision='a'*40,bundle_attempt_id='bundle',binding_attempt_id='binding',commitment_attempt_id='commitment',binding_artifact_sha256='b'*64)
    payload=dict(policy='REPORTED_HISTORICAL_RECONSTRUCTION_V1',on=ON.isoformat(),known_snapshot_capture=CAPTURE.isoformat(),
        context=context,selection=json_value(asdict(Selection(officer,(profile,)))),
        results=[dict(officer_uid=officer,projections=json_value([asdict(v) for v in values]))])
    summary=dict(policy=payload['policy'],status='PASSED',code_revision=context['code_revision'],officers=1,on=ON.isoformat(),
        aggregate=dict(Counter(v.dimension+':'+v.status for v in values)),encrypted_artifacts=1,selection_mode='SINGLE_NIC_CANDIDATE',
        accepted_state_claim=False,classification='UNASSESSED',public_payload_sha256=SHA,context=context)
    return officer,manifest,catalog,bindings,values,summary,payload


def replay(a):
    _,manifest,catalog,bindings,_,summary,payload=a
    context={k:v for k,v in summary['context'].items() if k!='code_revision'}
    return replay_saved(summary,[payload],manifest,catalog,bindings,evidence_context=context,public_sha=SHA)


def test_completed_result_is_replayed_with_explanations_and_no_status_change(archive):
    report=replay(archive)
    assert len(report)==1 and len(report[0]['dimensions'])==5
    assert [d['status'] for d in report[0]['dimensions']]==[p.status for p in archive[4]]
    assert all(d['accepted_state_claim'] is False for d in report[0]['dimensions'])


def test_value_free_aggregate_explains_rank_review_and_number_overlap(archive):
    report=replay(archive); aggregate=R.aggregate_explanations(report)
    encoded=json.dumps(aggregate)
    assert all(x not in encoded for x in (archive[0],'fixture-sensitive','fixture-number','fixture-type','fixture-assertion'))
    assert aggregate['claim_mode_counts']['rank:SNAPSHOT']==1
    assert aggregate['review_issue_counts']['posting:REPORTED_DATE_MISSING']>=1
    assert aggregate['police_number_observation_totals']['types_with_multiple_reported_numbers']==1


def test_different_number_types_observed_without_resolving_original_conflict(archive):
    projection=next(v for v in archive[4] if v.dimension=='police_number')
    b=projection.candidates[1];value=json.loads(b.value);value['number_type']='another-fixture-type'
    b=replace(b,value=json.dumps(value))
    report=explain(replace(projection,candidates=(projection.candidates[0],b)))
    assert report['status']=='CONFLICTING_REPORTS'
    assert report['police_number_observations']['distinct_reported_number_types']==2
    assert report['police_number_observations']['types_with_multiple_reported_numbers']==0


def test_duplicate_candidate_and_supporting_not_double_counted(archive):
    rank=archive[4][0];report=explain(rank)
    total=sum(report['group_counts'].values())
    assert report['unique_claims']<total


@pytest.mark.parametrize('change',['value','date','officer','dimension','status','accepted','fingerprint','reason','missing_projection'])
def test_saved_projection_tampering_fails_exact_replay(archive,change):
    a=deepcopy(archive);p=a[6]['results'][0]['projections'][0]
    if change=='value':p['candidates'][0]['value']='tampered'
    elif change=='date':p['candidates'][0]['start']='1999-01-01'
    elif change=='officer':a[6]['results'][0]['officer_uid']=str(uuid4())
    elif change=='dimension':p['dimension']='unknown'
    elif change=='status':p['status']='REPORTED_CANDIDATES'
    elif change=='accepted':p['accepted_state']='claimed'
    elif change=='fingerprint':p['candidates'][0]['destination_digest']='e'*64
    elif change=='reason':p['reasons']=[]
    else:a[6]['results'][0]['projections'].pop()
    with pytest.raises(ValueError):replay(a)


@pytest.mark.parametrize('change',['incomplete','count','chunks','aggregate','selection','mode','context','snapshot','on','public','extra'])
def test_saved_metadata_missing_scope_and_version_changes_fail(archive,change):
    a=deepcopy(archive);summary,payload=a[5:7]
    if change=='incomplete':summary['status']='STOPPED'
    elif change=='count':summary['officers']=2
    elif change=='chunks':summary['encrypted_artifacts']=2
    elif change=='aggregate':summary['aggregate']={}
    elif change=='selection':payload['selection']['linkage_accepted']=True
    elif change=='mode':summary['selection_mode']='ALL_OFFICERS'
    elif change=='context':payload['context']=dict(payload['context'],binding_attempt_id='wrong')
    elif change=='snapshot':payload['known_snapshot_capture']='2020-01-01T00:00:00+00:00'
    elif change=='on':payload['on']='2024-01-01'
    elif change=='public':summary['public_payload_sha256']='e'*64
    else:summary['extra']='unsupported'
    with pytest.raises(ValueError):replay(a)


def test_anchored_source_change_cannot_replay_stored_projection(archive):
    a=deepcopy(archive)
    row=next(v for v in a[2].values() if v['filename']=='promotion_history.csv')
    row['original']['values'][row['original']['columns'].index('to_rank')]='changed fixture'
    with pytest.raises(ValueError):replay(a)


@pytest.mark.parametrize('change',['reason','issue','filename','dimension'])
def test_unknown_output_strings_are_not_disclosed(archive,change):
    p=archive[4][0]
    if change=='dimension':p=replace(p,dimension='private-personnel-value')
    elif change=='reason':p=replace(p,reasons=('private-personnel-value',))
    elif change=='issue':p=replace(p,review=(replace(p.review[0],issues=('private-personnel-value',)),))
    else:
        c=p.candidates[0];ref=json.loads(c.source_reference);ref['filename']='private-personnel-value'
        p=replace(p,candidates=(replace(c,source_reference=json.dumps(ref)),),supporting=())
    with pytest.raises(ValueError):explain(p)


def write_archive(tmp_path,archive,crypto):
    directory=tmp_path/'saved';directory.mkdir(mode=0o700)
    summary,payload=archive[5:7]
    b=dict(artifact='REPORTED_HISTORY',policy=summary['policy'],context=summary['context'],
        public_payload_sha256=SHA,on=summary['on'],selection_mode=summary['selection_mode'],chunk=0)
    envelope=seal_artifact(crypto,crypto,payload,b)
    save_receipt(envelope,directory/'history-000.encrypted.json')
    return directory,envelope


def test_saved_ciphertext_and_backup_recovery_are_required(archive,tmp_path,monkeypatch):
    crypto=identity_crypto(tmp_path);directory,envelope=write_archive(tmp_path,archive,crypto)
    monkeypatch.setattr(R,'PUBLIC_SHA',SHA)
    assert R.saved_payloads(directory,archive[5],crypto,crypto)==[archive[6]]
    envelope['ciphertext']='broken';(directory/'history-000.encrypted.json').write_text(json.dumps(envelope))
    with pytest.raises(Exception):R.saved_payloads(directory,archive[5],crypto,crypto)


@pytest.mark.parametrize('change',['stopped','missing','extra','wrong_binding','symlink','permissions','bad_backup'])
def test_unsafe_or_incomplete_archives_cannot_be_read(archive,tmp_path,monkeypatch,change):
    crypto=identity_crypto(tmp_path);directory,env=write_archive(tmp_path,archive,crypto)
    monkeypatch.setattr(R,'PUBLIC_SHA',SHA); backup=crypto
    if change=='stopped':(directory/'STOPPED.json').write_text('{}')
    elif change=='missing':(directory/'history-000.encrypted.json').unlink()
    elif change=='extra':save_receipt(env,directory/'history-001.encrypted.json')
    elif change=='wrong_binding':
        env['binding']['on']='1990-01-01';(directory/'history-000.encrypted.json').write_text(json.dumps(env))
    elif change=='symlink':
        p=directory/'history-000.encrypted.json';moved=directory/'moved';p.rename(moved);p.symlink_to(moved)
    elif change=='permissions':(directory/'history-000.encrypted.json').chmod(0o644)
    else:
        d=tmp_path/'other';d.mkdir();backup=identity_crypto(d)
        backup.encryption_keys['enc']=b'Z'*32
    with pytest.raises(Exception):R.saved_payloads(directory,archive[5],crypto,backup)


def test_cli_reviews_archive_and_keeps_identity_out_of_output(archive,tmp_path,monkeypatch,capsys):
    """Orchestration fixture; anchoring/commitment primitives are tested separately."""
    from types import SimpleNamespace
    crypto=identity_crypto(tmp_path)
    officer,manifest,catalog,bindings,_,summary,payload=archive
    directory,_=write_archive(tmp_path,archive,crypto)
    save_receipt(summary,directory/'PASSED.json')
    key=tmp_path/'key';backup=tmp_path/'backup';key.write_text('test');backup.write_text('test')
    key.chmod(0o600);backup.chmod(0o600)
    commit=tmp_path/'commitment';commit.mkdir(mode=0o700)
    save_receipt({'test':'public'},commit/'public-commitments.json')
    save_receipt({'binding':{}},commit/'commitments.encrypted.json')
    context=summary['context'];saved=dict(context=dict(generator_revision='c'*40))
    monkeypatch.setattr(R.subprocess,'check_output',lambda cmd,**kw:'' if 'status' in cmd else 'e'*40)
    monkeypatch.setattr(R,'private_key_file',lambda p:crypto)
    monkeypatch.setattr(R,'load_keys',lambda *args:SimpleNamespace(assert_separate=lambda c:None))
    monkeypatch.setattr(R,'PUBLIC_SHA',SHA)
    monkeypatch.setattr(R,'digest',lambda p:SHA)
    monkeypatch.setattr(R,'load_attempt',lambda *args:(manifest,catalog))
    monkeypatch.setattr(R,'load_binding',lambda *args:(bindings,context['binding_artifact_sha256']))
    actual_open=R.open_artifact
    def open_saved(crypto,envelope,binding):
        if envelope=={'binding':{}}:return deepcopy(saved)
        return actual_open(crypto,envelope,binding)
    monkeypatch.setattr(R,'open_artifact',open_saved)
    regenerated=[]
    def generate(*args,**kwargs):
        regenerated.append(kwargs['generator_revision'])
        return {'test':'public'},deepcopy(saved)
    monkeypatch.setattr(R,'generate',generate)
    checked=[];monkeypatch.setattr(R,'verify_saved',lambda *args:checked.append(True))
    args=['--key-file',str(key),'--backup-key-file',str(backup),
        '--commitment-key-file',str(tmp_path/'ckey'),'--backup-commitment-key-file',str(tmp_path/'cbkey'),
        '--bundle-attempt',str(tmp_path/'bundle'),'--binding-attempt',str(tmp_path/'binding'),
        '--commitment-attempt',str(commit),'--reconstruction-attempt',str(directory),
        '--output-root',str(tmp_path/'out')]
    assert R.main(args)==0 and regenerated==['c'*40] and checked
    output=capsys.readouterr().out
    assert all(v not in output for v in (officer,'fixture-sensitive','fixture-number','fixture-type'))
    review=next((tmp_path/'out').iterdir())
    report=json.loads((review/'PASSED.json').read_text())
    assert report['mode']=='SAVED_RESULT_REPLAY' and not report['new_audit_executed']
    assert not report['live_readiness_claim'] and report['on']=='2024-12-31'
    env=json.loads((review/'explanations-000.encrypted.json').read_text())
    recovered=actual_open(crypto,env,env['binding'])
    assert recovered['results'][0]['officer_uid']==officer
    assert len(recovered['results'][0]['dimensions'])==5
