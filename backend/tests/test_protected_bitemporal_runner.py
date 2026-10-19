"""Disposable signed/encrypted evidence and actual loopback TLS integration."""
from copy import deepcopy
from datetime import date, timedelta
import json
import pytest
from cryptography.exceptions import InvalidTag
from app.identity import protected_bitemporal_runner as P
from app.identity import recording_tip_witness as W
from app.identity.evidence_bundle_v2 import open_artifact
from test_recording_tip_witness import witnessed, next_checkpoint
from test_observed_recording_journal import setup, OFFICER, authorize, append
from test_protected_recording_review import verified, keys
from test_witness_secure_transport import secured, listener, wire_client


@pytest.fixture
def output(tmp_path):
    root = tmp_path/'query-output';root.mkdir(mode=0o700)
    return root/'query.encrypted.json'


def run(t, output, **changes):
    args = dict(officer_uid=OFFICER, effective_on=date(2024,12,31),
        known_at=t['s']['clock'][0], destination=output)
    args.update(changes)
    return P.run_loaded_query(t['s']['snapshot'],t['s']['repo'],t['adapter'],**args)


def recover(t, output):
    envelope=json.loads(output.read_text())
    result=open_artifact(t['s']['crypto'],envelope,envelope['binding'])
    assert open_artifact(t['s']['backup'],envelope,envelope['binding'])==result
    return result


def values(result):
    return [json.loads(c['value'])['police_no'] for p in result['query']['projections']
        if p['dimension']=='police_number' for c in p['candidates']]


def inventory(t):
    return {p:p.read_bytes() for root in (t['r'].root,t['s']['root'],t['server'].root)
        for p in root.iterdir()}


def test_encrypted_baseline_query_preserves_stores_and_redacts_summary(witnessed,output):
    t=witnessed;before=inventory(t);summary=run(t,output);result=recover(t,output)
    assert values(result)==['fixture-100'] and result['registry_tip']==t['tip']
    assert result['coverage_semantics']=='JOURNAL_OBSERVATIONS_ONLY'
    assert result['accepted_state'] is None and not result['source_change_completeness_established']
    assert not result['query']['receipt_authenticity_claim']  # pure query makes no authentication claim
    assert result['authenticated_journal_replay']
    assert OFFICER not in json.dumps(summary) and 'fixture-100' not in output.read_text()
    assert output.stat().st_mode&0o777==0o600
    assert inventory(t)==before and list(output.parent.iterdir())==[output]


def test_later_correction_keeps_earlier_query_digest(witnessed,output):
    t=witnessed;start=t['s']['clock'][0];run(t,output);earlier=recover(t,output)
    pin=next_checkpoint(t);t['adapter'].register(checkpoint_file=pin['checkpoint_file'],checkpoint_sha256=pin['checkpoint_sha256'])
    old=output.parent/'earlier.json';new=output.parent/'later.json'
    run(t,old,known_at=start);run(t,new)
    assert values(recover(t,old))==['fixture-100'] and values(recover(t,new))==['fixture-200']
    assert recover(t,old)['query']['query_digest']==earlier['query']['query_digest']
    assert recover(t,old)['registry_tip']['sequence']==2


@pytest.mark.parametrize('change',['before','after','naive','effective','officer'])
def test_invalid_query_has_no_output(witnessed,output,change):
    t=witnessed;now=t['s']['clock'][0]
    changes={'before':dict(known_at=now-timedelta(microseconds=1)),
        'after':dict(known_at=now+timedelta(microseconds=1)),
        'naive':dict(known_at=now.replace(tzinfo=None)),
        'effective':dict(effective_on='2024-12-31'),
        'officer':dict(officer_uid='00000000-0000-0000-0000-000000000002')}[change]
    with pytest.raises(ValueError):run(t,output,**changes)
    assert not list(output.parent.iterdir())


@pytest.mark.parametrize('change',['catalog','binding','context','registry','key','permit'])
def test_wrong_anchored_source_or_config_refused(witnessed,output,change):
    t=witnessed;s=t['s']['snapshot']
    if change=='catalog':next(iter(s['catalog'].values()))['original']['values'][0]='changed'
    if change=='binding':next(iter(s['bindings']['raw_bindings'].values()))[0]['fixture_destination']='f'*64
    if change=='context':s['context']['bundle_attempt_id']='changed'
    if change=='registry':t['r'].repo=output.parent
    if change=='key':t['client'].witness_keys=dict(t['r'].registry_keys)
    if change=='permit':s['envelope']['binding']['fixture']='changed'
    with pytest.raises((ValueError,KeyError,InvalidTag)):run(t,output)
    assert not list(output.parent.iterdir())


@pytest.mark.parametrize('change',['pending','rollback','tampered','unavailable'])
def test_unverifiable_history_blocks_query(witnessed,output,change):
    t=witnessed
    if change in ('pending','rollback'):
        pin=next_checkpoint(t)
        if change=='rollback':
            t['adapter'].register(checkpoint_file=pin['checkpoint_file'],checkpoint_sha256=pin['checkpoint_sha256'])
            (t['r'].root/'entry-00000002.encrypted.json').unlink()
    if change=='tampered':(t['s']['root']/'baseline.encrypted.json').write_text('{}')
    if change=='unavailable':
        def fail(_):raise OSError('fixture offline')
        t['client'].exchange=fail
    with pytest.raises((ValueError,OSError,KeyError)):run(t,output)
    assert not list(output.parent.iterdir())


@pytest.mark.parametrize('change',['source','witness','permit','staging','encryption'])
def test_midflight_failure_removes_temporary_output(witnessed,output,monkeypatch,change):
    t=witnessed;original=P.seal_artifact
    def seal(*args):
        envelope=original(*args)
        if change=='source':next(iter(t['s']['snapshot']['catalog'].values()))['provenance']['extra']='changed'
        if change=='witness':monkeypatch.setattr(t['client'],'head',lambda:dict(sequence=2,sha256='a'*64))
        if change=='permit':t['s']['snapshot']['envelope']['binding']['changed']=True
        if change=='encryption':return {}
        return envelope
    monkeypatch.setattr(P,'seal_artifact',seal)
    if change=='staging':
        def fail(_):raise OSError('fixture fsync failed')
        monkeypatch.setattr(P.os,'fsync',fail)
    with pytest.raises((ValueError,OSError,KeyError)):run(t,output)
    assert not list(output.parent.iterdir())


@pytest.mark.parametrize('change',['existing','symlink','repository','journal','registry','permissions','traversal'])
def test_private_destination_rules(witnessed,output,change):
    t=witnessed;target=output
    if change=='existing':output.write_text('preserved')
    if change=='symlink':output.symlink_to(output.parent/'absent')
    if change=='repository':target=t['s']['repo']/'result.json'
    if change=='journal':target=t['s']['root']/'result.json'
    if change=='registry':target=t['r'].root/'result.json'
    if change=='permissions':output.parent.chmod(0o755)
    if change=='traversal':target=output.parent/'..'/'repo'/'query.json'
    with pytest.raises(ValueError):run(t,target)
    if change=='existing':assert output.read_text()=='preserved'


def test_public_entry_refuses_inprocess_service_before_loader(witnessed,output,monkeypatch):
    import app.identity.algorithm_snapshot as S
    monkeypatch.setattr(S,'load_verified_snapshot',lambda *a:pytest.fail('loader called'))
    with pytest.raises(ValueError,match='mutual-TLS'):
        P.run_bitemporal_query(None,witnessed['s']['repo'],'revision',witnessed['adapter'],
            officer_uid=OFFICER,effective_on=date(2024,12,31),known_at=witnessed['s']['clock'][0],destination=output)


def test_public_entry_uses_loader_and_actual_tls(secured,output,monkeypatch):
    import app.identity.algorithm_snapshot as S
    d=secured;t=d['t'];calls=[]
    def loader(*args):calls.append(args);return t['s']['snapshot']
    monkeypatch.setattr(S,'load_verified_snapshot',loader)  # only anchored-loader fixture boundary
    with listener(d):
        adapter=W.WitnessedCheckpointRegistry(t['r'],wire_client(d))
        summary=P.run_bitemporal_query('fixture-args',t['s']['repo'],'fixture-revision',adapter,
            officer_uid=OFFICER,effective_on=date(2024,12,31),known_at=t['s']['clock'][0],destination=output)
    assert calls==[('fixture-args',t['s']['repo'],'fixture-revision')]
    assert summary['status']=='PUBLISHED' and values(recover(t,output))==['fixture-100']


def test_withdrawal_retains_provenance_and_earlier_candidate(witnessed,output):
    t=witnessed;s=t['s'];start=s['clock'][0];s['clock'][0]+=timedelta(seconds=1)
    pin=append(s,t['pin'],authorize(s,t['pin'],withdrawn=True))
    t['adapter'].register(checkpoint_file=pin['checkpoint_file'],checkpoint_sha256=pin['checkpoint_sha256'])
    run(t,output);result=recover(t,output)
    assert values(result)==[] and result['query']['visible_versions'][0]['withdrawn']
    prior=output.parent/'prior.json';run(t,prior,known_at=start)
    assert values(recover(t,prior))==['fixture-100']


def test_new_runner_revision_can_replay_same_original_baseline(witnessed,output):
    import app.identity.audit_gate as A
    t=witnessed;s=t['s']['snapshot'];context=deepcopy(s['context']);context['code_revision']='f'*40
    envelope=s['envelope'];old=open_artifact(s['crypto'],envelope,envelope['binding'])
    old['context']=context
    s['context']=context
    from app.identity.evidence_bundle_v2 import seal_artifact
    s['envelope']=seal_artifact(s['crypto'],s['backup'],old,A.binding(context))
    run(t,output)
    assert values(recover(t,output))==['fixture-100']


def test_output_race_preserves_other_writer_file(witnessed,output,monkeypatch):
    original=P.os.link
    def race(source,destination):
        output.write_text('other writer output')
        return original(source,destination)
    monkeypatch.setattr(P.os,'link',race)
    with pytest.raises(FileExistsError):run(witnessed,output)
    assert output.read_text()=='other writer output' and list(output.parent.iterdir())==[output]
