"""File-backed transaction tests; SQLite is an internal fixture, not production."""
from copy import deepcopy
from datetime import timedelta
from uuid import UUID
import json
import pytest
from sqlalchemy import create_engine, event, select
from cryptography.exceptions import InvalidTag
from app.identity import committed_evidence_capture as C
from app.identity import observed_recording_journal as J
from app.identity import protected_bitemporal_runner as P
from app.identity.evidence_bundle_v2 import canonical, seal_artifact
from app.identity.protected_commitment import digest
from test_recording_tip_witness import witnessed
from test_observed_recording_journal import setup, numbers
from test_protected_recording_review import verified, keys

OP=str(UUID(int=99))


@pytest.fixture
def committed(witnessed,tmp_path):
    t=witnessed;directory=tmp_path/'fixture-db';directory.mkdir(mode=0o700)
    engine=create_engine('sqlite:///'+str(directory/'main.sqlite'))
    @event.listens_for(engine,'connect')
    def attach(connection,_):connection.execute('ATTACH DATABASE ? AS identity',(str(directory/'evidence.sqlite'),))
    C.metadata.create_all(engine)
    t['s']['clock'][0]+=timedelta(seconds=1)
    raw,item=next(iter(t['s']['snapshot']['catalog'].items()))
    row=deepcopy(item);row['raw_record_id']='b'*64
    values=dict(zip(row['original']['columns'],row['original']['values']));values['police_no']='fixture-200'
    row['original']['values']=[values[k] for k in row['original']['columns']]
    prior=t['adapter'].select()['state']['history'].versions[-1]
    submission=dict(operation_id=OP,source_row=row,
        source_claim_id='b'*64+':'+prior.claim.claim_id.split(':',1)[1],supersedes=prior.version_id)
    yield dict(t=t,engine=engine,submission=submission)
    engine.dispose()


def commit(d,**changes):
    params=deepcopy(d['submission']);params.update(changes);t=d['t']
    return C.commit_loaded_version(t['s']['snapshot'],d['engine'],t['adapter'],**params)


def capture(d,**changes):
    t=d['t'];s=t['s']
    params=dict(operation_id=OP,authority_signer=s['authority'],authority_key_id='authority',
        recorder_signer=s['signer'],recorder_key_id='recorder');params.update(changes)
    return C.capture_loaded_version(s['snapshot'],d['engine'],t['adapter'],**params)


def rows(d):
    with d['engine'].connect() as connection:return connection.execute(select(C.OUTBOX)).mappings().all()


def test_committed_readback_receipt_capture_and_idempotent_retry(committed):
    d=committed;t=d['t'];s=t['s'];old={p:p.read_bytes() for p in s['root'].iterdir()}
    assert commit(d)['status']=='COMMITTED' and capture(d)['status']=='CAPTURED'
    state=t['adapter'].select()['state'];assert numbers(state,s['clock'][0])==['fixture-200']
    assert all(p.read_bytes()==data for p,data in old.items())
    stored=rows(d)[0];assert 'fixture-200' not in stored['envelope_json']
    _,signed=J._read(s['root']/'event-00000001.encrypted.json',s['crypto'],s['backup'],J._binding('EVENT',t['r'].anchor))
    receipt=signed['payload']['authorization']['payload']
    assert receipt['evidence_epoch_sha256']==stored['envelope_sha256']
    assert receipt['issued_at']==s['clock'][0].isoformat()
    assert signed['payload']['observed_at']==s['clock'][0].isoformat()
    assert receipt['claim']['start']=='2024-01-01'
    all_files={p:p.read_bytes() for root in (s['root'],t['r'].root,t['server'].root) for p in root.iterdir()}
    s['clock'][0]+=timedelta(seconds=1200)
    assert capture(d)['status']=='ALREADY_CAPTURED'
    assert commit(d)['status']=='ALREADY_COMMITTED' and len(rows(d))==1
    assert all(p.read_bytes()==data for p,data in all_files.items())


def test_new_source_intake_and_withdrawal(committed):
    d=committed;t=d['t'];s=t['s']
    commit(d,supersedes=None);capture(d)
    state=t['adapter'].select()['state'];assert sorted(numbers(state,s['clock'][0]))==['fixture-100','fixture-200']
    predecessor=next(v for v in state['history'].versions if v.claim.claim_id.startswith('b'*64))
    s['clock'][0]+=timedelta(seconds=1);operation=str(UUID(int=100))
    commit(d,operation_id=operation,source_row=None,source_claim_id=None,supersedes=predecessor.version_id,
        withdrawn=True,withdrawal_reason='fixture source withdrawal')
    capture(d,operation_id=operation)
    assert numbers(t['adapter'].select()['state'],s['clock'][0])==['fixture-100']


def test_uncommitted_row_is_not_visible_to_receipt_issuer(committed):
    d=committed;t=d['t'];s=t['s'];intent={k:v for k,v in d['submission'].items() if k!='operation_id'}
    intent.update(withdrawn=False,withdrawal_reason=None)
    selected=t['adapter'].select();proposed=C._proposed(selected['state'],intent,OP)
    body=dict(policy=C.POLICY,operation_id=OP,journal_anchor=t['r'].anchor,intent=intent,proposed=proposed)
    envelope=seal_artifact(s['crypto'],s['backup'],body,C._binding(OP,t['r'].anchor))
    with d['engine'].connect() as connection:
        transaction=connection.begin()
        connection.execute(C.OUTBOX.insert().values(operation_id=OP,journal_anchor=t['r'].anchor,
            intent_sha256=digest(intent),envelope_sha256=digest(envelope),envelope_json=canonical(envelope)))
        with pytest.raises(ValueError,match='not visible'):capture(d)
        transaction.rollback()
    assert not rows(d) and not (s['root']/'event-00000001.encrypted.json').exists()


@pytest.mark.parametrize('change',['unknown','duplicate','stale','source','slot','subject','columns','withdrawal','clock'])
def test_invalid_submissions_do_not_commit(committed,change):
    d=committed;params={};row=deepcopy(d['submission']['source_row'])
    if change=='unknown':params['supersedes']='missing'
    if change=='duplicate':params.update(source_row=next(iter(d['t']['s']['snapshot']['catalog'].values())),
        source_claim_id=d['submission']['source_claim_id'].replace('b'*64,'a'*64),supersedes=None)
    if change=='stale':
        commit(d);capture(d);d['t']['s']['clock'][0]+=timedelta(seconds=1)
        params['operation_id']=str(UUID(int=101))
    if change=='source':row['filename']='unsupported.csv';params['source_row']=row
    if change=='slot':params['source_claim_id']='b'*64+':rank:current_rank'
    if change=='subject':row['candidate_links'][0]['officer_uid']=str(UUID(int=10));params['source_row']=row
    if change=='columns':row['original']['columns'][0]='changed';params['source_row']=row
    if change=='withdrawal':params.update(withdrawn=True,source_row=None,source_claim_id=None)
    if change=='clock':d['t']['s']['clock'][0]-=timedelta(seconds=1)
    before=len(rows(d))
    with pytest.raises(ValueError):commit(d,**params)
    assert len(rows(d))==before


def test_operation_id_and_identical_intent_conflicts(committed):
    d=committed;commit(d)
    with pytest.raises(ValueError,match='reused'):commit(d,supersedes=None)
    with pytest.raises(ValueError,match='different operation'):commit(d,operation_id=str(UUID(int=103)))
    assert len(rows(d))==1


@pytest.mark.parametrize('change',['ciphertext','digest','intent','anchor','binding','source_context'])
def test_tampered_outbox_cannot_be_signed(committed,change):
    d=committed;commit(d);row=dict(rows(d)[0]);t=d['t'];s=t['s']
    envelope=json.loads(row['envelope_json'])
    if change=='ciphertext':envelope['ciphertext']='AAAA';row['envelope_sha256']=digest(envelope)
    if change=='digest':row['envelope_sha256']='0'*64
    if change=='intent':row['intent_sha256']='0'*64
    if change=='anchor':row['journal_anchor']='0'*64
    if change=='binding':envelope['binding']['operation_id']=str(UUID(int=104));row['envelope_sha256']=digest(envelope)
    if change=='source_context':
        body=C._read(d['engine'],s,OP,t['r'].anchor)['body'];body['source_context']['bundle_attempt_id']='changed'
        envelope=seal_artifact(s['crypto'],s['backup'],body,C._binding(OP,t['r'].anchor));row['envelope_sha256']=digest(envelope)
    row['envelope_json']=canonical(envelope)
    with d['engine'].begin() as connection:connection.execute(C.OUTBOX.update().where(C.OUTBOX.c.operation_id==OP).values(**row))
    with pytest.raises((ValueError,InvalidTag)):capture(d)
    assert not (s['root']/'event-00000001.encrypted.json').exists()


@pytest.mark.parametrize('change',['authority','recorder','missing','connection','baseline'])
def test_capture_requires_pinned_signers_and_committed_read(committed,change):
    d=committed;params={}
    if change!='missing':commit(d)
    if change=='authority':params['authority_signer']=d['t']['s']['signer']
    if change=='recorder':params['recorder_signer']=d['t']['s']['authority']
    if change=='connection':
        with d['engine'].connect() as connection:
            d['engine']=connection
            with pytest.raises(ValueError,match='Engine'):capture(d)
        return
    if change=='baseline':next(iter(d['t']['s']['snapshot']['catalog'].values()))['provenance']['changed']=True
    with pytest.raises(ValueError):capture(d,**params)
    assert not (d['t']['s']['root']/'event-00000001.encrypted.json').exists()


def test_public_entry_refuses_fixture_database(committed):
    d=committed
    with pytest.raises(ValueError,match='PostgreSQL'):
        C.commit_evidence_version(None,d['t']['s']['repo'],'revision',d['engine'],d['t']['adapter'],**d['submission'])


@pytest.mark.parametrize('stage',['checkpoint','witness_before','witness_after'])
def test_interruption_never_duplicates_uncertain_capture(committed,monkeypatch,stage):
    d=committed;t=d['t'];commit(d)
    if stage=='checkpoint':
        original=J._publish
        def fail(path,*args):
            if path.name.startswith('checkpoint-'):raise OSError('fixture checkpoint interruption')
            return original(path,*args)
        monkeypatch.setattr(J,'_publish',fail)
    else:
        original=t['client'].exchange
        def fail(request):
            if request['payload']['operation']=='CAS':
                if stage=='witness_after':original(request)
                raise OSError('fixture witness interruption')
            return original(request)
        t['client'].exchange=fail
    with pytest.raises(OSError):capture(d)
    if stage=='checkpoint':monkeypatch.setattr(J,'_publish',original)
    else:t['client'].exchange=original
    if stage=='witness_after':assert capture(d)['status']=='ALREADY_CAPTURED'
    else:
        with pytest.raises(ValueError):capture(d)
    assert len(list(t['s']['root'].glob('event-*.encrypted.json')))==1
    assert len(rows(d))==1


def test_capture_rejects_duplicate_epoch_even_if_signed(committed,monkeypatch):
    d=committed;commit(d);capture(d)
    t=d['t'];selected=t['adapter'].select();selected['state']['checkpoint']['event_inventory']*=2
    monkeypatch.setattr(t['adapter'],'select',lambda:deepcopy(selected))
    with pytest.raises(ValueError,match='repeatedly'):capture(d)


def test_postgresql_schema_compiles_without_installing_it():
    from sqlalchemy.schema import CreateTable
    from sqlalchemy.dialects.postgresql import dialect
    sql=str(CreateTable(C.OUTBOX).compile(dialect=dialect()))
    assert 'identity.recording_evidence_outbox' in sql and 'UNIQUE (journal_anchor, intent_sha256)' in sql
    assert 'database_reported_created_at TIMESTAMP WITH TIME ZONE' in sql


def test_delayed_capture_uses_new_observation_time_not_database_or_csv_date(committed):
    d=committed;t=d['t'];s=t['s'];prepared=s['clock'][0];commit(d)
    s['clock'][0]+=timedelta(seconds=1800);capture(d)
    state=t['adapter'].select()['state']
    assert state['history'].versions[-1].recorded_at==s['clock'][0]
    assert numbers(state,prepared)==['fixture-100']
    assert numbers(state,s['clock'][0])==['fixture-200']


def test_database_transaction_failure_rolls_back_without_journal_write(committed):
    d=committed
    def fail(_):raise OSError('fixture commit rejected')
    event.listen(d['engine'],'commit',fail)
    try:
        with pytest.raises(OSError):commit(d)
    finally:event.remove(d['engine'],'commit',fail)
    assert not rows(d)
    assert not list(d['t']['s']['root'].glob('event-*.encrypted.json'))


def test_lost_post_commit_read_is_recoverable_by_idempotent_retry(committed,monkeypatch):
    d=committed;original=C._read;calls=[]
    def fail(*args):
        calls.append(1)
        if len(calls)==2:raise OSError('fixture response lost after database commit')
        return original(*args)
    monkeypatch.setattr(C,'_read',fail)
    with pytest.raises(OSError):commit(d)
    monkeypatch.setattr(C,'_read',original)
    assert len(rows(d))==1 and commit(d)['status']=='ALREADY_COMMITTED'
    assert capture(d)['status']=='CAPTURED'


def test_database_restart_keeps_committed_evidence(committed):
    d=committed;commit(d);d['engine'].dispose()
    assert capture(d)['status']=='CAPTURED' and len(rows(d))==1


def test_pending_outbox_does_not_extend_query_coverage(committed):
    d=committed;commit(d);state=d['t']['adapter'].select()['state']
    with pytest.raises(ValueError,match='outside'):numbers(state,d['t']['s']['clock'][0])
    assert state['history'].coverage_end<d['t']['s']['clock'][0]


def test_commit_and_capture_recheck_baseline_during_work(committed,monkeypatch):
    d=committed;original=C.seal_artifact
    def changed(*args):
        envelope=original(*args)
        next(iter(d['t']['s']['snapshot']['catalog'].values()))['provenance']['changed']=True
        return envelope
    monkeypatch.setattr(C,'seal_artifact',changed)
    with pytest.raises(ValueError):commit(d)
    assert not rows(d)


@pytest.mark.parametrize('index',range(5))
def test_postgresql_permission_guard_rejects_mutating_role(index):
    from unittest.mock import MagicMock
    from sqlalchemy.engine import Engine
    engine=MagicMock(spec=Engine);engine.dialect=MagicMock();engine.dialect.name='postgresql'
    flags=[False]*5;flags[index]=True
    engine.connect.return_value.__enter__.return_value.execute.return_value.one.return_value=tuple(flags)
    with pytest.raises(ValueError,match='append-only'):C._engine(engine,production=True)


@pytest.mark.parametrize('durability',[(False,True),(True,False)])
def test_postgresql_guard_rejects_non_durable_or_standby_server(durability):
    from unittest.mock import MagicMock
    from sqlalchemy.engine import Engine
    engine=MagicMock(spec=Engine);engine.dialect=MagicMock();engine.dialect.name='postgresql'
    engine.connect.return_value.__enter__.return_value.execute.return_value.one.side_effect=[(False,)*5,durability]
    with pytest.raises(ValueError,match='fsync'):C._engine(engine,production=True)
