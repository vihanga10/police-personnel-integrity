"""Real PostgreSQL tests: only a UUID-labelled disposable launcher container.

No connection from Settings/.env/database.py and no arbitrary database URL.
Without launcher configuration these tests explicitly skip, never imply pass.
"""
from copy import deepcopy
from datetime import timedelta
import os
import secrets
from uuid import UUID
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError
from scripts import run_isolated_recording_postgres as L
from app.identity import committed_evidence_capture as C
from app.identity import recording_tip_witness as W
from test_recording_tip_witness import witnessed
from test_observed_recording_journal import setup
from test_protected_recording_review import verified, keys
from test_witness_secure_transport import secured, listener, wire_client
from test_committed_evidence_capture import OP,commit,capture,rows
from test_committed_evidence_capture import (
    test_committed_readback_receipt_capture_and_idempotent_retry as check_capture,
    test_new_source_intake_and_withdrawal as check_intake,
    test_uncommitted_row_is_not_visible_to_receipt_issuer as check_visibility,
    test_operation_id_and_identical_intent_conflicts as check_conflicts,
    test_delayed_capture_uses_new_observation_time_not_database_or_csv_date as check_delay,
    test_database_restart_keeps_committed_evidence as check_pool_restart,
    test_database_transaction_failure_rolls_back_without_journal_write as check_rollback,
    test_pending_outbox_does_not_extend_query_coverage as check_pending,
    test_lost_post_commit_read_is_recoverable_by_idempotent_retry as check_lost_read,
    test_interruption_never_duplicates_uncertain_capture as check_interruption,
)

pytestmark=pytest.mark.skipif(not os.environ.get(L.ENV),reason='Run isolated PostgreSQL launcher; no database selected.')


def engine_for(config,user,password):
    return create_engine(URL.create('postgresql+psycopg',username=user,password=password,
        host='127.0.0.1',port=config['port'],database=config['database']),hide_parameters=True,
        connect_args={'connect_timeout':5,'options':'-c statement_timeout=5000 -c lock_timeout=2000'})


def attest_server(connection,config):
    row=connection.execute(text("SELECT current_database(), current_user, current_setting('cluster_name'), "
        "current_setting('server_version_num')::int, current_setting('fsync'), pg_is_in_recovery()")).one()
    L.require(row[0]==config['database'] and row[1]==config['user'] and
        row[2]==config['cluster_name'] and 160000<=row[3]<170000 and row[4]=='on' and row[5] is False,
        'Isolated PostgreSQL server identity differs; no schema writes allowed.')


@pytest.fixture
def postgres_case(witnessed):
    config=L.load_config(os.environ[L.ENV])
    admin=engine_for(config,config['user'],config['password'])
    runtime='ppi_runtime_'+secrets.token_hex(8);password=secrets.token_hex(32)
    engine=None;created=False
    try:
        with admin.begin() as connection:
            attest_server(connection,config)
            L.require(connection.execute(text("SELECT count(*) FROM pg_namespace WHERE nspname='identity'")).scalar_one()==0,
                'Existing identity schema refused even in isolated tests.')
            connection.execute(text('CREATE SCHEMA identity'))
            C.metadata.create_all(connection)
            # A parameterized transaction-local setting avoids secrets in SQL text.
            connection.execute(text("SELECT set_config('ppi_test.password',:password,true)"),{'password':password})
            connection.execute(text("DO $$ BEGIN EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', '"+
                runtime+"', current_setting('ppi_test.password')); END $$"))
            connection.execute(text('GRANT USAGE ON SCHEMA identity TO '+runtime))
            connection.execute(text('REVOKE ALL ON identity.recording_evidence_outbox FROM PUBLIC'))
            connection.execute(text('GRANT SELECT, INSERT ON identity.recording_evidence_outbox TO '+runtime))
        created=True
        engine=engine_for(config,runtime,password);C._engine(engine,production=True)
        t=witnessed;s=t['s'];s['clock'][0]+=timedelta(seconds=1)
        _,item=next(iter(s['snapshot']['catalog'].items()));source=deepcopy(item);source['raw_record_id']='b'*64
        values=dict(zip(source['original']['columns'],source['original']['values']));values['police_no']='fixture-200'
        source['original']['values']=[values[k] for k in source['original']['columns']]
        prior=t['adapter'].select()['state']['history'].versions[-1]
        yield dict(t=t,engine=engine,admin=admin,runtime=runtime,config=config,
            submission=dict(operation_id=OP,source_row=source,
            source_claim_id='b'*64+':'+prior.claim.claim_id.split(':',1)[1],supersedes=prior.version_id))
    finally:
        if engine is not None:engine.dispose()
        if created:
            # Re-attest before destructive cleanup: only this newly created test schema.
            L.load_config(os.environ[L.ENV])
            with admin.begin() as connection:
                attest_server(connection,config)
                connection.execute(text('DROP SCHEMA identity CASCADE'))
                connection.execute(text('DROP ROLE '+runtime))
        admin.dispose()


@pytest.mark.parametrize('check',[check_capture,check_intake,check_visibility,check_conflicts,
    check_delay,check_pool_restart,check_rollback,check_pending],ids=[
    'committed-capture-retry','intake-withdrawal','uncommitted-invisible','intent-conflicts',
    'delayed-observation','pool-reconnect','transaction-rollback','pending-coverage'])
def test_real_postgresql_capture_workflow(postgres_case,check):
    check(postgres_case)


def test_real_postgresql_lost_readback_retry(postgres_case,monkeypatch):
    check_lost_read(postgres_case,monkeypatch)


@pytest.mark.parametrize('stage',['checkpoint','witness_before','witness_after'])
def test_real_postgresql_interrupted_capture(postgres_case,monkeypatch,stage):
    check_interruption(postgres_case,monkeypatch,stage)


@pytest.mark.parametrize('statement',[
    "UPDATE identity.recording_evidence_outbox SET envelope_json='{}' WHERE operation_id=:id",
    'DELETE FROM identity.recording_evidence_outbox WHERE operation_id=:id',
    'TRUNCATE identity.recording_evidence_outbox',
])
def test_runtime_mutation_is_denied_by_postgresql(postgres_case,statement):
    d=postgres_case;commit(d);before=[dict(r) for r in rows(d)]
    with pytest.raises(DBAPIError) as error:
        with d['engine'].begin() as connection:connection.execute(text(statement),{'id':OP})
    assert error.value.orig.sqlstate=='42501'
    assert [dict(r) for r in rows(d)]==before


@pytest.mark.parametrize('privilege',['UPDATE','UPDATE (envelope_json)','DELETE','TRUNCATE','TRIGGER'])
def test_guard_rejects_actual_excess_runtime_grants(postgres_case,privilege):
    d=postgres_case
    with d['admin'].begin() as connection:
        connection.execute(text('GRANT '+privilege+' ON identity.recording_evidence_outbox TO '+d['runtime']))
    if privilege=='UPDATE (envelope_json)':
        with d['engine'].connect() as connection:
            assert connection.execute(text("SELECT has_table_privilege(current_user, "
                "'identity.recording_evidence_outbox','UPDATE')")).scalar_one() is False
    with pytest.raises(ValueError,match='append-only'):C._engine(d['engine'],production=True)
    with pytest.raises(ValueError,match='append-only'):commit(d)
    assert rows(d)==[]


def test_commit_forces_synchronous_wal_even_if_role_default_is_off(postgres_case):
    d=postgres_case
    with d['admin'].begin() as connection:
        connection.execute(text('ALTER ROLE '+d['runtime']+" SET synchronous_commit='off'"))
    d['engine'].dispose()
    from sqlalchemy import event
    observed=[]
    def before(connection,cursor,statement,parameters,context,many):
        if statement.startswith('INSERT INTO identity.recording_evidence_outbox'):
            cursor.execute('SHOW synchronous_commit');observed.append(cursor.fetchone()[0])
    event.listen(d['engine'],'before_cursor_execute',before)
    try:commit(d)
    finally:event.remove(d['engine'],'before_cursor_execute',before)
    assert observed==['on'] and len(rows(d))==1


def test_admin_database_role_is_refused(postgres_case):
    with pytest.raises(ValueError,match='append-only'):C._engine(postgres_case['admin'],production=True)


def test_public_bridge_uses_postgresql_and_real_tls_with_fixture_snapshot(postgres_case,secured,monkeypatch):
    import app.identity.algorithm_snapshot as S
    d=postgres_case;t=d['t'];assert secured['t'] is t
    loaded=[]
    def load(*args):loaded.append(args);return t['s']['snapshot']
    monkeypatch.setattr(S,'load_verified_snapshot',load)  # no live research snapshot or readiness waiver
    with listener(secured):
        adapter=W.WitnessedCheckpointRegistry(t['r'],wire_client(secured))
        result=C.commit_evidence_version('fixture',t['s']['repo'],'fixture-revision',d['engine'],adapter,**d['submission'])
        assert result['status']=='COMMITTED'
        s=t['s'];result=C.capture_evidence_version('fixture',s['repo'],'fixture-revision',d['engine'],adapter,
            operation_id=OP,authority_signer=s['authority'],authority_key_id='authority',
            recorder_signer=s['signer'],recorder_key_id='recorder')
    assert result['status']=='CAPTURED' and len(loaded)==2
