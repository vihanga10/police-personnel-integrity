"""Real staging-to-history checks, exclusively inside the attested disposable container."""
import os
from dataclasses import replace
from uuid import UUID
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from scripts import run_isolated_recording_postgres as L
from app.db.staging_base import StagingBase
from app.intake.staging_store import stage_file
from app.intake import controlled_recording_hook as H
from test_committed_evidence_postgres import postgres_case, attest_server
from test_recording_tip_witness import witnessed
from test_observed_recording_journal import setup
from test_protected_recording_review import verified, keys
from test_controlled_recording_hook import stage_values, route, process
from test_controlled_recording_hook import (
    test_correction_capture_preserves_stage_and_prior_history as check_correction,
    test_signed_new_intake_preserves_original_candidate as check_intake,
    test_refresh_expired_route_retries_same_operation as check_refresh,
    test_interrupted_readback_retries_identical_intent as check_retry,
)

pytestmark=pytest.mark.skipif(not os.environ.get(L.ENV),reason='Run isolated PostgreSQL launcher --suite intake-hook; no database selected.')


@pytest.fixture
def staged_postgres(postgres_case):
    d=postgres_case;created=False;B,F,R=H.IntakeBatch.__table__,H.IntakeFile.__table__,H.RawRecord.__table__
    try:
        with d['admin'].begin() as c:
            attest_server(c,d['config'])
            L.require(c.execute(text("SELECT count(*) FROM pg_namespace WHERE nspname='staging'")).scalar_one()==0,
                'Existing staging schema refused even in isolated tests.')
            c.execute(text('CREATE SCHEMA staging'));StagingBase.metadata.create_all(c, tables=[B, F, R])
            c.execute(text('REVOKE ALL ON ALL TABLES IN SCHEMA staging FROM PUBLIC'))
            c.execute(text('GRANT USAGE ON SCHEMA staging TO '+d['runtime']))
            c.execute(text('GRANT SELECT ON ALL TABLES IN SCHEMA staging TO '+d['runtime']))
        created=True
        batch,file,values=stage_values(d)
        result=stage_file(d['admin'],d['t']['s']['snapshot']['crypto'],batch_values=batch,file_values=file,rows=[values])
        assert result.outcome=='IMPORTED'
        with d['engine'].connect() as c:
            registered=c.execute(select(F)).mappings().one();raw=c.execute(select(R.c.raw_record_id)).scalar_one()
        scope=H.StageScope(batch['batch_id'],batch['archive_sha256'],batch['registration_receipt_sha256'],
            str(registered['import_file_id']),file['archive_path'],file['source_file_sha256'],1,'FIXTURE_REPORTED_SOURCE')
        yield dict(d=d,stage_engine=d['engine'],scope=scope,raw=raw,
            claim_id=raw+':'+d['submission']['source_claim_id'].split(':',1)[1],tables=(B,F,R))
    finally:
        if created:
            L.load_config(os.environ[L.ENV])
            with d['admin'].begin() as c:
                attest_server(c,d['config']);c.execute(text('DROP SCHEMA staging CASCADE'))


@pytest.mark.parametrize('check',[check_correction,check_intake,check_refresh],ids=['correction','intake','refresh-retry'])
def test_staging_to_witnessed_history(staged_postgres,check):check(staged_postgres)


def test_lost_readback_retry(staged_postgres,monkeypatch):check_retry(staged_postgres,monkeypatch)


@pytest.mark.parametrize('privilege',['INSERT (payload_ciphertext)','UPDATE (payload_ciphertext)','DELETE','TRUNCATE','TRIGGER'])
def test_excess_staging_grants_are_rejected(staged_postgres,privilege):
    h=staged_postgres;d=h['d']
    with d['admin'].begin() as c:c.execute(text('GRANT '+privilege+' ON staging.raw_record TO '+d['runtime']))
    with pytest.raises(ValueError,match='read-only'):route(h)


def test_runtime_cannot_change_staged_evidence(staged_postgres):
    h=staged_postgres
    with pytest.raises(DBAPIError) as error:
        with h['stage_engine'].begin() as c:c.execute(text('DELETE FROM staging.raw_record'))
    assert error.value.orig.sqlstate=='42501'
    assert process(h,route(h))['status']=='CAPTURED'


def test_uncommitted_staging_row_is_not_routable(staged_postgres):
    h=staged_postgres;d=h['d'];R=H.RawRecord.__table__;F=H.IntakeFile.__table__
    # A new file/row exists only in the writer transaction; the hook uses a separate connection.
    with d['admin'].connect() as c:
        tx=c.begin();file=dict(c.execute(select(F)).mappings().one());row=dict(c.execute(select(R)).mappings().one())
        new=UUID(int=123);file.update(import_file_id=new,archive_path='new/'+file['archive_path'])
        row.update(import_file_id=new,raw_record_id='f'*64,archive_path=file['archive_path'])
        c.execute(F.insert().values(**file));c.execute(R.insert().values(**row))
        scope=replace(h['scope'],import_file_id=str(new))
        with pytest.raises(ValueError,match='missing'):
            H.read_committed_stage(h['stage_engine'],d['t']['s']['snapshot'],scope,'f'*64)
        tx.rollback()


def test_signed_stage_cannot_be_changed_after_route(staged_postgres):
    h=staged_postgres;receipt=route(h)
    # Test administrator simulates corruption; runtime never has this privilege.
    with h['d']['admin'].begin() as c:
        c.execute(H.RawRecord.__table__.update().values(encryption_key_version='unknown'))
    with pytest.raises(ValueError):process(h,receipt)
