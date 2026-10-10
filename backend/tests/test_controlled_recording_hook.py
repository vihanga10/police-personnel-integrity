"""Synthetic committed staging fixtures; public API rejects SQLite."""
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timezone, timedelta
from uuid import UUID
import pytest
from sqlalchemy import MetaData, Table, Column, JSON, Uuid, create_engine, event, select
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from cryptography.exceptions import InvalidTag
from app.intake import controlled_recording_hook as H
from app.intake.staging_rows import seal_row
from app.identity import committed_evidence_capture as C
from app.identity import observed_recording_journal as J
from scripts import run_isolated_recording_postgres as L
from test_committed_evidence_capture import committed, rows
from test_recording_tip_witness import witnessed
from test_observed_recording_journal import setup, numbers
from test_protected_recording_review import verified, keys


def stage_values(d):
    s=d['t']['s'];item=d['submission']['source_row'];original=item['original']
    batch=dict(batch_id='HOOK-FIXTURE',archive_sha256='c'*64,archive_size_bytes=100,
        expected_file_count=1,registration_receipt_id=UUID(int=88),registration_receipt_sha256='d'*64,
        schema_version='1.0')
    file=dict(archive_path=item['filename'],source_file_sha256='e'*64,size_bytes=100,
        expected_row_count=1,column_count=len(original['columns']),columns=original['columns'],
        declared_encoding='UTF-8',delimiter=',')
    return batch,file,original['values']


def install_fixture_row(d,engine,tables=None):
    batch,file,values=stage_values(d);file_id=UUID(int=89)
    sealed=seal_row(d['t']['s']['snapshot']['crypto'],batch_id=batch['batch_id'],
        archive_path=file['archive_path'],source_file_sha256=file['source_file_sha256'],
        source_row_number=1,columns=file['columns'],values=values)
    row=asdict(sealed);row['import_file_id']=file_id
    tables=tables or (H.IntakeBatch.__table__,H.IntakeFile.__table__,H.RawRecord.__table__)
    now=d['t']['s']['clock'][0]-timedelta(days=200)
    with engine.begin() as c:
        c.execute(tables[0].insert().values(**batch,registered_at=now))
        c.execute(tables[1].insert().values(**file,import_file_id=file_id,batch_id=batch['batch_id'],registered_at=now))
        c.execute(tables[2].insert().values(**row,staged_at=now))
    scope=H.StageScope(batch['batch_id'],batch['archive_sha256'],batch['registration_receipt_sha256'],
        str(file_id),file['archive_path'],file['source_file_sha256'],1,'FIXTURE_REPORTED_SOURCE')
    return dict(d=d,stage_engine=engine,scope=scope,raw=sealed.raw_record_id,
        claim_id=sealed.raw_record_id+':'+d['submission']['source_claim_id'].split(':',1)[1],tables=tables)


@pytest.fixture
def hooked(committed,tmp_path,monkeypatch):
    original_binding=H.row_binding
    def fixture_binding(table,keys,row):
        # SQLite loses tzinfo; restore the synthetic fixture UTC zone only in tests.
        row={k:(v.replace(tzinfo=timezone.utc) if isinstance(v,datetime) and v.tzinfo is None else v)
            for k,v in row.items()}
        return original_binding(table,keys,row)
    monkeypatch.setattr(H,'row_binding',fixture_binding)
    engine=create_engine('sqlite:///'+str(tmp_path/'hook-main.sqlite'))
    @event.listens_for(engine,'connect')
    def attach(c,_):c.execute('ATTACH DATABASE ? AS staging',(str(tmp_path/'stage.sqlite'),))
    # Portable fixture columns only; production uses the unchanged PostgreSQL models.
    meta=MetaData();tables=[]
    for source in (H.IntakeBatch.__table__,H.IntakeFile.__table__,H.RawRecord.__table__):
        tables.append(Table(source.name,meta,*(Column(c.name,JSON() if isinstance(c.type,JSONB)
            else (Uuid(as_uuid=True) if isinstance(c.type,PGUUID) else c.type),primary_key=c.primary_key) for c in source.columns),schema='staging'))
    meta.create_all(engine)
    yield install_fixture_row(committed,engine,tables)
    engine.dispose()


def route(h,**changes):
    d=h['d'];s=d['t']['s'];params=dict(raw_record_id=h['raw'],source_claim_id=h['claim_id'],
        supersedes=d['submission']['supersedes'],authority_signer=s['authority'],authority_key_id='authority')
    params.update(changes)
    return H.issue_loaded_route(s['snapshot'],h['stage_engine'],d['t']['adapter'],h['scope'],**params)


def process(h,receipt,**changes):
    d=h['d'];s=d['t']['s'];params=dict(authority_signer=s['authority'],authority_key_id='authority',
        recorder_signer=s['signer'],recorder_key_id='recorder');params.update(changes)
    return H.process_loaded_route(s['snapshot'],h['stage_engine'],d['engine'],d['t']['adapter'],receipt,**params)


def test_correction_capture_preserves_stage_and_prior_history(hooked):
    h=hooked;d=h['d'];s=d['t']['s'];before=H.read_committed_stage(h['stage_engine'],s['snapshot'],h['scope'],h['raw'])
    result=process(h,route(h));assert result['status']=='CAPTURED'
    assert result['source_change_completeness_established'] is False
    assert numbers(d['t']['adapter'].select()['state'],s['clock'][0])==['fixture-200']
    history=d['t']['adapter'].select()['state']['history'];assert len(history.versions)==2
    assert history.versions[-1].recorded_at==s['clock'][0]
    assert H.read_committed_stage(h['stage_engine'],s['snapshot'],h['scope'],h['raw'])==before
    assert 'fixture-200' not in rows(d)[0]['envelope_json']


def test_signed_new_intake_preserves_original_candidate(hooked):
    h=hooked;assert process(h,route(h,supersedes=None))['status']=='CAPTURED'
    assert sorted(numbers(h['d']['t']['adapter'].select()['state'],h['d']['t']['s']['clock'][0]))==['fixture-100','fixture-200']


def test_refresh_expired_route_retries_same_operation(hooked):
    h=hooked;first=route(h);process(h,first);h['d']['t']['s']['clock'][0]+=timedelta(seconds=1200)
    with pytest.raises(ValueError,match='expired'):process(h,first)
    refreshed=route(h);assert refreshed['payload']['operation_id']==first['payload']['operation_id']
    assert process(h,refreshed)['status']=='ALREADY_CAPTURED' and len(rows(h['d']))==1


@pytest.mark.parametrize('field',['officer_uid','journal_anchor','operation_id','source_claim_id','supersedes','stage_sha256','issued_at','scope'])
def test_route_tampering_cannot_write(hooked,field):
    h=hooked;r=route(h);r['payload'][field]='changed'
    with pytest.raises(ValueError):process(h,r)
    assert not rows(h['d'])


@pytest.mark.parametrize('change',['archive','receipt','file','count','batch','filename','source'])
def test_pins_and_source_routing_are_signed(hooked,change):
    h=hooked;receipt=route(h)
    if change=='source':
        receipt['payload']['scope']['source_system_code']='another';
        with pytest.raises(ValueError):process(h,receipt)
    else:
        field={'archive':'archive_sha256','receipt':'receipt_sha256','file':'file_sha256','count':'expected_rows',
            'batch':'batch_id','filename':'filename'}[change]
        changed=replace(h['scope'],**{field:2 if field=='expected_rows' else
            ('transfer_history.csv' if field=='filename' else ('unknown' if field=='batch_id' else '0'*64))})
        with pytest.raises(ValueError):H.read_committed_stage(h['stage_engine'],h['d']['t']['s']['snapshot'],changed,h['raw'])
    assert not rows(h['d'])


@pytest.mark.parametrize('field',['payload_ciphertext','source_row_number','expected_row_count','columns'])
def test_changed_staging_after_signed_route_is_refused(hooked,field):
    h=hooked;r=route(h);table=h['tables'][2] if field in ('payload_ciphertext','source_row_number') else h['tables'][1]
    value={'payload_ciphertext':b'corrupt','source_row_number':2,'expected_row_count':2,'columns':['changed']}[field]
    with h['stage_engine'].begin() as c:c.execute(table.update().values(**{field:value}))
    with pytest.raises((ValueError,InvalidTag)):process(h,r)
    assert not rows(h['d'])


@pytest.mark.parametrize('signer',['authority_signer','recorder_signer'])
def test_bad_capture_key_does_not_leave_outbox(hooked,signer):
    h=hooked;r=route(h);s=h['d']['t']['s']
    with pytest.raises(ValueError):process(h,r,**{signer:s['signer'] if signer=='authority_signer' else s['authority']})
    assert not rows(h['d'])


def test_invalid_predecessor_never_commits(hooked):
    h=hooked
    with pytest.raises(ValueError):process(h,route(h,supersedes='missing'))
    assert not rows(h['d'])


def test_interrupted_readback_retries_identical_intent(hooked,monkeypatch):
    h=hooked;r=route(h);original=C._read;calls=[]
    def fail(*args):
        calls.append(1)
        if len(calls)==2:raise OSError('lost post-commit response')
        return original(*args)
    monkeypatch.setattr(C,'_read',fail)
    with pytest.raises(OSError):process(h,r)
    monkeypatch.setattr(C,'_read',original)
    assert len(rows(h['d']))==1 and process(h,r)['status']=='CAPTURED'


def test_public_hook_refuses_sqlite(hooked):
    h=hooked
    with pytest.raises(ValueError,match='PostgreSQL'):
        H.process_registered_route(None,'repo','revision',h['stage_engine'],h['d']['engine'],h['d']['t']['adapter'],{})


@pytest.mark.parametrize('index',range(5))
def test_staging_privilege_guard_rejects_mutating_role(index):
    from unittest.mock import MagicMock
    from sqlalchemy.engine import Engine
    e=MagicMock(spec=Engine);e.dialect=MagicMock();e.dialect.name='postgresql';flags=[False]*5;flags[index]=True
    e.connect.return_value.__enter__.return_value.execute.return_value.one.return_value=tuple(flags)
    with pytest.raises(ValueError,match='read-only'):H._stage_engine(e)


def test_named_suite_selection_has_no_database_override(monkeypatch):
    import sys
    seen=[];monkeypatch.setattr(L,'run_suite',lambda suite='recording':seen.append(suite) or 0)
    monkeypatch.setattr(sys,'argv',['launcher','--suite','intake-hook']);assert L.main()==0 and seen==['intake-hook']
    monkeypatch.setattr(sys,'argv',['launcher','--suite','/external/test.py'])
    with pytest.raises(ValueError):L.main()


@pytest.mark.parametrize('skip',[False,True])
def test_new_launcher_suite_enforces_twelve_real_tests(monkeypatch,skip):
    import json, subprocess
    from pathlib import Path
    from test_isolated_recording_postgres_launcher import record
    c=dict(run_id='a'*32,container_name='ppi-recording-test-'+'a'*32,database='ppi_recording_test_'+'a'*32,
        user='ppi_test_admin',password='d'*64,cluster_name='ppi-recording-'+'a'*32,
        container_id='b'*64,image_id='sha256:'+'c'*64,port=54321)
    monkeypatch.setattr(L.secrets,'token_hex',lambda n:'a'*32 if n==16 else 'd'*64)
    monkeypatch.setattr(L.shutil,'which',lambda _: '/fixture/docker');cleaned=[]
    def cmd(*args,**kwargs):
        if args[0]=='run':return subprocess.CompletedProcess(args,0,c['container_id'],'')
        if args[:2]==('container','inspect'):return subprocess.CompletedProcess(args,0,json.dumps([record(c)]),'')
        return subprocess.CompletedProcess(args,0,'','')
    monkeypatch.setattr(L,'command',cmd);monkeypatch.setattr(L,'cleanup',lambda *args:cleaned.append(args))
    def test_run(args,**kwargs):
        assert args[3]=='tests/test_controlled_recording_hook_postgres.py'
        xml=Path(next(a.split('=',1)[1] for a in args if a.startswith('--junitxml=')))
        xml.write_text('<testsuites><testsuite tests="12" failures="0" errors="0" skipped="'+str(int(skip))+'"/></testsuites>')
        return subprocess.CompletedProcess(args,0)
    monkeypatch.setattr(L.subprocess,'run',test_run)
    if skip:
        with pytest.raises(ValueError,match='every expected'):L.run_suite('intake-hook')
    else:assert L.run_suite('intake-hook')==0
    assert cleaned==[(c['container_name'],c['run_id'])]


def test_unknown_suite_is_rejected_before_docker(monkeypatch):
    monkeypatch.setattr(L.shutil,'which',lambda _:pytest.fail('Docker lookup before suite validation'))
    with pytest.raises(ValueError,match='allowlisted'):L.run_suite('external')
