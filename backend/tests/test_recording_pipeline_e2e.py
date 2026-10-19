"""End-to-end candidate evidence checks; disposable data, keys and readiness fixtures."""
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import date, timedelta
from uuid import UUID
import json
import pytest
from sqlalchemy import select
from app.intake import controlled_recording_hook as H
from app.intake.staging_rows import seal_row
from app.intake.staging_store import stage_file
from app.identity import committed_evidence_capture as C
from app.identity import observed_recording_journal as J
from app.identity import recording_tip_witness as W
from app.identity import recording_checkpoint_registry as R
from test_controlled_recording_hook import hooked, route, process, stage_values
from test_committed_evidence_capture import committed, rows
from test_recording_tip_witness import witnessed
from test_observed_recording_journal import setup
from test_protected_recording_review import verified, keys
from test_protected_bitemporal_runner import output, run, recover, values, inventory
from test_recording_checkpoint_registry import approval
from test_witness_secure_transport import secured, listener, wire_client


def query(h,path,known,**changes):
    t=h['d']['t'];before=inventory(t)
    summary=run(t,path,known_at=known,**changes);result=recover(t,path)
    assert inventory(t)==before
    assert result['accepted_state'] is None and result['authenticated_journal_replay']
    assert result['coverage_semantics']=='JOURNAL_OBSERVATIONS_ONLY'
    assert not result['source_change_completeness_established']
    assert path.stat().st_mode&0o777==0o600
    assert all(value not in path.read_text() and value not in json.dumps(summary)
        for value in ('fixture-100','fixture-200','fixture-300'))
    return result


def check_correction(h,output,monkeypatch,secured):
    t=h['d']['t'];start=t['adapter'].select()['state']['history'].coverage_end
    original=query(h,output,start);saved=inventory(t)
    receipt=route(h);assert process(h,receipt)['status']=='CAPTURED';observed=t['s']['clock'][0]
    assert all(p.read_bytes()==data for p,data in saved.items())
    earlier=query(h,output.parent/'earlier.json',start)
    later=query(h,output.parent/'later.json',observed)
    assert values(earlier)==['fixture-100'] and values(later)==['fixture-200']
    assert earlier['query']['query_digest']==original['query']['query_digest']
    before_effect=query(h,output.parent/'effective-before.json',observed,effective_on=date(2023,12,31))
    assert values(before_effect)==[]
    assert process(h,receipt)['status']=='ALREADY_CAPTURED' and len(rows(h['d']))==1
    assert len(t['adapter'].select()['state']['history'].versions)==2


def next_staging_file(h):
    d=h['d'];t=d['t'];batch,file,values_=stage_values(d);batch['batch_id']='HOOK-CORRECTION-FIXTURE'
    batch.update(archive_sha256='0'*64,registration_receipt_sha256='1'*64,registration_receipt_id=UUID(int=91))
    file['source_file_sha256']='f'*64;values_=list(values_);values_[file['columns'].index('police_no')]='fixture-300'
    B,F,Raw=h['tables'];engine=d.get('admin',h['stage_engine'])
    if engine.dialect.name=='postgresql':
        stage_file(engine,t['s']['snapshot']['crypto'],batch_values=batch,file_values=file,rows=[values_])
        with engine.connect() as c:
            registered=c.execute(select(F).where(F.c.batch_id==batch['batch_id'])).mappings().one()
            raw=c.execute(select(Raw.c.raw_record_id).where(Raw.c.batch_id==batch['batch_id'])).scalar_one()
        file_id=registered['import_file_id']
    else:
        file_id=UUID(int=90);now=t['s']['clock'][0]
        sealed=seal_row(t['s']['snapshot']['crypto'],batch_id=batch['batch_id'],archive_path=file['archive_path'],
            source_file_sha256=file['source_file_sha256'],source_row_number=1,columns=file['columns'],values=values_)
        raw=sealed.raw_record_id
        with engine.begin() as c:
            c.execute(B.insert().values(**batch,registered_at=now))
            c.execute(F.insert().values(**file,import_file_id=file_id,batch_id=batch['batch_id'],registered_at=now))
            c.execute(Raw.insert().values(**asdict(sealed),import_file_id=file_id,staged_at=now))
    return dict(h,scope=replace(h['scope'],batch_id=batch['batch_id'],file_sha256=file['source_file_sha256'],
        import_file_id=str(file_id),archive_sha256=batch['archive_sha256'],
        receipt_sha256=batch['registration_receipt_sha256']),raw=raw,claim_id=raw+':'+h['claim_id'].split(':',1)[1])


def check_intake_then_correction(h,output,monkeypatch,secured):
    d=h['d'];t=d['t'];start=t['adapter'].select()['state']['history'].coverage_end
    process(h,route(h,supersedes=None));intake_time=t['s']['clock'][0]
    prior=next(v for v in t['adapter'].select()['state']['history'].versions if v.claim.claim_id==h['claim_id'])
    t['s']['clock'][0]+=timedelta(seconds=1);new=next_staging_file(h)
    assert process(new,route(new,supersedes=prior.version_id))['status']=='CAPTURED'
    assert values(query(h,output,start))==['fixture-100']
    assert sorted(values(query(h,output.parent/'intake.json',intake_time)))==['fixture-100','fixture-200']
    assert sorted(values(query(h,output.parent/'corrected.json',t['s']['clock'][0])))==['fixture-100','fixture-300']
    assert len(rows(d))==2 and len(t['adapter'].select()['state']['history'].versions)==3


def check_pending_outbox(h,output,monkeypatch,secured):
    t=h['d']['t'];start=t['adapter'].select()['state']['history'].coverage_end;receipt=route(h)
    original=C.capture_loaded_version
    monkeypatch.setattr(C,'capture_loaded_version',lambda *a,**k:(_ for _ in ()).throw(OSError('before capture')))
    with pytest.raises(OSError):process(h,receipt)
    monkeypatch.setattr(C,'capture_loaded_version',original)
    assert len(rows(h['d']))==1 and values(query(h,output,start))==['fixture-100']
    with pytest.raises(ValueError,match='outside'):run(t,output.parent/'pending.json')
    assert not (output.parent/'pending.json').exists()
    assert process(h,receipt)['status']=='CAPTURED'
    assert values(query(h,output.parent/'captured.json',t['s']['clock'][0]))==['fixture-200']


def interrupt(h,monkeypatch,phase):
    t=h['d']['t'];receipt=route(h);original=J._publish if phase=='checkpoint' else t['client'].exchange
    if phase=='checkpoint':
        def fail(path,*args):
            if path.name.startswith('checkpoint-'):raise OSError('checkpoint interruption')
            return original(path,*args)
        monkeypatch.setattr(J,'_publish',fail)
    else:
        def fail(request):
            if request['payload']['operation']=='CAS':
                if phase=='witness-after':original(request)
                raise OSError('witness interruption')
            return original(request)
        t['client'].exchange=fail
    with pytest.raises(OSError):process(h,receipt)
    if phase=='checkpoint':monkeypatch.setattr(J,'_publish',original)
    else:t['client'].exchange=original
    return receipt


def check_interruption(h,output,monkeypatch,secured,phase):
    t=h['d']['t'];start=t['adapter'].select()['state']['history'].coverage_end
    receipt=interrupt(h,monkeypatch,phase);observed=t['s']['clock'][0];saved=inventory(t)
    assert len(rows(h['d']))==1 and len(list(t['s']['root'].glob('event-*.encrypted.json')))==1
    if phase=='witness-after':assert process(h,receipt)['status']=='ALREADY_CAPTURED'
    else:
        with pytest.raises(ValueError):run(t,output)
        assert not output.exists()
        t['s']['clock'][0]+=timedelta(seconds=1200)
        token=approval(t['s'],t['r'],t['client'].head(),t['recovery'])
        if phase=='checkpoint':
            result=t['adapter'].recover(token,recorder_signer=t['s']['signer'],recorder_key_id='recorder')
            assert result['observation_times_preserved']
        else:
            checkpoints=[p.name for p in t['s']['root'].glob('checkpoint-*.encrypted.json')
                if p.name!=t['pin']['checkpoint_file']]
            assert len(checkpoints)==1
            checkpoint=checkpoints[0]
            token=approval(t['s'],t['r'],t['client'].head(),t['recovery'],checkpoint)
            t['adapter'].reconcile(token)
        assert process(h,route(h))['status']=='ALREADY_CAPTURED'
        with pytest.raises(ValueError,match='outside'):run(t,output.parent/'too-late.json')
        assert not (output.parent/'too-late.json').exists()
    assert all(p.read_bytes()==data for p,data in saved.items())
    assert values(query(h,output,start))==['fixture-100']
    assert values(query(h,output.parent/'recovered.json',observed))==['fixture-200']
    assert t['adapter'].select()['state']['history'].versions[-1].recorded_at==observed
    assert len(rows(h['d']))==1 and len(list(t['s']['root'].glob('event-*.encrypted.json')))==1


def check_bad_recovery(h,output,monkeypatch,secured):
    t=h['d']['t'];interrupt(h,monkeypatch,'checkpoint');saved=inventory(t)
    token=approval(t['s'],t['r'],t['client'].head(),t['recovery']);token['signature']='AAAA'
    with pytest.raises(ValueError):t['adapter'].recover(token,recorder_signer=t['s']['signer'],recorder_key_id='recorder')
    assert inventory(t)==saved
    with pytest.raises(ValueError):run(t,output)
    assert not output.exists()
    token=approval(t['s'],t['r'],t['client'].head(),t['recovery'])
    t['adapter'].recover(token,recorder_signer=t['s']['signer'],recorder_key_id='recorder')
    assert values(query(h,output,t['s']['clock'][0]))==['fixture-200']


def check_rollback(h,output,monkeypatch,secured):
    t=h['d']['t'];process(h,route(h));tip=t['client'].head()
    entry=t['r'].root/'entry-00000002.encrypted.json';saved=entry.read_bytes();entry.unlink()
    with pytest.raises(ValueError):run(t,output)
    assert not output.exists() and t['client'].head()==tip
    entry.write_bytes(saved);entry.chmod(0o600)
    assert values(query(h,output,t['s']['clock'][0]))==['fixture-200']


def check_restart(h,output,monkeypatch,secured):
    t=h['d']['t'];process(h,route(h));tip=t['client'].head();h['d']['engine'].dispose()
    server=W.DurableTipWitness(**t['args'],expected_enrollment=t['enrollment'])
    client=W.WitnessClient(**t['client_args'],exchange=server.exchange)
    t['adapter']=W.WitnessedCheckpointRegistry(R.CheckpointRegistry(**t['registry_args']),client)
    assert client.head()==tip and process(h,route(h))['status']=='ALREADY_CAPTURED'
    assert values(query(h,output,t['s']['clock'][0]))==['fixture-200'] and len(rows(h['d']))==1


def check_public_mtls(h,output,monkeypatch,secured):
    from app.identity import algorithm_snapshot as S, protected_bitemporal_runner as P
    d=h['d'];t=d['t'];calls=[]
    assert secured['t'] is t
    def loader(*args):calls.append(args);return t['s']['snapshot']
    # Only the full live-readiness/replay boundary is a synthetic fixture.
    monkeypatch.setattr(S,'load_verified_snapshot',loader)
    with listener(secured):
        t['adapter']=W.WitnessedCheckpointRegistry(t['r'],wire_client(secured))
        if d['engine'].dialect.name=='postgresql':
            params=dict(raw_record_id=h['raw'],source_claim_id=h['claim_id'],supersedes=d['submission']['supersedes'],
                authority_signer=t['s']['authority'],authority_key_id='authority')
            receipt=H.issue_registered_route('fixture',t['s']['repo'],'revision',h['stage_engine'],d['engine'],t['adapter'],h['scope'],**params)
            result=H.process_registered_route('fixture',t['s']['repo'],'revision',h['stage_engine'],d['engine'],t['adapter'],receipt,
                authority_signer=t['s']['authority'],authority_key_id='authority',recorder_signer=t['s']['signer'],recorder_key_id='recorder')
        else:result=process(h,route(h))
        assert result['status']=='CAPTURED'
        P.run_bitemporal_query('fixture',t['s']['repo'],'revision',t['adapter'],officer_uid=t['adapter'].select()['state']['history'].officer_uid,
            effective_on=date(2024,12,31),known_at=t['s']['clock'][0],destination=output)
        assert values(recover(t,output))==['fixture-200']
    assert len(calls)==(3 if d['engine'].dialect.name=='postgresql' else 1)


CHECKS=[check_correction,check_intake_then_correction,check_pending_outbox,
    *[('interruption',phase) for phase in ('checkpoint','witness-before','witness-after')],
    check_bad_recovery,check_rollback,check_restart,check_public_mtls]
IDS=['historical-effective-dates','intake-correction-lineage','pending-outbox',
    'checkpoint-recovery','witness-reconcile','lost-witness-response','bad-recovery','rollback','restart','mutual-tls']


def execute(check,h,output,monkeypatch,secured):
    if isinstance(check,tuple):check_interruption(h,output,monkeypatch,secured,check[1])
    else:check(h,output,monkeypatch,secured)


@pytest.mark.parametrize('check',CHECKS,ids=IDS)
def test_recording_pipeline_fixture(hooked,output,monkeypatch,secured,check):
    execute(check,hooked,output,monkeypatch,secured)


@pytest.mark.parametrize('skip',[False,True])
def test_pipeline_launcher_checks_ten_executed_tests(monkeypatch,skip):
    import subprocess
    from pathlib import Path
    from scripts import run_isolated_recording_postgres as L
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
        assert args[3]=='tests/test_recording_pipeline_e2e_postgres.py'
        xml=Path(next(a.split('=',1)[1] for a in args if a.startswith('--junitxml=')))
        xml.write_text('<testsuites><testsuite tests="10" failures="0" errors="0" skipped="'+str(int(skip))+'"/></testsuites>')
        return subprocess.CompletedProcess(args,0)
    monkeypatch.setattr(L.subprocess,'run',test_run)
    if skip:
        with pytest.raises(ValueError,match='every expected'):L.run_suite('pipeline-e2e')
    else:assert L.run_suite('pipeline-e2e')==0
    assert cleaned==[(c['container_name'],c['run_id'])]


def test_pipeline_cli_preserves_suite_allowlist(monkeypatch):
    import sys
    from scripts import run_isolated_recording_postgres as L
    seen=[];monkeypatch.setattr(L,'run_suite',lambda suite='recording':seen.append(suite) or 0)
    monkeypatch.setattr(sys,'argv',['launcher','--suite','pipeline-e2e'])
    assert L.main()==0 and seen==['pipeline-e2e']
    monkeypatch.setattr(sys,'argv',['launcher','--suite','external'])
    with pytest.raises(ValueError):L.main()
