"""Exact coverage and read-only review orchestration; no real database IO."""
from copy import deepcopy
import importlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4
import pytest
from app.identity import review_stage2 as runner
from app.identity import inspect_stage2_coverage as coverage
from app.identity.source_coverage import receipt_coverage
from app.identity.inspect_service_plans import BATCH,CONFIRMATION


def args(tmp_path):
    return SimpleNamespace(key_file=tmp_path/'primary.json',backup_key_file=tmp_path/'backup.json',credential_root=tmp_path/'credentials',attempt_root=tmp_path/'attempts')


def test_all_nineteen_files_and_exact_total():
    assert len(coverage.ROWS)==19 and sum(coverage.ROWS.values())==167865
    assert sum(coverage.PERSONNEL_ROWS.values())==166651
    assert coverage.ROWS['station_master.csv']==coverage.ROWS['sri_lanka_police_stations_sinhala.csv']==607
    assert len(runner.PIPELINES)==8 and len(runner.MONGO_COUNTS)==17


@pytest.mark.parametrize('filename',['station_master.csv','sri_lanka_police_stations_sinhala.csv'])
def test_reference_receipts_require_correct_store_and_source(filename):
    fid=uuid4();rid='a'*64
    raw=dict(filename=filename,source_file_sha256='b'*64,source_row_number=1,import_file_id=fid)
    receipt=dict(raw_record_id=rid,complete=True,group='REFERENCE')
    assertion=dict(raw_record_id=rid,source_file_name=filename,source_code='POLICE_HR_IS',source_file_sha256='b'*64,source_row_number=1,
        intake_batch_id=BATCH,import_file_id=str(fid),assertion_type=coverage.ASSERTIONS[filename])
    coverage.validate_receipt_provenance(receipt,assertion,raw)
    for key in assertion:
        changed=dict(assertion,**{key:'ALTERED'})
        with pytest.raises(ValueError):coverage.validate_receipt_provenance(receipt,changed,raw)
    with pytest.raises(ValueError):coverage.validate_receipt_provenance(dict(receipt,group='REMAINING'),assertion,raw)


@pytest.mark.parametrize('mode',['complete','pending','bad_digest','orphan','bad_confirmation'])
def test_reference_receipt_loader_reads_metadata_only(mode):
    event,assertion=uuid4(),uuid4()
    prep=dict(delivery_id=event,raw_record_id='r',source_assertion_id=assertion,confirmation_sha256='0'*64 if mode=='bad_confirmation' else CONFIRMATION,document_sha256='a'*64)
    done=dict(delivery_id=uuid4() if mode=='orphan' else event,document_sha256='b'*64 if mode=='bad_digest' else 'a'*64)
    class Result:
        def __init__(self,rows):self.rows=rows
        def mappings(self):return iter(self.rows)
    class ReadConnection:
        def execute(self,statement):
            assert statement.is_select
            assert not {'document_bson','evidence_ciphertext','asserted_value_ciphertext'}&{c.name for c in statement.selected_columns}
            name=statement.get_final_froms()[0].name
            return Result([prep] if name=='reference_delivery_preparation' else [done] if name=='reference_delivery_completion' and mode!='pending' else [])
    if mode in {'bad_digest','orphan','bad_confirmation'}:
        with pytest.raises(ValueError):coverage.load_receipts(ReadConnection())
    else:
        receipts,ids=coverage.load_receipts(ReadConnection())
        assert receipts==[dict(raw_record_id='r',assertion_id=assertion,complete=mode=='complete',group='REFERENCE')]
        assert ids=={assertion}


def test_equal_counts_cannot_hide_replaced_staged_row():
    report=receipt_coverage({'a','b'},[dict(raw_record_id='a',complete=True),dict(raw_record_id='c',complete=True)])
    assert report['missing_rows']==report['unexpected_rows']==1 and report['complete_rows']==1


def test_commands_are_fixed_read_only_arrays_and_parse_in_real_clis(tmp_path):
    commands=runner.commands(args(tmp_path),tmp_path/'repository',tmp_path/'journal')
    assert len(commands)==9 and commands[0][0]=='COVERAGE'
    for name,command in commands:
        assert isinstance(command,list) and '--write' not in command
        if name=='COVERAGE':continue
        assert '--reconcile' in command
        assert '--expected-archive-sha256' in command
        module=importlib.import_module(command[3])
        parse=getattr(module,'arguments',None) or module._args
        with patch('sys.argv',['program',*command[4:]]):parsed=parse()
        assert parsed.reconcile is True and parsed.write is False
    service=next(c for name,c in commands if name=='SERVICE')
    assert '--mongo-credential-directory' in service and str(tmp_path/'credentials/mongo-v1') in service


@pytest.mark.parametrize('flag',['--write','--reconcile','--skip-reconciliation'])
def test_runner_has_no_write_or_skip_option(tmp_path,flag):
    values=['program','--key-file','/primary','--backup-key-file','/backup','--credential-root','/credentials','--attempt-root','/attempts',flag]
    with patch('sys.argv',values),pytest.raises(SystemExit):runner.arguments()


@pytest.mark.parametrize('failure',[None,'COVERAGE','PROFILE','SERVICE','REFERENCE','COUNTS'])
def test_orchestrator_requires_every_check_before_success(tmp_path,monkeypatch,failure):
    configuration=args(tmp_path);monkeypatch.setattr(runner,'arguments',lambda:configuration)
    monkeypatch.setattr(runner.subprocess,'check_output',lambda command,**kwargs:'' if command[-1]=='--porcelain' else 'd'*40)
    names=[name for name,_ in runner.commands(configuration,tmp_path,tmp_path/'journal')]
    calls=[]
    def run(command,**kwargs):
        name=names[len(calls)];calls.append(name)
        assert kwargs['check'] is False and '--write' not in command
        return SimpleNamespace(returncode=1 if failure==name else 0)
    monkeypatch.setattr(runner.subprocess,'run',run)
    counted=[]
    def counts(root):
        counted.append(root)
        if failure=='COUNTS':raise ValueError('Injected count failure.')
        return dict(sql_tables=len(runner.SQL_COUNTS),mongo_collections=17)
    monkeypatch.setattr(runner,'check_counts',counts)
    assert runner.main()==(0 if failure is None else 1)
    if failure in names:assert calls==names[:names.index(failure)+1] and not counted
    else:assert calls==names and counted
    receipts=list(configuration.attempt_root.glob('*/*.json'))
    passed=[p for p in receipts if '"event": "PASSED"' in p.read_text()]
    assert bool(passed) is (failure is None)
    if failure:assert any(p.name=='STOPPED.json' for p in receipts)
    for receipt in receipts:
        assert 'asserted_value_ciphertext' not in receipt.read_text()
        assert 'payload_ciphertext' not in receipt.read_text()


def test_dirty_source_blocks_connections_and_child_checks(tmp_path,monkeypatch):
    monkeypatch.setattr(runner,'arguments',lambda:args(tmp_path))
    monkeypatch.setattr(runner.subprocess,'check_output',lambda *a,**k:' M source.py')
    def forbidden(*a,**k):raise AssertionError('Review must stop before running a child or count gate.')
    monkeypatch.setattr(runner.subprocess,'run',forbidden);monkeypatch.setattr(runner,'check_counts',forbidden)
    assert runner.main()==1
    assert not (tmp_path/'attempts').exists()
