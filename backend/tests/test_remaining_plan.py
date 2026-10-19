"""Planning invariants, real crypto recovery and an inert read-only six-file runner."""
from dataclasses import replace
from datetime import date
from decimal import Decimal
from pathlib import Path
from uuid import uuid4
import json, base64, os
import pytest
from app.identity import inspect_remaining_plans as inspection
from app.identity.remaining_plan import plan_remaining, validate_remaining_routing, ROUTES
from app.identity.remaining_plan_crypto import seal_remaining_plan, open_remaining_plan, context
from app.security.identity_crypto import IdentityCrypto


def row_for(filename):
    row = dict.fromkeys(inspection.HEADERS[filename], '')
    key = inspection.SOURCE_KEYS[filename]
    if key: row[key] = 'PRIVATE_KEY'
    if 'officer_nic_no' in row: row['officer_nic_no'] = 'PRIVATE_NIC'
    return row


def planned(filename, row=None, **kw):
    return plan_remaining(filename, row or row_for(filename), officer_uid=kw.pop('officer_uid', uuid4() if 'officer_nic_no' in inspection.HEADERS[filename] else None), **kw)


def item(plan, name):
    return next(f for f in plan.fields if f.source_column == name)


@pytest.mark.parametrize('filename', list(inspection.HEADERS))
def test_all_fields_preserved_once_in_source_order_and_not_exposed_by_repr(filename):
    row = row_for(filename)
    plan = planned(filename, row)
    assert tuple(f.source_column for f in plan.fields) == inspection.HEADERS[filename]
    assert [f.source_value for f in plan.fields] == [row[n] for n in inspection.HEADERS[filename]]
    assert 'PRIVATE' not in repr(plan)
    assert all((f.destination, f.target_field) == ROUTES[filename][f.source_column] for f in plan.fields)


@pytest.mark.parametrize('value,valid', [('2026-10-07', True), ('2026-02-30',False), ('07/10/2026',False), ('2026-1-7',False)])
def test_reported_dates_never_become_effective_intervals(value, valid):
    row=row_for('_demotions_enacted.csv');row['punishment_date']=value
    f=item(planned('_demotions_enacted.csv',row),'punishment_date')
    assert (f.status == 'PARSED') == valid
    if valid: assert f.value == date(2026,10,7)
    assert f.source_value == value


@pytest.mark.parametrize('value,valid', [('0',True),('12',True),('-1',False),('1.5',False),('NaN',False),('Infinity',False)])
def test_court_appearances_are_nonnegative_integer_counts(value,valid):
    row=row_for('court_details.csv');row['appearances_to_date']=value
    f=item(planned('court_details.csv',row),'appearances_to_date')
    assert (f.status == 'PARSED') == valid
    if valid: assert type(f.value) is int


@pytest.mark.parametrize('value,valid',[('3.75',True),('-1',False),('NaN',False),('Infinity',False)])
def test_decimal_numeric_claims_preserve_precision_and_reject_nonfinite(value,valid):
    row=row_for('officer_education.csv');row['uni_gpa']=value
    f=item(planned('officer_education.csv',row),'uni_gpa')
    assert (f.status=='PARSED') == valid
    if valid: assert f.value == Decimal(value)


@pytest.mark.parametrize('value,valid',[('23:30',True),('00:01:02',True),('24:00',False),('9:00',False),('11 PM',False)])
def test_time_parsing_does_not_infer_day_or_timezone(value,valid):
    row=row_for('operations.csv');row['operation_start_time']=value
    assert (item(planned('operations.csv',row),'operation_start_time').status=='PARSED')==valid


def test_unresolved_alternate_subject_is_preserved_and_flagged():
    row=row_for('public_complaints.csv');row['officer_nic_as_recorded']='PRIVATE_ALTERNATE'
    plan=planned('public_complaints.csv',row)
    assert item(plan,'officer_nic_as_recorded').status=='REVIEW_REQUIRED'
    assert item(plan,'unit_senior_questioned_nic').status=='MISSING'
    assert item(plan,'officer_nic_as_recorded').source_value=='PRIVATE_ALTERNATE'
    plan=planned('public_complaints.csv',row,identity_candidates={'officer_nic_as_recorded':uuid4()})
    assert 'ALTERNATE_SUBJECT_CANDIDATE_DIFFERS' in plan.review_issues


def test_family_alias_mapping_is_source_scoped():
    row=row_for('officer_family_details.csv');row['recorded_by_officer_rank']='ASP'
    assert item(planned('officer_family_details.csv',row),'recorded_by_officer_rank').value=='ASP'
    row=row_for('operations.csv');row['commanding_officer_rank']='ASP'
    assert item(planned('operations.csv',row),'commanding_officer_rank').status=='REVIEW_REQUIRED'


def test_pair_mismatch_and_nested_structure_remain_unaccepted():
    row=row_for('officer_education.csv');row.update(ol_subject='PRIVATE;PRIVATE',ol_grades='A')
    assert 'ol_subject:REPORTED_LIST_LENGTH_MISMATCH' in planned('officer_education.csv',row).review_issues
    row=row_for('court_details.csv');row['participate_officers_details']='[{"name":"PRIVATE"}]'
    f=item(planned('court_details.csv',row),'participate_officers_details')
    assert f.value['reported_shape']=='JSON_STRUCTURE_UNASSESSED'
    assert f.source_value==row['participate_officers_details']


def test_no_fabricated_event_subject_or_incomplete_source_allowed():
    with pytest.raises(ValueError): plan_remaining('operations.csv',row_for('operations.csv'),officer_uid=uuid4())
    row=row_for('court_details.csv');row.pop('court_no')
    with pytest.raises(ValueError): plan_remaining('court_details.csv',row)
    row=row_for('court_details.csv');row['court_no']=123
    with pytest.raises(ValueError): plan_remaining('court_details.csv',row)


def test_routing_document_coverage_and_mutation_guards():
    path=Path(__file__).resolve().parents[2]/'docs/field-routing.json'
    document=json.loads(path.read_text())
    validate_remaining_routing(document)
    file=next(f for f in document['files'] if f['filename']=='operations.csv')
    file['fields'][0]['target_field']='WRONG'
    with pytest.raises(ValueError): validate_remaining_routing(document)


@pytest.fixture
def keys(tmp_path):
    key=base64.b64encode(os.urandom(32)).decode()
    paths=[]
    for name in ('primary','backup'):
        path=tmp_path/(name+'.json')
        path.write_text(json.dumps(dict(active_encryption_key_version='TEST',active_lookup_key_version='TEST',
            encryption_keys={'TEST':key},lookup_keys={'TEST':key})))
        path.chmod(0o600);paths.append(path)
    return IdentityCrypto(paths[0]),IdentityCrypto(paths[1])


@pytest.mark.parametrize('filename', list(inspection.HEADERS))
def test_dual_key_recovery_preserves_originals_and_blocks_unapproved_determinations(filename,keys):
    primary,backup=keys;plan=planned(filename);raw='a'*64
    cipher,version=seal_remaining_plan(primary,plan,raw_record_id=raw,reference_evidence={'source':'test'})
    opening=dict(key_version=version,filename=filename,raw_record_id=raw)
    payload=open_remaining_plan(primary,cipher,**opening)
    assert payload==open_remaining_plan(backup,cipher,**opening)
    assert [f['source_value'] for f in payload['fields']]==[f.source_value for f in plan.fields]
    assert payload['record_classification']=='UNASSESSED' and payload['effects_applied'] is False
    assert all(payload[k] is None for k in ('valid_from','valid_to','reconstructed_state','authority_result'))
    with pytest.raises(Exception): open_remaining_plan(primary,cipher,**dict(opening,raw_record_id='b'*64))
    payload['effects_applied']=True
    altered,v=primary.encrypt_assertion(payload,context=context(filename,raw))
    with pytest.raises(ValueError): open_remaining_plan(primary,altered,**dict(opening,key_version=v))
    with pytest.raises(ValueError): seal_remaining_plan(primary,replace(plan,fields=plan.fields[:-1]),raw_record_id=raw,reference_evidence={})


def test_six_source_runner_reads_only_and_suppresses_private_text(tmp_path, monkeypatch, capsys):
    """Exercise actual sealed-row recovery; mocked SQL accepts SELECT/read-only commands only."""
    import base64
    from contextlib import nullcontext
    from dataclasses import asdict
    from types import SimpleNamespace
    from uuid import uuid4
    from sqlalchemy.sql.selectable import Select
    from app.intake.staging_rows import seal_row
    from app.security.identity_crypto import IdentityCrypto
    from app.staging.models import IntakeBatch, IntakeFile, RawRecord
    key = base64.b64encode(b'k'*32).decode()
    keys = []
    for name in ('primary.json','backup.json'):
        path = tmp_path/name
        path.write_text(json.dumps(dict(active_encryption_key_version='TEST', active_lookup_key_version='TEST',
            encryption_keys={'TEST':key}, lookup_keys={'TEST':key})))
        path.chmod(0o600)
        keys.append(path)
    crypto = IdentityCrypto(keys[0])
    files, rows = [], {}
    private = 'PRIVATE-OFFICER-CELL-NEVER-PRINT'
    for filename, header in inspection.HEADERS.items():
        row = dict.fromkeys(header, private)
        for name in inspection.STRUCTURED_FIELDS[filename]:
            row[name] = json.dumps([{'name':private}])
        file_id = uuid4()
        files.append(dict(batch_id=inspection.BATCH, archive_path=filename, source_file_sha256='b'*64,
            import_file_id=file_id, columns=list(header), expected_row_count=1))
        rows[file_id] = [dict(asdict(seal_row(crypto, batch_id=inspection.BATCH, archive_path=filename,
            source_file_sha256='b'*64, source_row_number=1, columns=list(header), values=list(row.values()))), import_file_id=file_id)]
    class Result:
        def __init__(self,value): self.value=value
        def mappings(self): return self
        def one(self): return self.value
        def all(self): return self.value
        def __iter__(self): return iter(self.value)
    class Connection:
        def begin(self): return nullcontext()
        def execute(self,statement):
            if not isinstance(statement, Select):
                assert str(statement) in {'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY',
                    'SELECT current_user, current_database()'}
                return Result(('police_identity_app','police_identity'))
            table=statement.get_final_froms()[0].fullname
            if table==IntakeBatch.__table__.fullname:
                return Result(dict(archive_sha256=inspection.ARCHIVE,expected_file_count=6))
            if table==IntakeFile.__table__.fullname: return Result(files)
            assert table==RawRecord.__table__.fullname
            return Result(rows[statement.compile().params['import_file_id_1']])
    class Engine:
        disposed=False
        def connect(self): return nullcontext(Connection())
        def dispose(self): self.disposed=True
    engine=Engine()
    monkeypatch.setattr('sys.argv',['inspect','--key-file',str(keys[0]),'--backup-key-file',str(keys[1])])
    monkeypatch.setattr(inspection,'private_key_file',IdentityCrypto)
    monkeypatch.setattr(inspection,'Settings',lambda:SimpleNamespace(host='127.0.0.1',port=5432,name='police_identity',user='police_identity_app'))
    monkeypatch.setattr(inspection,'create_identity_engine',lambda settings:engine)
    monkeypatch.setattr(inspection,'load_source_confirmation',lambda *args,**kw:SimpleNamespace(
        confirmation_sha256=inspection.CONFIRMATION,source_for=lambda name:inspection.SOURCES[name]))
    monkeypatch.setattr(inspection,'inspected_link',lambda *args:('EXACT_EVIDENCE_CANDIDATE',uuid4()))
    monkeypatch.setattr(inspection, 'EXPECTED_ROWS', dict.fromkeys(inspection.HEADERS, 1))
    # The runner validates routes separately; freeze the contract in pure tests below.
    monkeypatch.setattr(inspection, 'validate_remaining_routing', lambda document: None)
    assert inspection.main()==0 and engine.disposed
    output=capsys.readouterr().out
    assert private not in output
    reports=[json.loads(line) for line in output.splitlines() if line.startswith('{')]
    assert len(reports)==6 and all(r['rows_planned']==1 for r in reports)
    by_name={r['filename']:r for r in reports}
    assert all("targeted_observations" in r and "reference_key_observations" in r for r in reports)
    assert 'No database writes, Mongo connection' in output




def test_false_flag_is_parsed_and_unknown_flag_is_preserved_for_review():
    row=row_for('operations.csv');row['is_major']='FALSE'
    assert item(planned('operations.csv',row),'is_major').value is False
    row['is_major']='unknown'
    f=item(planned('operations.csv',row),'is_major')
    assert f.status=='REVIEW_REQUIRED' and f.source_value=='unknown'


def test_positive_child_count_with_absent_list_requires_review():
    row=row_for('officer_family_details.csv');row['children_no']='2'
    assert 'REPORTED_CHILD_COUNT_WITH_MISSING_LIST' in planned('officer_family_details.csv',row).review_issues
