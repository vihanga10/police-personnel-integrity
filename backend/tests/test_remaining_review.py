"""Conservative aggregate observations and a six-source read-only orchestration test."""
import json
from pathlib import Path
import pytest
from app.identity import inspect_remaining_review as inspection


@pytest.mark.parametrize('text,shape', [
    ('', 'MISSING'), ('  ', 'MISSING'), ('[]', 'JSON_LIST'),
    ('[{"nic":"PRIVATE"}]', 'JSON_LIST'), ('{"name":"PRIVATE"}', 'JSON_OBJECT'),
    ('"PRIVATE"', 'JSON_SCALAR'), ('12', 'JSON_SCALAR'), ('null', 'JSON_SCALAR'),
    ('[broken', 'JSON_LIKE_INVALID'), ('{broken', 'JSON_LIKE_INVALID'),
    ('PRIVATE;PRIVATE', 'DELIMITED_TEXT'), ('PRIVATE|PRIVATE', 'DELIMITED_TEXT'),
    ('PRIVATE,PRIVATE', 'DELIMITED_TEXT'), ('PRIVATE\nPRIVATE', 'DELIMITED_TEXT'),
    ('PRIVATE', 'OTHER_TEXT'), ('x'*1048577, 'OVERSIZED_TEXT_NOT_PARSED'),
])
def test_nested_text_shapes_never_echo_values_or_accept_linkage(text, shape):
    assert inspection.structured_shape(text) == shape


@pytest.mark.parametrize('filename,count', [
    ('officer_education.csv', 19), ('officer_family_details.csv', 23),
    ('operations.csv', 32), ('court_details.csv', 16),
    ('public_complaints.csv', 54), ('_demotions_enacted.csv', 4),
])
def test_frozen_headers_and_safe_field_sets(filename, count):
    header = inspection.HEADERS[filename]
    assert len(header) == len(set(header)) == count
    for mapping in (inspection.DATES, inspection.ACTOR_FIELDS, inspection.RANK_FIELDS,
        inspection.BOOLEAN_FIELDS, inspection.NUMERIC_FIELDS, inspection.REFERENCE_FIELDS,
        inspection.STRUCTURED_FIELDS):
        assert set(mapping[filename]) <= set(header)
    key = inspection.SOURCE_KEYS[filename]
    assert key is None or key in header
    assert key != 'officer_nic_no'
    inventory = json.loads((Path(__file__).resolve().parents[2]/'docs/input-header-inventory.json').read_text())
    assert header == tuple(next(f['columns'] for f in inventory['files'] if f['filename'] == filename))


def test_reported_sources_do_not_invent_direct_npc_receipt():
    assert inspection.SOURCES['public_complaints.csv'] == 'PF_REGISTRY'
    assert inspection.SOURCES['officer_family_details.csv'] == 'POLICE_HR_IS'
    assert inspection.SOURCES['officer_education.csv'] == 'POLICE_HR_IS'
    assert 'NPC' not in inspection.SOURCES.values()


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
    assert inspection.main()==0 and engine.disposed
    output=capsys.readouterr().out
    assert private not in output
    reports=[json.loads(line) for line in output.splitlines() if line.startswith('{')]
    assert len(reports)==6 and all(r['rows']==1 for r in reports)
    by_name={r['filename']:r for r in reports}
    assert all("targeted_observations" in r and "reference_key_observations" in r for r in reports)
    assert 'No database writes, Mongo connection' in output


@pytest.mark.parametrize("value,shape,size", [
    ("", "MISSING", None), ("a;b", "DELIMITED_LIST", 2),
    ("a|b", "DELIMITED_LIST", 2), ("a,b", "DELIMITED_LIST", 2),
    ("a;b,c", "MIXED_DELIMITERS", None), ("a;;b", "EMPTY_LIST_MEMBER", None),
    ('["a",2]', "JSON_FLAT_LIST", 2), ('[{"nic":"PRIVATE"}]', "JSON_STRUCTURE_UNASSESSED", None),
    ('[true]', "JSON_STRUCTURE_UNASSESSED", None), ('[broken', "INVALID_JSON_LIKE", None),
    ("a", "SINGLE_TEXT", 1), ("x"*1048577, "OVERSIZED", None),
])
def test_lists_preserve_uncertain_structure(value, shape, size):
    actual, items = inspection.split_reported_items(value)
    assert actual == shape
    assert (None if items is None else len(items)) == size


def test_reference_matches_do_not_infer_missing_keys_or_event_truth():
    keys = {name: set() for name in inspection.HEADERS}
    keys['operations.csv'].add('PRIVATE')
    result = inspection.resolve_reference_counts([
        ('court_details.csv', 'operation_no', 'operations.csv', 'PRIVATE'),
        ('court_details.csv', 'operation_no', 'operations.csv', 'UNKNOWN'),
        ('court_details.csv', 'operation_no', 'operations.csv', ''),
    ], keys)
    assert dict(result['court_details.csv']) == {
        'operation_no:REPORTED_KEY_MATCH': 1, 'operation_no:NO_REPORTED_KEY_MATCH': 1,
        'operation_no:MISSING': 1,
    }
    assert 'PRIVATE' not in json.dumps(result)


def test_alternate_subject_and_optional_missing_actor_are_distinct(monkeypatch):
    row = {name: '' for name in inspection.HEADERS['public_complaints.csv']}
    row.update(officer_nic_no='PRIVATE_CANONICAL', officer_nic_as_recorded='PRIVATE_ALTERNATE')
    monkeypatch.setattr(inspection, 'inspected_link', lambda *args:
        ('EXACT_EVIDENCE_CANDIDATE', 'candidate') if args[3] == 'PRIVATE_CANONICAL' else ('NO_CANDIDATE_FOUND', None))
    counts = inspection.review_row('public_complaints.csv', row, None, None, None, {})
    assert counts['alternate_subject:NO_CANDIDATE_FOUND'] == 1
    assert counts['subject_candidate_comparison:UNASSESSED'] == 1
    assert counts['optional_senior_nic:MISSING'] == 1
    assert 'PRIVATE' not in json.dumps(counts)


def test_unknown_rank_text_is_never_displayed():
    row = {name: '' for name in inspection.HEADERS['officer_family_details.csv']}
    row['recorded_by_officer_rank'] = 'PRIVATE_NAME'
    counts = inspection.review_row('officer_family_details.csv', row, None, None, None, {})
    assert counts['rank:recorded_by_officer_rank:UNMAPPED_LABEL'] == 1
    assert 'PRIVATE_NAME' not in json.dumps(counts)
    row['recorded_by_officer_rank'] = 'ASP'
    assert inspection.review_row('officer_family_details.csv', row, None, None, None, {})['rank:recorded_by_officer_rank:ASP'] == 1
