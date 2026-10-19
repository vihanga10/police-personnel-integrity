"""Test read-only progress gates and CLI mode guards without real database access."""
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID
from bson import BSON
import hashlib
import pytest
from app.identity import import_remaining
from app.identity.service_delivery import PreparedDelivery
from app.storage.check_remaining_mongo import fixture as remaining_fixture


def fixture():
    document, key, _ = remaining_fixture("education_records")
    return document, key


class Response:
    def __init__(self, value):
        self.value = value
    def mappings(self):
        return self
    def one_or_none(self):
        return self.value
    def scalar_one_or_none(self):
        return self.value


class ReadConnection:
    def __init__(self, saved, receipt):
        self.values = iter((saved, receipt))
        self.reads = 0
    def execute(self, statement):
        # Accidental persistence in state inspection is a test failure.
        assert statement.is_select
        self.reads += 1
        return Response(next(self.values))


class ReadCollection:
    def __init__(self, document):
        self.document = document
        self.name = "education_records"
    def find_one(self, query):
        if self.document is None:
            return None
        assert self.document["raw_record_id"] == query["raw_record_id"]
        return self.document


@pytest.mark.parametrize("present,receipt,state", [
    (False, False, "PENDING_MONGO"), (True, False, "PENDING_RECEIPT"),
    (True, True, "VERIFIED_EXISTING"),
])
def test_saved_progress_inspection_has_no_write_path(present, receipt, state):
    document, _ = fixture()
    encoded = bytes(BSON.encode(document))
    prepared = PreparedDelivery(encoded, hashlib.sha256(encoded).hexdigest())
    connection = ReadConnection({"delivery_id": UUID(document["_id"])}, prepared.document_sha256 if receipt else None)
    collection = ReadCollection(prepared.document() if present else None)
    binding = SimpleNamespace(raw_record_id=document["raw_record_id"])
    with patch.object(import_remaining, "assert_saved", return_value=prepared):
        actual, recovered = import_remaining.saved_state(connection, collection, crypto=None, backup=None, binding=binding, payload={"filename": "officer_education.csv"})
    assert actual == state and recovered == prepared and connection.reads == 2


def test_unprepared_row_is_planned_without_creating_a_record():
    connection, collection = ReadConnection(None, None), ReadCollection(None)
    state, prepared = import_remaining.saved_state(connection, collection, crypto=None, backup=None,
        binding=SimpleNamespace(raw_record_id="a" * 64), payload={"filename": "officer_education.csv"})
    assert (state, prepared, connection.reads) == ("PLANNED", None, 1)


def test_orphan_mongo_evidence_cannot_be_adopted_without_sql_preparation():
    document, _ = fixture()
    with pytest.raises(ValueError, match="no SQL preparation"):
        import_remaining.saved_state(ReadConnection(None, None), ReadCollection(document), crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id=document["raw_record_id"]), payload={"filename": "officer_education.csv"})


def test_missing_completed_mongo_evidence_requires_integrity_review():
    document, _ = fixture()
    encoded = bytes(BSON.encode(document))
    prepared = PreparedDelivery(encoded, hashlib.sha256(encoded).hexdigest())
    with patch.object(import_remaining, "assert_saved", return_value=prepared), pytest.raises(ValueError, match="integrity review"):
        import_remaining.saved_state(ReadConnection({}, prepared.document_sha256), ReadCollection(None), crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id=document["raw_record_id"]), payload={"filename": "officer_education.csv"})


def cli_arguments():
    values = ["program", "--batch-id", import_remaining.BATCH, "--expected-archive-sha256", import_remaining.ARCHIVE,
              "--expected-confirmation-sha256", import_remaining.CONFIRMATION, "--expected-education-rows", "6596", "--expected-operation-rows", "19554", "--expected-court-rows", "9538", "--expected-complaint-rows", "998", "--expected-demotion-rows", "8"]
    for name in ("confirmation", "key-file", "backup-key-file", "remaining-credential-directory", "attempt-root"):
        values += ["--" + name, "/test/" + name]
    return values


def test_default_mode_cannot_write_or_repair():
    with patch("sys.argv", cli_arguments()):
        args = import_remaining.arguments()
    assert args.write is False and args.reconcile is False


def test_write_and_reconciliation_cannot_be_combined():
    with patch("sys.argv", cli_arguments() + ["--write", "--reconcile"]), pytest.raises(SystemExit):
        import_remaining.arguments()


def test_unreviewed_batch_fingerprint_is_refused_before_connections():
    values = cli_arguments()
    values[values.index(import_remaining.ARCHIVE)] = "0" * 64
    with patch("sys.argv", values), pytest.raises(SystemExit):
        import_remaining.arguments()


def checkpoint_totals():
    return (dict(import_remaining.EXPECTED_ROWS),
        {name:240 if name == 'public_complaints.csv' else 0 for name in import_remaining.ROUTES}, {})


def test_verified_batch_counts_do_not_promote_truth():
    import_remaining.validate_batch_totals(*checkpoint_totals())


@pytest.mark.parametrize("index", [0, 1])
def test_changed_counts_stop_preflight(index):
    values = list(checkpoint_totals())
    key = next(iter(values[index]))
    values[index][key] += 1
    with pytest.raises(ValueError):
        import_remaining.validate_batch_totals(*values)


def test_wrong_collection_is_rejected_without_a_database_read():
    connection = ReadConnection(None, None)
    collection = ReadCollection(None)
    collection.name = "operation_records"
    with pytest.raises(ValueError, match="Wrong remaining Mongo destination"):
        import_remaining.saved_state(connection, collection, crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id="a"*64), payload={"filename": "officer_education.csv"})
    assert connection.reads == 0


@pytest.mark.parametrize("flag", ["--expected-education-rows", "--expected-operation-rows", "--expected-court-rows", "--expected-complaint-rows", "--expected-demotion-rows"])
def test_wrong_source_row_count_is_refused_before_connections(flag):
    values = cli_arguments()
    values[values.index(flag)+1] = "0"
    with patch("sys.argv", values), pytest.raises(SystemExit):
        import_remaining.arguments()


@pytest.mark.parametrize('filename', list(import_remaining.ROUTES))
def test_payload_recovery_preserves_unknowns_and_multi_person_rows(tmp_path, filename):
    import base64, json
    from dataclasses import asdict
    from uuid import uuid4
    from app.intake.staging_rows import seal_row
    from app.security.identity_crypto import IdentityCrypto
    key = base64.b64encode(b'k'*32).decode()
    path = tmp_path/'ephemeral.json'
    path.write_text(json.dumps(dict(active_encryption_key_version='TEST',active_lookup_key_version='TEST',
        encryption_keys={'TEST':key},lookup_keys={'TEST':key})))
    crypto = IdentityCrypto(path)
    officer,file_id = uuid4(),uuid4()
    row = dict.fromkeys(import_remaining.ROUTES[filename],'')
    if 'officer_nic_no' in row: row['officer_nic_no'] = 'TEST-NIC'
    source_key = import_remaining.SOURCE_KEYS[filename]
    if source_key: row[source_key] = '00012'
    if filename == 'public_complaints.csv': row['officer_nic_as_recorded'] = 'UNKNOWN-NIC'
    sealed = seal_row(crypto,batch_id=import_remaining.BATCH,archive_path=filename,source_file_sha256='b'*64,
        source_row_number=1,columns=list(row),values=list(row.values()))
    raw = dict(asdict(sealed),import_file_id=file_id)
    file = dict(batch_id=import_remaining.BATCH,archive_path=filename,source_file_sha256='b'*64,
        import_file_id=file_id,columns=list(row))
    refs = [dict(identifier_version_id=str(uuid4()),source_assertion_id=str(uuid4()),
        linkage_method='EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH',historical_eligibility='UNASSESSED')]
    args = SimpleNamespace(batch_id=import_remaining.BATCH,expected_archive_sha256=import_remaining.ARCHIVE,
        expected_confirmation_sha256=import_remaining.CONFIRMATION)
    def discover(*args):
        return ('NO_CANDIDATE_FOUND',None) if args[3] else ('UNUSABLE_NIC',None)
    with patch.object(import_remaining,'find_identifier_candidates',return_value=SimpleNamespace(
        status='SINGLE_CANDIDATE',officer_uids=(officer,))) as lookup, \
        patch.object(import_remaining,'verified_nic_evidence',return_value=refs) as proof, \
        patch.object(import_remaining,'inspected_link',side_effect=discover):
        cache = {}
        payload,binding,digest,source_id = import_remaining.remaining_payload(None,crypto,crypto,raw,file,args,'d'*40,cache,{})
        again = import_remaining.remaining_payload(None,crypto,crypto,raw,file,args,'d'*40,cache,{})
        assert {f['source_column']:f['source_value'] for f in payload['fields']} == row
        assert digest == again[2] and len(digest) == 64
        assert payload['effects_applied'] is False and payload['valid_from'] is None
        assert payload['reference_evidence']['source_system_code'] == import_remaining.SOURCES[filename]
        single = 'officer_nic_no' in row
        assert payload['officer_uid'] == (str(officer) if single else None)
        assert binding.identifier_version_id == (UUID(refs[0]['identifier_version_id']) if single else None)
        assert lookup.call_count == proof.call_count == int(single)
        assert source_id == ('00012' if source_key else str(officer))
        if filename == 'public_complaints.csv':
            assert payload['needs_review'] is True
            assert payload['reference_evidence']['identity_candidates']['officer_nic_as_recorded'] == dict(
                candidate_state='NO_CANDIDATE_FOUND',officer_uid=None)


@pytest.mark.parametrize('mode,invalid,expected_result', [
    ('validation', False, 0), ('write', False, 0), ('write', True, 1), ('reconcile', False, 1),
])
def test_complete_importer_flow_gates_all_writes(tmp_path, monkeypatch, mode, invalid, expected_result):
    """Small five-source orchestration, actual crypto/protocol, inert database boundaries."""
    import base64
    from contextlib import nullcontext
    from dataclasses import asdict
    import json
    from uuid import uuid4
    from sqlalchemy.sql.selectable import Select
    from app.identity.station_reference import StationIndex
    from app.intake.staging_rows import seal_row
    from app.security.identity_crypto import IdentityCrypto
    from app.models import RemainingSourceAssertion
    from app.staging.models import IntakeBatch, IntakeFile, RawRecord
    from app.identity.remaining_sql_ledger import PREP
    from app.identity.service_delivery import PreparedDelivery
    mod = import_remaining
    key = base64.b64encode(b'z'*32).decode()
    keys = []
    for name in ('primary.json', 'backup.json'):
        path = tmp_path / name
        path.write_text(json.dumps(dict(active_encryption_key_version='TEST', active_lookup_key_version='TEST',
            encryption_keys={'TEST': key}, lookup_keys={'TEST': key})))
        path.chmod(0o600)
        keys.append(path)
    crypto = IdentityCrypto(keys[0])
    officer = uuid4()
    files, raw_rows = [], {}
    for filename in mod.ROUTES:
        row = dict.fromkeys(mod.ROUTES[filename], '')
        if 'officer_nic_no' in row: row['officer_nic_no'] = 'SAME-TEST-NIC'
        if mod.SOURCE_KEYS[filename]: row[mod.SOURCE_KEYS[filename]] = '00012'
        if invalid and filename == '_demotions_enacted.csv':
            row['officer_nic_no'] = ''
        file_id = uuid4()
        file = dict(batch_id=mod.BATCH, archive_path=filename, source_file_sha256='b'*64,
            import_file_id=file_id, columns=list(row), expected_row_count=1)
        files.append(file)
        raw = dict(asdict(seal_row(crypto, batch_id=mod.BATCH, archive_path=filename, source_file_sha256='b'*64,
            source_row_number=1, columns=list(row), values=list(row.values()))), import_file_id=file_id)
        raw_rows[raw['raw_record_id']] = raw
    batch = dict(archive_sha256=mod.ARCHIVE, expected_file_count=5)

    class Result:
        def __init__(self, value): self.value = value
        def mappings(self): return self
        def scalars(self): return self
        def one(self): return self.value
        def all(self): return self.value
        def one_or_none(self): return self.value
        def __iter__(self): return iter(self.value)

    class Connection:
        def begin(self): return nullcontext()
        def execute(self, statement):
            if not isinstance(statement, Select):
                assert str(statement) in {
                    'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY',
                    'SELECT current_user, current_database()'}
                return Result(('police_identity_app', 'police_identity'))
            table = statement.get_final_froms()[0].fullname
            if table == IntakeBatch.__table__.fullname: return Result(batch)
            if table == IntakeFile.__table__.fullname: return Result(files)
            if table == RemainingSourceAssertion.__table__.fullname: return Result([])
            if table == PREP.fullname:
                return Result(None if len(list(statement.selected_columns)) == len(PREP.c) else [])
            assert table == RawRecord.__table__.fullname
            params = statement.compile().params
            if 'raw_record_id_1' in params: return Result(raw_rows[params['raw_record_id_1']])
            return Result([r for r in raw_rows.values() if r['import_file_id'] == params['import_file_id_1']])

    class Engine:
        disposed = False
        def connect(self): return nullcontext(Connection())
        def dispose(self): self.disposed = True

    class Collection:
        def __init__(self, name): self.name, self.documents, self.inserts = name, [], 0
        def find_one(self, query):
            return next((d for d in self.documents if all(d.get(k) == v for k,v in query.items())), None)
        def find(self, query, projection): return iter(self.documents)
        def insert_one(self, document):
            self.inserts += 1
            self.documents.append(document)
            return SimpleNamespace(acknowledged=True)

    class Mongo:
        closed = False
        def __init__(self): self.collections = {name: Collection(name) for name in mod.COLLECTION_POLICIES}
        def __getitem__(self, name): return self if name == mod.DATABASE else self.collections[name]
        def close(self): self.closed = True

    class Ledger:
        instances = []
        def __init__(self, engine, **kwargs):
            self.prepared, self.receipt = None, None
            self.instances.append(self)
        def prepare_once(self, proposed):
            self.prepared = proposed
            return proposed
        def completion_digest(self, event): return self.receipt
        def complete_once(self, prepared):
            self.receipt = prepared.document_sha256
            return self.receipt

    engine, mongo = Engine(), Mongo()
    args = SimpleNamespace(batch_id=mod.BATCH, expected_archive_sha256=mod.ARCHIVE,
        expected_confirmation_sha256=mod.CONFIRMATION, confirmation=tmp_path/'confirmation.json',
        key_file=keys[0], backup_key_file=keys[1], remaining_credential_directory=tmp_path/'creds',
        attempt_root=tmp_path/'attempts', write=mode=='write', reconcile=mode=='reconcile')
    monkeypatch.setattr(mod, 'arguments', lambda: args)
    monkeypatch.setattr(mod.subprocess, 'check_output', lambda command, **kw: '' if command[-1]=='--porcelain' else 'd'*40)
    monkeypatch.setattr(mod, 'Settings', lambda: SimpleNamespace(host='127.0.0.1', port=5432, name='police_identity', user='police_identity_app'))
    monkeypatch.setattr(mod, 'create_identity_engine', lambda settings: engine)
    monkeypatch.setattr(mod, 'private_key_file', IdentityCrypto)
    monkeypatch.setattr(mod, 'verify_recovery', lambda *args: None)
    monkeypatch.setattr(mod, 'remaining_password', lambda directory: 'TEST-ONLY')
    monkeypatch.setattr(mod, 'remaining_client', lambda password: mongo)
    monkeypatch.setattr(mod, 'load_source_confirmation', lambda *args, **kw: SimpleNamespace(
        confirmation_sha256=mod.CONFIRMATION, source_for=lambda name:mod.SOURCES[name]))
    monkeypatch.setattr(mod, 'find_identifier_candidates', lambda *args:SimpleNamespace(
        status='NO_CANDIDATE_FOUND' if invalid and not args[2].value else 'SINGLE_CANDIDATE',
        officer_uids=() if invalid and not args[2].value else (officer,)))
    monkeypatch.setattr(mod, 'inspected_link', lambda *args:('UNUSABLE_NIC',None))
    refs = [dict(identifier_version_id=str(uuid4()), source_assertion_id=str(uuid4()),
        linkage_method='EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH', historical_eligibility='UNASSESSED')]
    monkeypatch.setattr(mod, 'verified_nic_evidence', lambda *args:refs)
    monkeypatch.setattr(mod, 'EXPECTED_ROWS', {name:1 for name in mod.ROUTES})
    def small_totals(counts, reviews, observations):
        assert dict(counts) == {name:1 for name in mod.ROUTES}
        assert dict(reviews) == {name:0 for name in mod.ROUTES}
    monkeypatch.setattr(mod, 'validate_batch_totals', small_totals)
    monkeypatch.setattr(mod, 'SqlRemainingLedger', Ledger)
    assert mod.main() == expected_result
    assert engine.disposed and mongo.closed
    expected_writes = 5 if mode == 'write' and not invalid else 0
    assert len(Ledger.instances) == sum(c.inserts for c in mongo.collections.values()) == expected_writes
    for ledger in Ledger.instances:
        assert isinstance(ledger.prepared, PreparedDelivery)
        assert ledger.receipt == ledger.prepared.document_sha256
    # Journals contain only aggregate/opaque bookkeeping; no original NIC/source cells.
    for path in args.attempt_root.glob('*/*.json'):
        assert 'SAME-TEST-NIC' not in path.read_text()
