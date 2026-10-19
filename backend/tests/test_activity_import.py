"""Test read-only progress gates and CLI mode guards without real database access."""
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID
from bson import BSON
import hashlib
import pytest
from app.identity import import_activities
from app.identity.service_delivery import PreparedDelivery
from app.storage.check_activity_mongo import fixture as activity_fixture


def fixture():
    document, key, _ = activity_fixture("duty_periods")
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
        self.name = "duty_periods"
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
    with patch.object(import_activities, "assert_saved", return_value=prepared):
        actual, recovered = import_activities.saved_state(connection, collection, crypto=None, backup=None, binding=binding, payload={"filename": "officer_duty_periods.csv"})
    assert actual == state and recovered == prepared and connection.reads == 2


def test_unprepared_row_is_planned_without_creating_a_record():
    connection, collection = ReadConnection(None, None), ReadCollection(None)
    state, prepared = import_activities.saved_state(connection, collection, crypto=None, backup=None,
        binding=SimpleNamespace(raw_record_id="a" * 64), payload={"filename": "officer_duty_periods.csv"})
    assert (state, prepared, connection.reads) == ("PLANNED", None, 1)


def test_orphan_mongo_evidence_cannot_be_adopted_without_sql_preparation():
    document, _ = fixture()
    with pytest.raises(ValueError, match="no SQL preparation"):
        import_activities.saved_state(ReadConnection(None, None), ReadCollection(document), crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id=document["raw_record_id"]), payload={"filename": "officer_duty_periods.csv"})


def test_missing_completed_mongo_evidence_requires_integrity_review():
    document, _ = fixture()
    encoded = bytes(BSON.encode(document))
    prepared = PreparedDelivery(encoded, hashlib.sha256(encoded).hexdigest())
    with patch.object(import_activities, "assert_saved", return_value=prepared), pytest.raises(ValueError, match="integrity review"):
        import_activities.saved_state(ReadConnection({}, prepared.document_sha256), ReadCollection(None), crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id=document["raw_record_id"]), payload={"filename": "officer_duty_periods.csv"})


def cli_arguments():
    values = ["program", "--batch-id", import_activities.BATCH, "--expected-archive-sha256", import_activities.ARCHIVE,
              "--expected-confirmation-sha256", import_activities.CONFIRMATION, "--expected-duty-rows", "3138", "--expected-firearms-rows", "30348", "--expected-good-conduct-rows", "2779", "--expected-bad-conduct-rows", "370"]
    for name in ("confirmation", "key-file", "backup-key-file", "activity-credential-directory", "attempt-root"):
        values += ["--" + name, "/test/" + name]
    return values


def test_default_mode_cannot_write_or_repair():
    with patch("sys.argv", cli_arguments()):
        args = import_activities.arguments()
    assert args.write is False and args.reconcile is False


def test_write_and_reconciliation_cannot_be_combined():
    with patch("sys.argv", cli_arguments() + ["--write", "--reconcile"]), pytest.raises(SystemExit):
        import_activities.arguments()


def test_unreviewed_batch_fingerprint_is_refused_before_connections():
    values = cli_arguments()
    values[values.index(import_activities.ARCHIVE)] = "0" * 64
    with patch("sys.argv", values), pytest.raises(SystemExit):
        import_activities.arguments()


def checkpoint_totals():
    return (dict(import_activities.EXPECTED_ROWS), {filename: 0 for filename in import_activities.ROUTES},
            {"H2_ALL_CORE_MISSING": 1614, "H2_ALL_CORE_PRESENT": 28734,
             "YEAR_EQUALS_REPORTED_H1_PLUS_H2": 28734,
             "YEAR_EQUALS_REPORTED_H1_WITH_H2_MISSING": 1614,
             "H1_SUPERVISOR_POLICE_SIGNATURE_MISSING_NOT_AUTHENTICITY_RESULT": 1232,
             "H2_SUPERVISOR_POLICE_SIGNATURE_MISSING_NOT_AUTHENTICITY_RESULT": 2744,
             "ANNUAL_SUPERVISOR_POLICE_SIGNATURE_MISSING_NOT_AUTHENTICITY_RESULT": 1227,
             "PUNISHMENT_DATE_MISSING_EFFECT_UNKNOWN": 81,
             "DELEGATION_REFERENCE_MISSING_NOT_PROOF_OF_NO_AUTHORITY": 370})


def test_verified_batch_counts_do_not_promote_truth():
    import_activities.validate_batch_totals(*checkpoint_totals())


@pytest.mark.parametrize("index", [0, 1, 2])
def test_changed_counts_stop_preflight(index):
    values = list(checkpoint_totals())
    key = next(iter(values[index]))
    values[index][key] += 1
    with pytest.raises(ValueError):
        import_activities.validate_batch_totals(*values)


def test_wrong_collection_is_rejected_without_a_database_read():
    connection = ReadConnection(None, None)
    collection = ReadCollection(None)
    collection.name = "firearms_assessments"
    with pytest.raises(ValueError, match="Wrong activity Mongo destination"):
        import_activities.saved_state(connection, collection, crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id="a"*64), payload={"filename": "officer_duty_periods.csv"})
    assert connection.reads == 0


@pytest.mark.parametrize("flag", ["--expected-duty-rows", "--expected-firearms-rows", "--expected-good-conduct-rows", "--expected-bad-conduct-rows"])
def test_wrong_source_row_count_is_refused_before_connections(flag):
    values = cli_arguments()
    values[values.index(flag)+1] = "0"
    with patch("sys.argv", values), pytest.raises(SystemExit):
        import_activities.arguments()


@pytest.mark.parametrize('filename', list(import_activities.ROUTES))
@pytest.mark.parametrize('bad_actor', [False, True])
def test_payload_preserves_originals_and_requires_supported_actors(tmp_path, filename, bad_actor):
    import base64
    import json
    from dataclasses import asdict
    from uuid import uuid4
    from app.identity.station_reference import StationIndex
    from app.intake.staging_rows import seal_row
    from app.security.identity_crypto import IdentityCrypto
    key = base64.b64encode(b'k'*32).decode()
    path = tmp_path / 'ephemeral.json'
    path.write_text(json.dumps(dict(active_encryption_key_version='TEST', active_lookup_key_version='TEST',
        encryption_keys={'TEST': key}, lookup_keys={'TEST': key})))
    crypto = IdentityCrypto(path)
    officer, file_id = uuid4(), uuid4()
    row = dict.fromkeys(import_activities.ROUTES[filename], '')
    row['officer_nic_no'] = 'TEST-NIC'
    row[import_activities.SOURCE_KEYS[filename]] = '00012'
    actor_names = import_activities.ACTOR_FIELDS[filename]
    if actor_names:
        row[next(iter(actor_names))] = 'TEST-ACTOR'
    if filename == 'officer_duty_periods.csv':
        row.update(period_station_code='001', period_station_name='TEST-STATION', current_station_code='001')
    elif filename == 'officer_firearms_expertise.csv':
        # Missing H2 remains missing; unreviewed status remains an encrypted claim.
        row.update(gun_performance_station_code='001', gun_performance_station_name='TEST-STATION',
            record_status='Unknown original status', h1_total_points='12', year_total_points='12')
    elif filename == 'good_conduct_register.csv':
        row.update(accused_arrested='TRUE', accused_convicted='FALSE')
    sealed = seal_row(crypto, batch_id=import_activities.BATCH, archive_path=filename, source_file_sha256='b'*64,
        source_row_number=1, columns=list(row), values=list(row.values()))
    raw = dict(asdict(sealed), import_file_id=file_id)
    file = dict(batch_id=import_activities.BATCH, archive_path=filename, source_file_sha256='b'*64,
        import_file_id=file_id, columns=list(row))
    refs = [dict(identifier_version_id=str(uuid4()), source_assertion_id=str(uuid4()),
        linkage_method='EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH', historical_eligibility='UNASSESSED')]
    with patch.object(import_activities, 'find_identifier_candidates', return_value=SimpleNamespace(
            status='SINGLE_CANDIDATE', officer_uids=(officer,))) as lookup, \
         patch.object(import_activities, 'verified_nic_evidence', return_value=refs) as proof, \
         patch.object(import_activities, 'inspected_link', return_value=(
            'NO_CANDIDATE' if bad_actor else 'EXACT_EVIDENCE_CANDIDATE', None if bad_actor else officer)):
        subject_cache = {}
        def recover():
            return import_activities.activity_payload(None, crypto, crypto, raw, file,
                StationIndex({'TEST-STATION': ('001',)}, {'001': 'e'*64}), {'fixture': True},
                SimpleNamespace(expected_confirmation_sha256=import_activities.CONFIRMATION), 'd'*40, subject_cache, {})
        if bad_actor and actor_names:
            with pytest.raises(ValueError):
                recover()
        else:
            payload, binding, digest, source_id = recover()
            recovered = recover()
            assert {f['source_column']: f['source_value'] for f in payload['fields']} == row
            assert payload['valid_from'] is None and payload['valid_to'] is None
            assert payload['authority_result'] is None and payload['reconstructed_state'] is None
            assert binding.confirmation_sha256 == import_activities.CONFIRMATION
            assert digest == recovered[2] and len(digest) == 64 and source_id == '00012'
            assert lookup.call_count == proof.call_count == 1
            fields = {f['source_column']: f for f in payload['fields']}
            if filename == 'officer_firearms_expertise.csv':
                assert fields['h2_total_points']['value'] is None
                assert fields['record_status']['value'] == {'reported_label': 'Unknown original status', 'code': None}
            if filename == 'good_conduct_register.csv':
                assert fields['accused_arrested']['value'] is True
                assert fields['accused_convicted']['value'] is False


@pytest.mark.parametrize('mode,invalid,expected_result', [
    ('validation', False, 0), ('write', False, 0), ('write', True, 1), ('reconcile', False, 1),
])
def test_complete_importer_flow_gates_all_writes(tmp_path, monkeypatch, mode, invalid, expected_result):
    """Small four-source orchestration, actual crypto/protocol, inert database boundaries."""
    import base64
    from contextlib import nullcontext
    from dataclasses import asdict
    import json
    from uuid import uuid4
    from sqlalchemy.sql.selectable import Select
    from app.identity.station_reference import StationIndex
    from app.intake.staging_rows import seal_row
    from app.security.identity_crypto import IdentityCrypto
    from app.models import SourceAssertion
    from app.staging.models import IntakeBatch, IntakeFile, RawRecord
    from app.identity.activity_sql_ledger import PREP
    from app.identity.service_delivery import PreparedDelivery
    mod = import_activities
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
        row.update(officer_nic_no='SAME-TEST-NIC')
        row[mod.SOURCE_KEYS[filename]] = '00012'
        if invalid and filename == 'bad_conduct_register.csv':
            row['date_of_offence'] = 'invalid date'
        file_id = uuid4()
        file = dict(batch_id=mod.BATCH, archive_path=filename, source_file_sha256='b'*64,
            import_file_id=file_id, columns=list(row), expected_row_count=1)
        files.append(file)
        raw = dict(asdict(seal_row(crypto, batch_id=mod.BATCH, archive_path=filename, source_file_sha256='b'*64,
            source_row_number=1, columns=list(row), values=list(row.values()))), import_file_id=file_id)
        raw_rows[raw['raw_record_id']] = raw
    batch = dict(archive_sha256=mod.ARCHIVE, expected_file_count=4)

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
            if table == SourceAssertion.__table__.fullname: return Result([])
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
        key_file=keys[0], backup_key_file=keys[1], activity_credential_directory=tmp_path/'creds',
        attempt_root=tmp_path/'attempts', write=mode=='write', reconcile=mode=='reconcile')
    monkeypatch.setattr(mod, 'arguments', lambda: args)
    monkeypatch.setattr(mod.subprocess, 'check_output', lambda command, **kw: '' if command[-1]=='--porcelain' else 'd'*40)
    monkeypatch.setattr(mod, 'Settings', lambda: SimpleNamespace(host='127.0.0.1', port=5432, name='police_identity', user='police_identity_app'))
    monkeypatch.setattr(mod, 'create_identity_engine', lambda settings: engine)
    monkeypatch.setattr(mod, 'private_key_file', IdentityCrypto)
    monkeypatch.setattr(mod, 'verify_recovery', lambda *args: None)
    monkeypatch.setattr(mod, 'activity_password', lambda directory: 'TEST-ONLY')
    monkeypatch.setattr(mod, 'activity_client', lambda password: mongo)
    monkeypatch.setattr(mod, 'load_source_confirmation', lambda *args, **kw: SimpleNamespace(
        confirmation_sha256=mod.CONFIRMATION, source_for=lambda name:'SRB'))
    monkeypatch.setattr(mod, 'load_staged_station_index', lambda *args, **kw:(StationIndex({}, {}), {}))
    monkeypatch.setattr(mod, 'find_identifier_candidates', lambda *args:SimpleNamespace(status='SINGLE_CANDIDATE', officer_uids=(officer,)))
    refs = [dict(identifier_version_id=str(uuid4()), source_assertion_id=str(uuid4()),
        linkage_method='EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH', historical_eligibility='UNASSESSED')]
    monkeypatch.setattr(mod, 'verified_nic_evidence', lambda *args:refs)
    monkeypatch.setattr(mod, 'EXPECTED_ROWS', {name:1 for name in mod.ROUTES})
    def small_totals(counts, reviews, observations):
        assert dict(counts) == {name:1 for name in mod.ROUTES}
        assert dict(reviews) == {name:0 for name in mod.ROUTES}
    monkeypatch.setattr(mod, 'validate_batch_totals', small_totals)
    monkeypatch.setattr(mod, 'SqlActivityLedger', Ledger)
    assert mod.main() == expected_result
    assert engine.disposed and mongo.closed
    expected_writes = 4 if mode == 'write' and not invalid else 0
    assert len(Ledger.instances) == sum(c.inserts for c in mongo.collections.values()) == expected_writes
    for ledger in Ledger.instances:
        assert isinstance(ledger.prepared, PreparedDelivery)
        assert ledger.receipt == ledger.prepared.document_sha256
    # Journals contain only aggregate/opaque bookkeeping; no original NIC/source cells.
    for path in args.attempt_root.glob('*/*.json'):
        assert 'SAME-TEST-NIC' not in path.read_text()
