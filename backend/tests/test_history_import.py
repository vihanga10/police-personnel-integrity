"""Test read-only progress gates and CLI mode guards without real database access."""
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID
from bson import BSON
import hashlib
import pytest
from app.identity import import_histories
from app.identity.service_delivery import PreparedDelivery
from app.storage.check_history_mongo import fixture as historical_fixture


def fixture():
    document, key, _ = historical_fixture("transfer_events")
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
        self.name = "transfer_events"
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
    with patch.object(import_histories, "assert_saved", return_value=prepared):
        actual, recovered = import_histories.saved_state(connection, collection, crypto=None, backup=None, binding=binding, payload={"filename": "transfer_history.csv"})
    assert actual == state and recovered == prepared and connection.reads == 2


def test_unprepared_row_is_planned_without_creating_a_record():
    connection, collection = ReadConnection(None, None), ReadCollection(None)
    state, prepared = import_histories.saved_state(connection, collection, crypto=None, backup=None,
        binding=SimpleNamespace(raw_record_id="a" * 64), payload={"filename": "transfer_history.csv"})
    assert (state, prepared, connection.reads) == ("PLANNED", None, 1)


def test_orphan_mongo_evidence_cannot_be_adopted_without_sql_preparation():
    document, _ = fixture()
    with pytest.raises(ValueError, match="no SQL preparation"):
        import_histories.saved_state(ReadConnection(None, None), ReadCollection(document), crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id=document["raw_record_id"]), payload={"filename": "transfer_history.csv"})


def test_missing_completed_mongo_evidence_requires_integrity_review():
    document, _ = fixture()
    encoded = bytes(BSON.encode(document))
    prepared = PreparedDelivery(encoded, hashlib.sha256(encoded).hexdigest())
    with patch.object(import_histories, "assert_saved", return_value=prepared), pytest.raises(ValueError, match="integrity review"):
        import_histories.saved_state(ReadConnection({}, prepared.document_sha256), ReadCollection(None), crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id=document["raw_record_id"]), payload={"filename": "transfer_history.csv"})


def cli_arguments():
    values = ["program", "--batch-id", import_histories.BATCH, "--expected-archive-sha256", import_histories.ARCHIVE,
              "--expected-confirmation-sha256", import_histories.CONFIRMATION, "--expected-transfer-rows", "33316", "--expected-promotion-rows", "13974"]
    for name in ("confirmation", "key-file", "backup-key-file", "history-credential-directory", "attempt-root"):
        values += ["--" + name, "/test/" + name]
    return values


def test_default_mode_cannot_write_or_repair():
    with patch("sys.argv", cli_arguments()):
        args = import_histories.arguments()
    assert args.write is False and args.reconcile is False


def test_write_and_reconciliation_cannot_be_combined():
    with patch("sys.argv", cli_arguments() + ["--write", "--reconcile"]), pytest.raises(SystemExit):
        import_histories.arguments()


def test_unreviewed_batch_fingerprint_is_refused_before_connections():
    values = cli_arguments()
    values[values.index(import_histories.ARCHIVE)] = "0" * 64
    with patch("sys.argv", values), pytest.raises(SystemExit):
        import_histories.arguments()


def checkpoint_totals():
    return (dict(import_histories.EXPECTED_ROWS),
            {"transfer_history.csv": 30, "promotion_history.csv": 0},
            {"SOURCE_REPORTS_CANCELLED_TRANSFER_PRESERVE_ORIGINAL": 118})


def test_verified_batch_counts_pass_without_promoting_source_truth():
    import_histories.validate_batch_totals(*checkpoint_totals())


@pytest.mark.parametrize("index,changed", [(0, {"transfer_history.csv": 33315, "promotion_history.csv": 13974}),
    (1, {"transfer_history.csv": 0, "promotion_history.csv": 0}),
    (1, {"transfer_history.csv": 30, "promotion_history.csv": 1}),
    (2, {"SOURCE_REPORTS_CANCELLED_TRANSFER_PRESERVE_ORIGINAL": 117}),
    (2, {"SOURCE_REPORTS_CANCELLED_TRANSFER_PRESERVE_ORIGINAL": 118, "UNEXPECTED_CHRONOLOGY": 1})])
def test_changed_review_coverage_or_cancellation_counts_stop_preflight(index, changed):
    values = list(checkpoint_totals())
    values[index] = changed
    with pytest.raises(ValueError):
        import_histories.validate_batch_totals(*values)


def test_wrong_collection_is_rejected_without_a_database_read():
    connection = ReadConnection(None, None)
    collection = ReadCollection(None)
    collection.name = "promotion_events"
    with pytest.raises(ValueError, match="Wrong historical Mongo destination"):
        import_histories.saved_state(connection, collection, crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id="a"*64), payload={"filename": "transfer_history.csv"})
    assert connection.reads == 0


@pytest.mark.parametrize("flag", ["--expected-transfer-rows", "--expected-promotion-rows"])
def test_wrong_source_row_count_is_refused_before_connections(flag):
    values = cli_arguments()
    values[values.index(flag)+1] = "0"
    with patch("sys.argv", values), pytest.raises(SystemExit):
        import_histories.arguments()


@pytest.mark.parametrize('filename', ['transfer_history.csv', 'promotion_history.csv'])
def test_payload_recovery_preserves_originals_and_exact_linkage_references(tmp_path, filename):
    import base64
    from dataclasses import asdict
    import json
    from uuid import uuid4
    from app.identity.history_plan import ROUTES
    from app.identity.station_reference import StationIndex
    from app.intake.staging_rows import seal_row
    from app.security.identity_crypto import IdentityCrypto
    key = base64.b64encode(b'k'*32).decode()
    path = tmp_path / 'ephemeral.json'
    path.write_text(json.dumps(dict(active_encryption_key_version='TEST', active_lookup_key_version='TEST',
                                   encryption_keys={'TEST': key}, lookup_keys={'TEST': key})))
    crypto = IdentityCrypto(path)
    officer, file_id = uuid4(), uuid4()
    row = dict.fromkeys(ROUTES[filename], '')
    row.update(officer_nic_no='SYNTHETIC-NIC', to_rank='Inspector of Police', effective_date='2020-01-01', is_same_unit='FALSE')
    if filename == 'transfer_history.csv':
        row.update(transfer_id='00001', is_cancelled='FALSE', days_in_previous_posting='-12',
                   to_station_code='001', to_station_name='TEST-STATION')
    else:
        row.update(promotion_id='00002', from_rank='Sub Inspector of Police')
    sealed = seal_row(crypto, batch_id='TEST-BATCH', archive_path=filename, source_file_sha256='b'*64,
                      source_row_number=1, columns=list(row), values=list(row.values()))
    raw = dict(asdict(sealed), import_file_id=file_id)
    file = dict(batch_id='TEST-BATCH', archive_path=filename, source_file_sha256='b'*64,
                import_file_id=file_id, columns=list(row))
    refs = [dict(identifier_version_id=str(uuid4()), source_assertion_id=str(uuid4()),
                 linkage_method='EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH', historical_eligibility='UNASSESSED') for _ in range(2)]
    with patch.object(import_histories, 'find_identifier_candidates', return_value=SimpleNamespace(
        status='SINGLE_CANDIDATE', officer_uids=(officer,))), patch.object(import_histories, 'verified_nic_evidence', return_value=refs):
        payload, binding, fingerprint, source_id = import_histories.history_payload(None, crypto, crypto, raw, file,
            StationIndex({'TEST-STATION': ('001',)}, {'001': 'e'*64}), {'fixture': True},
            SimpleNamespace(expected_confirmation_sha256='c'*64), 'd'*40)
    assert {f['source_column']: f['source_value'] for f in payload['fields']} == row
    assert binding.identifier_version_id == UUID(min(ref['identifier_version_id'] for ref in refs))
    assert payload['reference_evidence']['identifier_evidence'] == sorted(refs, key=lambda ref: ref['identifier_version_id'])
    assert len(fingerprint) == 64 and source_id in {'00001', '00002'}
    assert payload['authority_result'] is None and payload['record_classification'] == 'UNASSESSED'
    if filename == 'transfer_history.csv':
        assert payload['needs_review'] is True
        assert payload['reference_evidence']['station_matches']['to_station_code']['raw_record_id'] == 'e'*64
