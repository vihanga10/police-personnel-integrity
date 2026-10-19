"""Test read-only progress gates and CLI mode guards without real database access."""
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID
from bson import BSON
import hashlib
import pytest
from app.identity import import_srbs
from app.identity.service_delivery import PreparedDelivery
from app.storage.check_srb_mongo import fixture as srb_fixture


def fixture():
    document, key, _ = srb_fixture("police_number_intervals")
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
        self.name = "police_number_intervals"
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
    with patch.object(import_srbs, "assert_saved", return_value=prepared):
        actual, recovered = import_srbs.saved_state(connection, collection, crypto=None, backup=None, binding=binding, payload={"filename": "officer_police_numbers.csv"})
    assert actual == state and recovered == prepared and connection.reads == 2


def test_unprepared_row_is_planned_without_creating_a_record():
    connection, collection = ReadConnection(None, None), ReadCollection(None)
    state, prepared = import_srbs.saved_state(connection, collection, crypto=None, backup=None,
        binding=SimpleNamespace(raw_record_id="a" * 64), payload={"filename": "officer_police_numbers.csv"})
    assert (state, prepared, connection.reads) == ("PLANNED", None, 1)


def test_orphan_mongo_evidence_cannot_be_adopted_without_sql_preparation():
    document, _ = fixture()
    with pytest.raises(ValueError, match="no SQL preparation"):
        import_srbs.saved_state(ReadConnection(None, None), ReadCollection(document), crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id=document["raw_record_id"]), payload={"filename": "officer_police_numbers.csv"})


def test_missing_completed_mongo_evidence_requires_integrity_review():
    document, _ = fixture()
    encoded = bytes(BSON.encode(document))
    prepared = PreparedDelivery(encoded, hashlib.sha256(encoded).hexdigest())
    with patch.object(import_srbs, "assert_saved", return_value=prepared), pytest.raises(ValueError, match="integrity review"):
        import_srbs.saved_state(ReadConnection({}, prepared.document_sha256), ReadCollection(None), crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id=document["raw_record_id"]), payload={"filename": "officer_police_numbers.csv"})


def cli_arguments():
    values = ["program", "--batch-id", import_srbs.BATCH, "--expected-archive-sha256", import_srbs.ARCHIVE,
              "--expected-confirmation-sha256", import_srbs.CONFIRMATION, "--expected-number-rows", "15123", "--expected-restriction-rows", "10971", "--expected-override-rows", "150"]
    for name in ("confirmation", "key-file", "backup-key-file", "srb-credential-directory", "attempt-root"):
        values += ["--" + name, "/test/" + name]
    return values


def test_default_mode_cannot_write_or_repair():
    with patch("sys.argv", cli_arguments()):
        args = import_srbs.arguments()
    assert args.write is False and args.reconcile is False


def test_write_and_reconciliation_cannot_be_combined():
    with patch("sys.argv", cli_arguments() + ["--write", "--reconcile"]), pytest.raises(SystemExit):
        import_srbs.arguments()


def test_unreviewed_batch_fingerprint_is_refused_before_connections():
    values = cli_arguments()
    values[values.index(import_srbs.ARCHIVE)] = "0" * 64
    with patch("sys.argv", values), pytest.raises(SystemExit):
        import_srbs.arguments()


def checkpoint_totals():
    return (dict(import_srbs.EXPECTED_ROWS), {filename: 0 for filename in import_srbs.ROUTES},
            {"MISSING_END_NOT_EXPLICIT_OPEN_INTERVAL": 10774,
             "MISSING_REMOVAL_NOT_PROOF_OF_ACTIVE_RESTRICTION": 10137,
             "OVERRIDE_CLAIM_PRESERVED_NOT_APPLIED": 150})


def test_verified_batch_counts_do_not_promote_truth():
    import_srbs.validate_batch_totals(*checkpoint_totals())


@pytest.mark.parametrize("index", [0, 1, 2])
def test_changed_counts_stop_preflight(index):
    values = list(checkpoint_totals())
    key = next(iter(values[index]))
    values[index][key] += 1
    with pytest.raises(ValueError):
        import_srbs.validate_batch_totals(*values)


def test_wrong_collection_is_rejected_without_a_database_read():
    connection = ReadConnection(None, None)
    collection = ReadCollection(None)
    collection.name = "restriction_records"
    with pytest.raises(ValueError, match="Wrong SRB Mongo destination"):
        import_srbs.saved_state(connection, collection, crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id="a"*64), payload={"filename": "officer_police_numbers.csv"})
    assert connection.reads == 0


@pytest.mark.parametrize("flag", ["--expected-number-rows", "--expected-restriction-rows", "--expected-override-rows"])
def test_wrong_source_row_count_is_refused_before_connections(flag):
    values = cli_arguments()
    values[values.index(flag)+1] = "0"
    with patch("sys.argv", values), pytest.raises(SystemExit):
        import_srbs.arguments()




@pytest.mark.parametrize("filename", list(import_srbs.ROUTES))
@pytest.mark.parametrize("bad_link", [False, True])
def test_original_payloads_and_subject_consistency(tmp_path, filename, bad_link):
    import base64
    import json
    from dataclasses import asdict
    from uuid import uuid4
    from app.identity.station_reference import StationIndex
    from app.intake.staging_rows import seal_row
    from app.security.identity_crypto import IdentityCrypto
    key = base64.b64encode(b"k"*32).decode()
    path = tmp_path / "ephemeral.json"
    path.write_text(json.dumps(dict(active_encryption_key_version="TEST", active_lookup_key_version="TEST",
        encryption_keys={"TEST": key}, lookup_keys={"TEST": key})))
    crypto = IdentityCrypto(path)
    officer, file_id = uuid4(), uuid4()
    row = dict.fromkeys(import_srbs.ROUTES[filename], "")
    row["officer_nic_no"] = "TEST-NIC"
    indexes = {"restriction_id": {}, "transfer_id": {}}
    overrides = {}
    if filename == "officer_police_numbers.csv":
        row.update(police_no="00012", number_type="TEST", valid_from="2020-01-01")
    elif filename == "officer_restrictions.csv":
        row.update(restriction_id="R1", restriction_start_date="2020-01-01", restriction_record_date="2020-01-02",
            restriction_verifiable="TRUE", override_recorded="TRUE", restriction_recorded_officer_nic="TEST-ACTOR",
            restriction_recorded_officer_rank="Assistant Superintendent of Police",
            restricted_station_code="001", restricted_station_name="TEST-STATION")
        overrides["R1"] = [uuid4() if bad_link else officer]
    else:
        row.update(override_id="O1", restriction_id="R1", transfer_id="T1", override_date="2020-02-01",
            override_reference="P1", override_ground="Reported ground", override_reason="Reported reason",
            override_authority_nic="TEST-ACTOR", override_authority_rank="Assistant Superintendent of Police")
        for name, file in (("restriction_id", "officer_restrictions.csv"), ("transfer_id", "transfer_history.csv")):
            indexes[name][row[name]] = [import_srbs.SourceReference(file, "e"*64, uuid4() if bad_link else officer)]
    sealed = seal_row(crypto, batch_id=import_srbs.BATCH, archive_path=filename, source_file_sha256="b"*64,
        source_row_number=1, columns=list(row), values=list(row.values()))
    raw = dict(asdict(sealed), import_file_id=file_id)
    file = dict(batch_id=import_srbs.BATCH, archive_path=filename, source_file_sha256="b"*64,
        import_file_id=file_id, columns=list(row))
    refs = [dict(identifier_version_id=str(uuid4()), source_assertion_id=str(uuid4()),
        linkage_method="EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH", historical_eligibility="UNASSESSED")]
    with patch.object(import_srbs, "find_identifier_candidates", return_value=SimpleNamespace(
            status="SINGLE_CANDIDATE", officer_uids=(officer,))), \
         patch.object(import_srbs, "verified_nic_evidence", return_value=refs), \
         patch.object(import_srbs, "inspected_link", return_value=("EXACT_EVIDENCE_CANDIDATE", officer)):
        def recover():
            return import_srbs.srb_payload(None, crypto, crypto, raw, file,
                StationIndex({"TEST-STATION": ("001",)}, {"001": "e"*64}), {"fixture": True},
                SimpleNamespace(expected_confirmation_sha256=import_srbs.CONFIRMATION), "d"*40, indexes, overrides, {})
        if bad_link and filename != "officer_police_numbers.csv":
            with pytest.raises(ValueError):
                recover()
        else:
            payload, binding, digest, source_id = recover()
            assert {f["source_column"]: f["source_value"] for f in payload["fields"]} == row
            assert payload["valid_from"] is None and payload["valid_to"] is None
            assert payload["authority_result"] is None and payload["reconstructed_state"] is None
            assert binding.confirmation_sha256 == import_srbs.CONFIRMATION
            assert len(digest) == 64 and source_id == row[import_srbs.SOURCE_KEYS[filename]]


@pytest.mark.parametrize("end", [None, {"type": "date", "value": "2021-01-01"}])
def test_bounded_period_grouping_uses_reported_label_and_preserves_unknown_end(end):
    from copy import deepcopy
    from datetime import date
    payload = dict(filename="officer_police_numbers.csv", officer_uid="TEST-OFFICER", fields=[
        dict(source_column="number_type", source_value="  Reported type  ",
             value={"reported_label": "Reported type", "code": None}),
        dict(source_column="valid_from", source_value="2020-01-01",
             value={"type": "date", "value": "2020-01-01"}),
        dict(source_column="valid_to", source_value="" if end is None else "2021-01-01", value=end),
    ])
    original, periods = deepcopy(payload), {}
    import_srbs.record_bounded_number_period(payload, periods)
    assert payload == original
    assert periods == ({} if end is None else {
        ("TEST-OFFICER", "Reported type"): [(date(2020, 1, 1), date(2021, 1, 1))]})
