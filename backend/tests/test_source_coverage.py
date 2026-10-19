"""Coverage gaps, protected key matching and provenance checks without database IO."""
from copy import deepcopy
import hashlib
from uuid import uuid4
import pytest
from app.identity.source_coverage import ReferenceInventory, receipt_coverage, coordinate_shape, SOURCES, ROWS
from app.identity.inspect_source_coverage import routing_contract, validate_receipt_provenance
from app.identity.inspect_service_plans import BATCH


class Crypto:
    def lookup_hmac(self, text, identifier_type):
        # Deterministic test token only; production uses the private keyed crypto.
        return hashlib.sha256((identifier_type + text).encode()).digest(), "TEST"


def test_same_counts_cannot_hide_replaced_row():
    report = receipt_coverage({"a", "b"}, [{"raw_record_id": "a", "complete": True}, {"raw_record_id": "c", "complete": True}])
    assert report["missing_rows"] == report["unexpected_rows"] == 1
    assert report["complete_rows"] == 1


@pytest.mark.parametrize("complete,duplicates,missing", [(True, 0, 0), (False, 0, 0), (True, 1, 1)])
def test_incomplete_and_duplicate_coverage(complete, duplicates, missing):
    receipts = [{"raw_record_id": "a", "complete": complete}, {"raw_record_id": "a" if duplicates else "b", "complete": complete}]
    report = receipt_coverage({"a", "b"}, receipts)
    assert report["duplicate_rows"] == duplicates and report["missing_rows"] == missing
    assert report["incomplete_rows"] == (0 if complete else 2)


def observations(inventory, filename, field):
    return {r["observation"]: r["count"] for r in inventory.report()["reference_observations"] if (r["filename"], r["field"]) == (filename, field)}


def test_leading_zero_keys_never_collapsed():
    inventory = ReferenceInventory(Crypto())
    inventory.add("operations.csv", dict(operation_no="001", complaint_number="", operation_handle_station_code=""))
    inventory.add("court_details.csv", dict(court_no="C1", operation_no="1", complaint_no=""))
    assert observations(inventory, "court_details.csv", "operation_no") == {"NO_REPORTED_KEY_MATCH": 1}


def test_exact_trim_match_and_ambiguity_preserved():
    inventory = ReferenceInventory(Crypto())
    for key in (" 001 ", "001"):
        inventory.add("operations.csv", dict(operation_no=key, complaint_number="", operation_handle_station_code=""))
    inventory.add("court_details.csv", dict(court_no="C1", operation_no="001", complaint_no=""))
    assert observations(inventory, "court_details.csv", "operation_no") == {"MULTIPLE_REPORTED_KEY_ROWS": 1}


def test_override_reference_subject_claims_are_compared_not_authorized():
    inventory = ReferenceInventory(Crypto())
    inventory.add("officer_restrictions.csv", dict(restriction_id="R1", officer_nic_no="NIC-A", restricted_station_code=""))
    inventory.add("restriction_overrides.csv", dict(restriction_id="R1", transfer_id="", officer_nic_no="NIC-B"))
    assert observations(inventory, "restriction_overrides.csv", "restriction_id") == {"SINGLE_REPORTED_KEY_MATCH": 1, "DIFFERENT_REPORTED_SUBJECT": 1}


def test_sinhala_name_is_candidate_only_and_coordinates_remain_observations():
    inventory = ReferenceInventory(Crypto())
    inventory.add("station_master.csv", dict(station_code="001", station_name_si="නිදර්ශන-ස්ථානය"))
    inventory.add("sri_lanka_police_stations_sinhala.csv", {"Police Station (පොලිස් ස්ථානය)": "නිදර්ශන-ස්ථානය", "Latitude": "91", "Longitude": "79"})
    assert observations(inventory, "sri_lanka_police_stations_sinhala.csv", "Police Station (පොලිස් ස්ථානය)") == {"SINGLE_REPORTED_KEY_MATCH": 1}
    assert any(r["observation"] == "OUTSIDE_DECIMAL_DEGREE_RANGE" for r in inventory.report()["coordinate_observations"])
    assert "නිදර්ශන-ස්ථානය" not in str(inventory.report())


def test_private_reference_values_never_appear_in_reports_or_indexes():
    inventory = ReferenceInventory(Crypto())
    inventory.add("public_complaints.csv", dict(complaint_id="PRIVATE-COMPLAINT", officer_nic_no="PRIVATE-NIC",
        linked_case_no="PRIVATE-CASE", linked_court_case_no="", linked_transfer_id="", linked_punishment_id="",
        npc_reference_no="PRIVATE-NPC", linked_hrc_reference="PRIVATE-HRC", station_code=""))
    assert "PRIVATE" not in str(inventory.report())
    assert "PRIVATE" not in str(inventory.keys)
    assert "PRIVATE" not in str(inventory.pending)
    assert {r["observation"] for r in inventory.report()["external_reference_observations"]} == {"NO_RECEIVED_TARGET_CATALOG"}


@pytest.mark.parametrize("value,status", [("", "MISSING"), ("nan", "NONFINITE"), ("Infinity", "NONFINITE"), ("text", "NONNUMERIC"), ("-91", "OUTSIDE_DECIMAL_DEGREE_RANGE"), ("90", "WITHIN_DECIMAL_DEGREE_RANGE")])
def test_coordinate_shapes(value, status):
    assert coordinate_shape(value, -90, 90) == status


def test_routing_requires_all_sources_preserved():
    document = {"files": [{"filename": name, "fields": [{"source_column": "x", "preserve_in_protected_staging": True}]} for name in SOURCES]}
    assert set(routing_contract(document)) == set(SOURCES)
    document["files"].pop()
    with pytest.raises(ValueError): routing_contract(document)


def test_duplicate_or_unpreserved_routing_fields_rejected():
    document = {"files": [{"filename": name, "fields": [{"source_column": "x", "preserve_in_protected_staging": True}]} for name in SOURCES]}
    document["files"][0]["fields"].append(deepcopy(document["files"][0]["fields"][0]))
    with pytest.raises(ValueError): routing_contract(document)
    document["files"][0]["fields"].pop(); document["files"][0]["fields"][0]["preserve_in_protected_staging"] = False
    with pytest.raises(ValueError): routing_contract(document)


@pytest.mark.parametrize("field", [None, "raw_record_id", "source_file_name", "source_code", "source_file_sha256", "source_row_number", "intake_batch_id", "import_file_id", "assertion_type", "group"])
def test_receipt_provenance_mismatch_rejected(field):
    file_id = uuid4()
    receipt = dict(raw_record_id="a", complete=True, group="FAMILY")
    raw = dict(filename="officer_family_details.csv", source_file_sha256="b" * 64, source_row_number=1, import_file_id=file_id)
    assertion = dict(raw_record_id="a", source_file_name=raw["filename"], source_code="POLICE_HR_IS", source_file_sha256="b" * 64,
        source_row_number=1, intake_batch_id=BATCH, import_file_id=str(file_id), assertion_type="HR_FAMILY_EVIDENCE")
    if field is None: validate_receipt_provenance(receipt, assertion, raw)
    else:
        (receipt if field == "group" else assertion)[field] = "ALTERED"
        with pytest.raises(ValueError): validate_receipt_provenance(receipt, assertion, raw)


def test_two_reference_files_are_separate_from_seventeen_imported_files():
    assert len(ROWS) == 17 and len(SOURCES) == 19
    assert "station_master.csv" not in ROWS and "sri_lanka_police_stations_sinhala.csv" not in ROWS


@pytest.mark.parametrize("mode", ["complete", "pending", "bad_digest", "orphan_completion", "bad_confirmation"])
def test_completion_states_are_checked_without_reading_sealed_documents(mode):
    from app.identity.inspect_source_coverage import load_receipts
    from app.identity.inspect_service_plans import CONFIRMATION
    event, assertion = uuid4(), uuid4()
    prep = dict(delivery_id=event, raw_record_id="r", source_assertion_id=assertion,
        confirmation_sha256="0" * 64 if mode == "bad_confirmation" else CONFIRMATION, document_sha256="a" * 64)
    done = dict(delivery_id=uuid4() if mode == "orphan_completion" else event,
        document_sha256="b" * 64 if mode == "bad_digest" else "a" * 64)
    class Result:
        def __init__(self, rows): self.rows = rows
        def mappings(self): return iter(self.rows)
    class ReadConnection:
        def execute(self, statement):
            assert statement.is_select
            assert not {"document_bson", "evidence_ciphertext", "asserted_value_ciphertext"} & {c.name for c in statement.selected_columns}
            name = statement.get_final_froms()[0].name
            rows = [prep] if name == "service_delivery_preparation" else [done] if name == "service_delivery_completion" and mode != "pending" else []
            return Result(rows)
    if mode in {"bad_digest", "orphan_completion", "bad_confirmation"}:
        with pytest.raises(ValueError): load_receipts(ReadConnection())
    else:
        receipts, assertions = load_receipts(ReadConnection())
        assert len(receipts) == 1 and receipts[0]["complete"] == (mode == "complete")
        assert assertions == {assertion}
