"""Encryption, replay and mutation tests; real SQL is covered by rollback checker."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4
import pytest
from cryptography.exceptions import InvalidTag
from app.security.identity_crypto import IdentityCrypto
from app.identity import family_writer as writer
from app.identity.family_records import FILENAME, POLICY, check_payload, logical_records, context
from app.identity.remaining_plan import plan_remaining
from app.identity.remaining_plan_crypto import seal_remaining_plan, open_remaining_plan
from app.identity.inspect_remaining_sources import HEADERS
from app.identity.inspect_service_plans import CONFIRMATION


@pytest.fixture
def keys(tmp_path):
    key = base64.b64encode(b"k" * 32).decode()
    material = dict(active_encryption_key_version="TEST", active_lookup_key_version="TEST", encryption_keys={"TEST": key}, lookup_keys={"TEST": key})
    paths = [tmp_path / n for n in ("primary.json", "backup.json")]
    for path in paths: path.write_text(json.dumps(material)); path.chmod(0o600)
    return tuple(IdentityCrypto(path) for path in paths)


def payload(crypto, **changes):
    officer = uuid4()
    row = dict.fromkeys(HEADERS[FILENAME], "")
    row.update(officer_nic_no="TEST-NIC", spouse_name="TEST-SPOUSE", date_of_marriage="2010-01-02",
        date_of_divorce="2015-01-02", childern_fullname="CHILD-A;CHILD-B", children_age="4;7", children_no="2",
        next_of_near_relative_name="TEST-KIN", recorded_by_officer_name="TEST-RECORDER")
    row.update(changes)
    plan = plan_remaining(FILENAME, row, officer_uid=officer)
    cipher, version = seal_remaining_plan(crypto, plan, raw_record_id="b" * 64, reference_evidence={})
    return open_remaining_plan(crypto, cipher, key_version=version, filename=FILENAME, raw_record_id="b" * 64)


class Result:
    def __init__(self, rows): self.rows = rows
    def mappings(self): return self
    def one(self): assert len(self.rows) == 1; return self.rows[0]
    def one_or_none(self): assert len(self.rows) <= 1; return self.rows[0] if self.rows else None
    def first(self): return self.rows[0] if self.rows else None
    def scalar_one(self):
        value = self.one(); return next(iter(value.values())) if isinstance(value, dict) else value


class MemoryConnection:
    """Small SQL boundary double; no mutation shortcuts in production writer."""
    def __init__(self): self.rows, self.insertions = {}, 0
    def execute(self, statement, *args):
        if getattr(statement, "is_insert", False):
            values = dict(statement.compile().params)
            name = statement.table.name
            values["assertion_state"] = values.get("assertion_state") or "ACTIVE"
            values["independence_status"] = values.get("independence_status") or "UNVERIFIED"
            for field in ("valid_from", "valid_to", "transaction_end", "source_recorded_at", "actor_officer_uid",
                "supersedes_family_relation_version_id", "supersedes_civil_event_version_id", "supersedes_next_of_kin_version_id", "supersedes_attestation_version_id"):
                values.setdefault(field, None)
            self.rows.setdefault(name, []).append(values); self.insertions += 1
            return Result([])
        if not getattr(statement, "is_select", False): return Result([])
        name = statement.get_final_froms()[0].name
        if name == "source_system":
            column = next(iter(statement.selected_columns)).name
            return Result([{column: "POLICE_HR_IS" if column == "source_system_code" else uuid4()}])
        rows = self.rows.get(name, [])
        # Each equality clause is applied independently, including assertion type.
        for clause in statement._where_criteria:
            rows = [r for r in rows if r.get(clause.left.name) == clause.right.value]
        if next(iter(statement.selected_columns)).name == "count": return Result([{"count": len(rows)}])
        return Result(rows)


@pytest.fixture
def imported(keys):
    crypto, backup = keys; expected = payload(crypto)
    binding = writer.FamilyBinding("b" * 64, uuid4(), CONFIRMATION, "c" * 40)
    raw = dict(batch_id="TEST", import_file_id=uuid4(), source_file_sha256="d" * 64, source_row_number=1, staged_at=datetime.now(timezone.utc))
    db = MemoryConnection()
    # Keep an unrelated PF relationship as a preservation sentinel.
    db.rows["officer_family_relation"] = [dict(source_assertion_id=uuid4(), relationship_type="FATHER", marker="PF-UNCHANGED")]
    with patch.object(writer, "check_source", return_value=raw):
        assert writer.transform(db, crypto, backup, binding=binding, payload=expected) == ("PLANNED", 6)
        assert db.insertions == 0
        assert writer.transform(db, crypto, backup, binding=binding, payload=expected, allow_write=True) == ("CREATED", 6)
    return db, crypto, backup, binding, expected, raw


def test_read_only_and_write_replay_preserve_pf(imported):
    db, crypto, backup, binding, expected, raw = imported
    before = deepcopy(db.rows); count = db.insertions
    with patch.object(writer, "check_source", return_value=raw):
        for allow in (False, True):
            assert writer.transform(db, crypto, backup, binding=binding, payload=expected, allow_write=allow) == ("VERIFIED_EXISTING", 6)
    assert db.rows == before and db.insertions == count
    assert db.rows["officer_family_relation"][0]["marker"] == "PF-UNCHANGED"


@pytest.mark.parametrize("table,column,value", [
    ("officer_family_relation", "relationship_type", "FATHER"),
    ("officer_family_relation", "version_number", 2),
    ("officer_family_relation", "relation_chain_uid", uuid4()),
    ("officer_family_civil_event_version", "family_relation_version_id", uuid4()),
    ("officer_family_civil_event_version", "officer_uid", uuid4()),
    ("officer_next_of_kin_version", "family_relation_version_id", uuid4()),
    ("officer_next_of_kin_version", "valid_from", "2020-01-01"),
    ("source_attestation", "resolution_status", "RESOLVED"),
    ("source_attestation", "actor_officer_uid", uuid4()),
    ("source_attestation", "attestation_type", "CERTIFIED_BY"),
    ("source_assertion", "assertion_type", "PF_PERSONAL_PROFILE"),
    ("source_assertion", "source_recorded_at", "2020-01-01"),
    ("family_transform_receipt", "confirmation_sha256", "f" * 64),
    ("family_transform_receipt", "identifier_version_id", uuid4()),
    ("family_transform_receipt", "code_revision", "f" * 40),
])
def test_replay_rejects_changed_binding(imported, table, column, value):
    db, crypto, backup, binding, expected, raw = imported
    index = 1 if table == "officer_family_relation" else 0
    db.rows[table][index][column] = value
    with patch.object(writer, "check_source", return_value=raw), pytest.raises((ValueError, InvalidTag)):
        writer.transform(db, crypto, backup, binding=binding, payload=expected)


@pytest.mark.parametrize("table", ["source_assertion", "family_transform_receipt", *writer.MODELS])
def test_ciphertext_tamper_rejected(imported, table):
    db, crypto, backup, binding, expected, raw = imported
    index = 1 if table == "officer_family_relation" else 0
    column = "asserted_value_ciphertext" if table == "source_assertion" else "evidence_ciphertext" if table == "family_transform_receipt" else "profile_payload_ciphertext"
    data = db.rows[table][index][column]; db.rows[table][index][column] = data[:-1] + bytes([data[-1] ^ 1])
    with patch.object(writer, "check_source", return_value=raw), pytest.raises(InvalidTag):
        writer.transform(db, crypto, backup, binding=binding, payload=expected)


def test_missing_destination_and_extra_destination_rejected(imported):
    db, crypto, backup, binding, expected, raw = imported
    extra = deepcopy(db.rows["officer_next_of_kin_version"][0])
    extra["next_of_kin_version_id"] = uuid4()
    db.rows["officer_next_of_kin_version"].append(extra)
    with patch.object(writer, "check_source", return_value=raw), pytest.raises(ValueError):
        writer.transform(db, crypto, backup, binding=binding, payload=expected)


def test_children_are_one_aggregate_without_pairing(keys):
    expected = payload(keys[0], children_age="4", date_of_death="not-a-date")
    children = [r for r in logical_records(expected) if r.kind == "CHILD"]
    assert len(children) == 1
    assert children[0].payload()["positional_pairing_accepted"] is False
    assert expected["needs_review"] is True
    assert not any(r.kind == "DEATH" for r in logical_records(expected))
    assert next(f for f in expected["fields"] if f["source_column"] == "date_of_death")["source_value"] == "not-a-date"


def test_sparse_row_keeps_assertion_without_invented_family(keys):
    changes = dict.fromkeys(HEADERS[FILENAME], ""); changes["officer_nic_no"] = "TEST-NIC"
    assert logical_records(payload(keys[0], **changes)) == ()


def test_civil_claim_without_name_retains_unresolved_spouse_anchor(keys):
    expected = payload(keys[0], spouse_name="")
    records = logical_records(expected)
    assert any(r.kind == "SPOUSE" for r in records)
    assert next(r for r in records if r.kind == "MARRIAGE").relation_kind == "SPOUSE"


@pytest.mark.parametrize("field,value", [("effects_applied", True), ("record_classification", "ORDINARY"), ("valid_from", "2020-01-01"), ("authority_result", "VALID")])
def test_unapproved_determinations_rejected(keys, field, value):
    expected = payload(keys[0]); expected[field] = value
    with pytest.raises(ValueError): check_payload(expected)


@pytest.mark.parametrize("component", ["record_id", "chain", "relation", "assertion", "officer", "table", "raw_id"])
def test_aad_binds_every_destination_component(keys, component):
    crypto, backup = keys
    kwargs = dict(raw_id="b" * 64, officer=uuid4(), assertion=uuid4(), record_id=uuid4(), table="officer_family_relation", chain=uuid4(), relation=uuid4())
    cipher, version = writer.seal(crypto, backup, {"synthetic": "fixture"}, context("DESTINATION", **kwargs))
    kwargs[component] = "different" if component in {"table", "raw_id"} else uuid4()
    with pytest.raises(InvalidTag): writer.recover(crypto, backup, cipher, version, context("DESTINATION", **kwargs))


@pytest.mark.parametrize("change", [None, "source_value", "normalized_value", "source_hash", "actor_candidate", "subject_ambiguous"])
def test_source_is_independently_replanned(keys, change):
    """Retaining original cells alone is insufficient: parsed claims must also agree."""
    from app.identity.inspect_service_plans import BATCH, ARCHIVE
    crypto, backup = keys; expected = payload(crypto)
    officer = writer.UUID(expected["officer_uid"])
    binding = writer.FamilyBinding("b" * 64, uuid4(), CONFIRMATION, "c" * 40)
    file = dict(batch_id=BATCH, archive_path=FILENAME, source_file_sha256="d" * 64, import_file_id=uuid4(), columns=list(HEADERS[FILENAME]))
    raw = dict(file, raw_record_id=binding.raw_record_id, source_row_number=1)
    original = dict(columns=list(HEADERS[FILENAME]), values=[f["source_value"] for f in expected["fields"]])
    expected["reference_evidence"] = dict(batch_id=BATCH, archive_sha256=ARCHIVE, confirmation_sha256=CONFIRMATION,
        source_system_code="POLICE_HR_IS", raw_record_id=binding.raw_record_id, import_file_id=str(file["import_file_id"]),
        source_file_sha256=file["source_file_sha256"], source_row_number=1,
        identity_candidates={"officer_nic_no": dict(candidate_state="EXACT_EVIDENCE_CANDIDATE", officer_uid=str(officer)),
            "recorded_by_officer_nic": dict(candidate_state="UNUSABLE_NIC", officer_uid=None)})
    if change == "source_value": expected["fields"][1]["source_value"] = "ALTERED-SPOUSE"
    if change == "normalized_value": expected["fields"][1]["value"] = "ALTERED-SPOUSE"
    if change == "source_hash": expected["reference_evidence"]["source_file_sha256"] = "f" * 64
    if change == "actor_candidate": expected["reference_evidence"]["identity_candidates"]["recorded_by_officer_nic"]["officer_uid"] = str(uuid4())
    class SourceConnection:
        def execute(self, statement):
            name = statement.get_final_froms()[0].name
            return Result([{"raw_record": raw, "intake_file": file, "intake_batch": {"archive_sha256": ARCHIVE}}[name]])
    discovered = [("MULTIPLE_CANDIDATES", None) if change == "subject_ambiguous" else ("EXACT_EVIDENCE_CANDIDATE", officer), ("UNUSABLE_NIC", None)]
    with patch.object(writer, "stored_row", return_value=None), patch.object(writer, "open_row", return_value=original), \
        patch.object(writer, "check_nic"), patch.object(writer, "inspected_link", side_effect=discovered):
        if change is None: assert writer.check_source(SourceConnection(), crypto, backup, binding, expected) == raw
        else:
            with pytest.raises(ValueError): writer.check_source(SourceConnection(), crypto, backup, binding, expected)
