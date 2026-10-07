"""Preserve activity originals and test conditional evidence, aliases and encryption."""
from dataclasses import replace
from datetime import date
from decimal import Decimal
from uuid import uuid4
import base64
import json
import pytest
from app.identity.srb_activity_plan import plan_activity, HEADERS, status_vocabulary, ACTOR_FIELDS
from app.identity.srb_activity_plan_crypto import seal_activity_plan, open_activity_plan
from app.security.identity_crypto import IdentityCrypto


def row_for(filename):
    row = dict.fromkeys(HEADERS[filename], "")
    row["officer_nic_no"] = "TEST-NIC"
    key = {"officer_duty_periods.csv": "period_id", "officer_firearms_expertise.csv": "gun_record_id",
           "good_conduct_register.csv": "good_conduct_id", "bad_conduct_register.csv": "punishment_id"}[filename]
    row[key] = "00012"
    return row


@pytest.mark.parametrize("filename", list(HEADERS))
def test_every_original_cell_is_preserved(filename):
    row = row_for(filename)
    uid = uuid4()
    plan = plan_activity(filename, row, officer_uid=uid)
    assert {f.source_column: f.source_value for f in plan.fields} == row
    assert next(f.value for f in plan.fields if f.source_column == "officer_nic_no") == uid
    assert "REFERENCE_AUTHENTICITY_AND_LINKAGE_UNASSESSED" in plan.uncertainties
    assert "ACTIVITY_EFFECT_COMPETENCY_AND_LEGAL_STATUS_UNASSESSED" in plan.uncertainties


@pytest.mark.parametrize("alias,expected", [("CI", "CIP"), ("ASP", "ASP"), ("IP", "IP"), ("SDIG", "SDIG")])
def test_recording_rank_alias_is_field_scoped(alias, expected):
    row = row_for("officer_duty_periods.csv")
    row.update(period_recorded_by_authority_rank=alias, period_rank=alias)
    plan = plan_activity("officer_duty_periods.csv", row, officer_uid=uuid4())
    fields = {f.source_column: f for f in plan.fields}
    assert fields["period_recorded_by_authority_rank"].value == expected
    assert fields["period_rank"].status == "REVIEW_REQUIRED"
    assert fields["period_recorded_by_authority_rank"].issues == ("REPORTED_RANK_NOT_AUTHORITY",)


@pytest.mark.parametrize("value,status", [("TRUE", "PARSED"), ("FALSE", "PARSED"), ("1", "REVIEW_REQUIRED")])
def test_accused_flags_are_not_counts(value, status):
    row = row_for("good_conduct_register.csv")
    row["accused_arrested"] = value
    field = next(f for f in plan_activity("good_conduct_register.csv", row, officer_uid=uuid4()).fields if f.source_column == "accused_arrested")
    assert field.status == status
    if status == "PARSED":
        assert type(field.value) is bool


@pytest.mark.parametrize("value,status", [("NaN", "REVIEW_REQUIRED"), ("-1", "REVIEW_REQUIRED"),
    ("Infinity", "REVIEW_REQUIRED"), ("12.50", "PARSED")])
def test_finite_money_claims(value, status):
    row = row_for("good_conduct_register.csv")
    row["amount_paid_rs"] = value
    field = next(f for f in plan_activity("good_conduct_register.csv", row, officer_uid=uuid4()).fields if f.source_column == "amount_paid_rs")
    assert field.status == status and field.source_value == value
    if status == "PARSED":
        assert field.value == Decimal(value)


def test_missing_h2_is_never_zero_and_partial_h2_requires_review():
    row = row_for("officer_firearms_expertise.csv")
    row.update(h1_total_points="20", year_total_points="20")
    plan = plan_activity("officer_firearms_expertise.csv", row, officer_uid=uuid4())
    assert next(f.value for f in plan.fields if f.source_column == "h2_total_points") is None
    assert "H2_ALL_CORE_MISSING" in plan.observations
    row["h2_total_points"] = "10"
    assert "H2_CORE_PARTIALLY_POPULATED" in plan_activity("officer_firearms_expertise.csv", row, officer_uid=uuid4()).review_issues


def test_signature_without_h2_core_requires_review_without_deleting_it():
    row = row_for("officer_firearms_expertise.csv")
    row["h2_supervisor_police_signature"] = "TEST-SIGNATURE"
    plan = plan_activity("officer_firearms_expertise.csv", row, officer_uid=uuid4())
    assert "H2_SIGNATURE_WITHOUT_CORE_EVIDENCE" in plan.review_issues
    assert next(f.source_value for f in plan.fields if f.source_column == "h2_supervisor_police_signature") == "TEST-SIGNATURE"


def test_actor_candidate_and_station_match_do_not_establish_authority_or_history():
    row = row_for("officer_duty_periods.csv")
    actor = uuid4()
    row.update(period_recorded_by_authority_nic="TEST-ACTOR", period_station_code="001", period_station_name="TEST-STATION")
    plan = plan_activity("officer_duty_periods.csv", row, officer_uid=uuid4(),
        actor_candidates={"period_recorded_by_authority_nic": actor}, station_candidates={"TEST-STATION": ("001",)})
    assert not plan.review_issues
    assert next(f.value for f in plan.fields if f.source_column == "period_recorded_by_authority_nic") == actor
    bad = plan_activity("officer_duty_periods.csv", row, officer_uid=uuid4(), station_candidates={"TEST-STATION": ("002",)})
    assert "SOURCE_SCOPED_STATION_REFERENCE_UNRESOLVED" in bad.review_issues and bad.needs_review


def test_reversed_interval_is_flagged_and_not_corrected():
    row = row_for("officer_duty_periods.csv")
    row.update(period_from="2021-01-01", period_to="2020-01-01")
    plan = plan_activity("officer_duty_periods.csv", row, officer_uid=uuid4())
    assert "REPORTED_INTERVAL_END_BEFORE_START" in plan.review_issues
    assert next(f.value for f in plan.fields if f.source_column == "period_to") == date(2020, 1, 1)


@pytest.mark.parametrize("text,expected", [("FULL_YEAR_COMPLETE", "FULL_YEAR_COMPLETE"),
    ("H1 only", "H1 only"), ("TEST PERSON NAME", "UNREVIEWED_STATUS_TEXT"), ("", "MISSING"),
    ("123456789012", "UNREVIEWED_STATUS_TEXT")])
def test_status_output_has_no_arbitrary_text(text, expected):
    assert status_vocabulary(text) == expected


@pytest.mark.parametrize("filename", list(HEADERS))
def test_encrypted_plan_recovery_and_binding(tmp_path, filename):
    key = base64.b64encode(b"k"*32).decode()
    path = tmp_path / "ephemeral.json"
    path.write_text(json.dumps(dict(active_encryption_key_version="TEST", active_lookup_key_version="TEST",
        encryption_keys={"TEST": key}, lookup_keys={"TEST": key})))
    crypto = IdentityCrypto(path)
    uid = uuid4()
    plan = plan_activity(filename, row_for(filename), officer_uid=uid)
    cipher, version = seal_activity_plan(crypto, plan, raw_record_id="a"*64, reference_evidence={"fixture": True})
    payload = open_activity_plan(crypto, cipher, key_version=version, filename=filename, officer_uid=uid, raw_record_id="a"*64)
    assert all(payload[n] is None for n in ("valid_from", "valid_to", "authority_result", "reconstructed_state"))
    assert payload["record_classification"] == "UNASSESSED" and payload["authority_assessment"] == "NOT_RUN"
    assert {f["source_column"]: f["source_value"] for f in payload["fields"]} == row_for(filename)
    with pytest.raises(Exception):
        open_activity_plan(crypto, cipher, key_version=version, filename=filename, officer_uid=uuid4(), raw_record_id="a"*64)
    with pytest.raises(ValueError):
        seal_activity_plan(crypto, replace(plan, fields=plan.fields[:-1]), raw_record_id="a"*64, reference_evidence={})


def test_runner_reads_all_four_sources_and_recovers_plans_without_writes(tmp_path, monkeypatch, capsys):
    from contextlib import nullcontext
    from dataclasses import asdict
    from types import SimpleNamespace
    from app.identity import inspect_srb_activity_plans as runner
    from app.identity.station_reference import StationIndex
    from app.intake.staging_rows import seal_row
    key = base64.b64encode(b"k"*32).decode()
    path = tmp_path / "ephemeral.json"
    path.write_text(json.dumps(dict(active_encryption_key_version="TEST", active_lookup_key_version="TEST",
        encryption_keys={"TEST": key}, lookup_keys={"TEST": key})))
    crypto = IdentityCrypto(path)
    uid = uuid4()
    files, records = [], []
    for filename in HEADERS:
        values = row_for(filename)
        if filename == "officer_firearms_expertise.csv":
            values.update(record_status="H1_ONLY_RECORDED", h1_total_points="20", year_total_points="20")
        file_id = uuid4()
        file = dict(batch_id=runner.BATCH, archive_path=filename, source_file_sha256="b"*64,
            import_file_id=file_id, expected_row_count=1, columns=list(values))
        sealed = seal_row(crypto, batch_id=runner.BATCH, archive_path=filename, source_file_sha256="b"*64,
            source_row_number=1, columns=list(values), values=list(values.values()))
        files.append(file)
        records.append([dict(asdict(sealed), import_file_id=file_id)])
    answers = iter([("police_identity_app", "police_identity"),
        dict(archive_sha256=runner.ARCHIVE, expected_file_count=4), files, *records])
    class Result:
        def __init__(self, value): self.value = value
        def one(self): return self.value
        def all(self): return self.value
        def mappings(self): return self
        def __iter__(self): return iter(self.value)
    class Connection:
        def begin(self): return nullcontext()
        def execute(self, query):
            if str(query).startswith("SET TRANSACTION"):
                assert "READ ONLY" in str(query)
                return Result(None)
            assert getattr(query, "is_select", False) or str(query) == "SELECT current_user, current_database()"
            return Result(next(answers))
    class Engine:
        def connect(self): return nullcontext(Connection())
        def dispose(self): pass
    monkeypatch.setattr(runner, "Settings", lambda: SimpleNamespace(host="127.0.0.1", port=5432, name="police_identity", user="police_identity_app"))
    monkeypatch.setattr(runner, "create_identity_engine", lambda _: Engine())
    monkeypatch.setattr(runner, "private_key_file", lambda _: crypto)
    monkeypatch.setattr(runner, "EXPECTED_ROWS", dict.fromkeys(HEADERS, 1))
    monkeypatch.setattr(runner, "load_source_confirmation", lambda *a, **kw: SimpleNamespace(
        confirmation_sha256=runner.CONFIRMATION, source_for=lambda _: "SRB"))
    monkeypatch.setattr(runner, "load_staged_station_index", lambda *a, **kw: (StationIndex({}, {}), {"fixture": True}))
    monkeypatch.setattr(runner, "inspected_link", lambda *a: ("EXACT_EVIDENCE_CANDIDATE", uid))
    monkeypatch.setattr(runner, "find_identifier_candidates", lambda *a: SimpleNamespace(status="SINGLE_CANDIDATE", officer_uids=(uid,)))
    monkeypatch.setattr(runner, "verified_nic_evidence", lambda *a: [dict(identifier_version_id=str(uuid4()), source_assertion_id=str(uuid4()))])
    monkeypatch.setattr("sys.argv", ["program", "--key-file", str(path), "--backup-key-file", str(tmp_path / "backup.json")])
    assert runner.main() == 0
    output = capsys.readouterr().out
    assert "TEST-NIC" not in output and str(uid) not in output
    reports = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    assert len(reports) == 4 and all(report["rows_planned"] == 1 for report in reports)
    firearm = next(report for report in reports if report["filename"] == "officer_firearms_expertise.csv")
    assert firearm["record_status_vocabulary"] == {"H1_ONLY_RECORDED": 1}
