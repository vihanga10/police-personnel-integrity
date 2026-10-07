"""Read-only Stage 2 source/SQL receipt coverage and reported-reference inventory.

No Mongo connection, writes, saved plaintext, accepted linkage or classification.
Existing per-import encrypted reconciliation remains a separate check.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path, PurePosixPath
from sqlalchemy import select, text
from database import create_identity_engine
from settings import Settings
from app.identity.inspect_service_plans import BATCH, ARCHIVE, CONFIRMATION
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.profile_records import WRITER_POLICY as PROFILE_POLICY
from app.identity.source_coverage import POLICY, ROWS, REFERENCES, SOURCES, ASSERTIONS, ReferenceInventory, receipt_coverage
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.models import (SourceAssertion, SourceSystem, RemainingSourceAssertion, ProfileTransformReceipt,
    FamilyTransformReceipt, ServiceDeliveryPreparation, ServiceDeliveryCompletion, HistoryDeliveryPreparation,
    HistoryDeliveryCompletion, SrbDeliveryPreparation, SrbDeliveryCompletion, ActivityDeliveryPreparation,
    ActivityDeliveryCompletion, RemainingDeliveryPreparation, RemainingDeliveryCompletion)


def require(condition, message):
    if not condition: raise ValueError(message)


def routing_contract(document):
    """All nineteen received files must retain every original field in staging."""
    files = document.get("files", [])
    names = [f["filename"] for f in files]
    require(len(names) == len(set(names)) and set(names) == set(SOURCES), "Routing file membership differs.")
    result = {}
    for file in files:
        columns = [f["source_column"] for f in file["fields"]]
        require(len(columns) == len(set(columns)) and all(f.get("preserve_in_protected_staging") is True for f in file["fields"]), "Routing field preservation differs.")
        result[file["filename"]] = set(columns)
    return result


def load_receipts(connection):
    """Read opaque SQL receipt/preparation metadata, never sealed document payloads."""
    result, referenced = [], set()
    for model, policy in ((ProfileTransformReceipt, PROFILE_POLICY), (FamilyTransformReceipt, "HR_FAMILY_WRITER_V1")):
        table = model.__table__
        for row in connection.execute(select(table.c.raw_record_id, table.c.source_assertion_id,
            table.c.confirmation_sha256, table.c.policy_version)).mappings():
            require(row["confirmation_sha256"] == CONFIRMATION and row["policy_version"] == policy, "Receipt policy/confirmation differs.")
            result.append(dict(raw_record_id=row["raw_record_id"], assertion_id=row["source_assertion_id"], complete=True,
                group="PROFILE" if model is ProfileTransformReceipt else "FAMILY"))
            referenced.add(row["source_assertion_id"])
    pipelines = (
        (ServiceDeliveryPreparation, ServiceDeliveryCompletion, "SERVICE"),
        (HistoryDeliveryPreparation, HistoryDeliveryCompletion, "HISTORY"),
        (SrbDeliveryPreparation, SrbDeliveryCompletion, "SRB"),
        (ActivityDeliveryPreparation, ActivityDeliveryCompletion, "ACTIVITY"),
        (RemainingDeliveryPreparation, RemainingDeliveryCompletion, "REMAINING"),
    )
    for preparation, completion, group in pipelines:
        prep, done = preparation.__table__, completion.__table__
        completions = {r["delivery_id"]: r["document_sha256"] for r in connection.execute(select(done.c.delivery_id, done.c.document_sha256)).mappings()}
        seen = set()
        for row in connection.execute(select(prep.c.delivery_id, prep.c.raw_record_id, prep.c.source_assertion_id,
            prep.c.confirmation_sha256, prep.c.document_sha256)).mappings():
            require(row["confirmation_sha256"] == CONFIRMATION, "Preparation confirmation differs.")
            digest = completions.get(row["delivery_id"])
            require(digest is None or digest == row["document_sha256"], "Completion/preparation digest differs.")
            seen.add(row["delivery_id"]); referenced.add(row["source_assertion_id"])
            result.append(dict(raw_record_id=row["raw_record_id"], assertion_id=row["source_assertion_id"], complete=digest is not None, group=group))
        require(set(completions) <= seen, "Completion has no SQL preparation.")
    return result, referenced


def load_assertions(connection):
    """Load provenance columns only; the payload is not needed for row coverage."""
    sources = dict(connection.execute(select(SourceSystem.source_system_id, SourceSystem.source_system_code)).all())
    assertions = {}
    for model in (SourceAssertion, RemainingSourceAssertion):
        t = model.__table__
        columns = [t.c[n] for n in ("source_assertion_id", "raw_record_id", "source_file_name", "source_system_id", "source_file_sha256",
            "source_row_number", "intake_batch_id", "import_file_id", "assertion_type")]
        for row in connection.execute(select(*columns).where(t.c.assertion_type.in_(list(ASSERTIONS.values())))).mappings():
            require(row["source_assertion_id"] not in assertions, "Assertion ID duplicated across stores.")
            assertions[row["source_assertion_id"]] = dict(row, source_code=sources.get(row["source_system_id"]))
    return assertions


def validate_receipt_provenance(receipt, assertion, raw):
    """A matching row count cannot conceal a receipt bound to another source row."""
    filename = raw["filename"]
    expected_group = "PROFILE" if filename == "officer_personal_information.csv" else "FAMILY" if filename == "officer_family_details.csv" else "SERVICE" if filename == "officer_service_information.csv" else "HISTORY" if filename in {"transfer_history.csv", "promotion_history.csv"} else "SRB" if filename in {"officer_police_numbers.csv", "officer_restrictions.csv", "restriction_overrides.csv"} else "ACTIVITY" if filename in {"officer_duty_periods.csv", "officer_firearms_expertise.csv", "good_conduct_register.csv", "bad_conduct_register.csv"} else "REMAINING"
    require(filename in ROWS and receipt["group"] == expected_group, "Receipt pipeline/source differs.")
    expected = dict(raw_record_id=receipt["raw_record_id"], source_file_name=filename, source_code=SOURCES[filename],
        source_file_sha256=raw["source_file_sha256"], source_row_number=raw["source_row_number"], intake_batch_id=BATCH,
        import_file_id=str(raw["import_file_id"]), assertion_type=ASSERTIONS[filename])
    require(all(assertion.get(k) == v for k, v in expected.items()), "Receipt assertion provenance differs.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--backup-key-file", type=Path, required=True)
    args = parser.parse_args()
    engine = None
    try:
        require(args.key_file.resolve() != args.backup_key_file.resolve(), "Separate primary and backup keys required.")
        crypto, backup = private_key_file(args.key_file), private_key_file(args.backup_key_file)
        verify_recovery(crypto, backup)
        repository = Path(__file__).resolve().parents[3]
        routing = routing_contract(json.loads((repository / "docs/field-routing.json").read_text()))
        settings = Settings()
        require((settings.host, settings.port, settings.name, settings.user) == ("127.0.0.1", 5432, "police_identity", "police_identity_app"), "Unexpected SQL application target.")
        engine = create_identity_engine(settings)
        inventory = ReferenceInventory(crypto)
        reports, raw_sources, source_ids, grouped = [], {}, defaultdict(set), defaultdict(list)
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                require(tuple(connection.execute(text("SELECT current_user, current_database()")).one()) == ("police_identity_app", "police_identity"), "Unexpected connected SQL target.")
                batch = connection.execute(select(IntakeBatch.__table__).where(IntakeBatch.batch_id == BATCH)).mappings().one()
                files = connection.execute(select(IntakeFile.__table__).where(IntakeFile.batch_id == BATCH)).mappings().all()
                names = [PurePosixPath(f["archive_path"]).name for f in files]
                require(batch["archive_sha256"] == ARCHIVE and len(files) == batch["expected_file_count"] and len(names) == len(set(names)) and set(names) == set(SOURCES), "Registered source membership differs.")
                confirmation = load_source_confirmation(repository / "docs/intake-source-confirmation.json", expected_batch_id=BATCH,
                    expected_archive_sha256=ARCHIVE, expected_filenames=set(names), allowed_source_codes={"PF_REGISTRY", "POLICE_HR_IS", "SRB"})
                require(confirmation.confirmation_sha256 == CONFIRMATION, "Source confirmation differs.")
                for file in sorted(files, key=lambda f: f["archive_path"]):
                    filename = PurePosixPath(file["archive_path"]).name
                    require(confirmation.source_for(filename) == SOURCES[filename], "Supplying source differs.")
                    require(len(file["columns"]) == len(set(file["columns"])) and set(file["columns"]) == routing[filename], "Registered header/routing coverage differs.")
                    if filename in ROWS: require(file["expected_row_count"] == ROWS[filename], "Reviewed business-file row count differs.")
                    if filename == "station_master.csv": require(file["expected_row_count"] == 607, "Reviewed station-master count differs.")
                    rows = connection.execute(select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"])
                        .order_by(RawRecord.source_row_number).execution_options(yield_per=500)).mappings()
                    count = 0
                    for count, raw in enumerate(rows, 1):
                        require(raw["source_row_number"] == count and all(raw[k] == file[k] for k in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")), "Staged row sequence/provenance differs.")
                        original = open_row(crypto, stored_row(raw))
                        require(original == open_row(backup, stored_row(raw)) and original["columns"] == file["columns"], "Staged row/header recovery differs.")
                        values = dict(zip(original["columns"], original["values"], strict=True))
                        require(all(isinstance(v, str) for v in values.values()), "Original source values must remain text.")
                        inventory.add(filename, values)
                        rid = raw["raw_record_id"]
                        require(rid not in raw_sources, "Repeated raw-record ID.")
                        raw_sources[rid] = dict(filename=filename, source_file_sha256=raw["source_file_sha256"], source_row_number=count, import_file_id=raw["import_file_id"])
                        source_ids[filename].add(rid)
                    require(count == file["expected_row_count"], "Staged row count differs.")
                    print("Source recovery progress:", filename, "| rows=", count, flush=True)
                receipts, referenced = load_receipts(connection)
                assertions = load_assertions(connection)
                require(set(assertions) == referenced, "Orphan imported assertion or receipt detected.")
                for receipt in receipts:
                    raw = raw_sources.get(receipt["raw_record_id"])
                    require(raw is not None, "Receipt outside reviewed batch.")
                    assertion = assertions.get(receipt["assertion_id"])
                    require(assertion is not None, "Receipt assertion missing.")
                    validate_receipt_provenance(receipt, assertion, raw)
                    grouped[raw["filename"]].append(receipt)
                for filename in sorted(SOURCES):
                    coverage = receipt_coverage(source_ids[filename], grouped[filename])
                    if filename in REFERENCES:
                        require(not grouped[filename], "Reference file unexpectedly routed through a personnel writer.")
                        report = dict(filename=filename, reported_source=SOURCES[filename], staged_rows=coverage["staged_rows"],
                            storage_status="ENCRYPTED_STAGING_ONLY", normalized_reference_storage="PENDING", historical_applicability="UNKNOWN")
                    else: report = dict(filename=filename, reported_source=SOURCES[filename], **coverage)
                    reports.append(report)
        print("Read-only source/reference coverage report:")
        for report in reports: print(json.dumps(report, sort_keys=True))
        print(json.dumps(inventory.report(), sort_keys=True, ensure_ascii=False))
        complete = all(r.get("missing_rows", 0) == r.get("incomplete_rows", 0) == r.get("unexpected_rows", 0) == r.get("duplicate_rows", 0) == 0 for r in reports)
        print("Personnel SQL receipt coverage:", "PASSED" if complete else "REVIEW_REQUIRED")
        print("Registered files:", len(reports), "| personnel files:", len(ROWS), "| reference files:", len(REFERENCES))
        print("Normalized station/Sinhala reference storage remains pending; Sinhala row count follows verified registration.")
        print("Reported key matches are candidates, not accepted linkage, authority, periods or source truth.")
        print("linked_case_no target remains provisional; NPC/HRC mentions are not independently received sources.")
        print("No Mongo connection or fresh Mongo reconciliation; existing import reconciliation is separate.")
        print("No database writes, saved plaintext, personnel values or classification changes. Stage 2 remains in progress.")
        return 0 if complete else 1
    except Exception as error:
        print("Source/reference coverage stopped:", type(error).__name__)
        if isinstance(error, ValueError): print(str(error))
        print("No writes requested; inspect the failure without sharing personnel values or credentials.")
        return 1
    finally:
        if engine is not None: engine.dispose()


if __name__ == "__main__": raise SystemExit(main())
