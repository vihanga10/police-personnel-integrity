"""Read-only protected station/Sinhala reference planning and encrypted recovery; aggregate output only."""
import argparse
import json
from pathlib import Path, PurePosixPath
from sqlalchemy import select, text
from database import create_identity_engine
from settings import Settings
from app.identity.inspect_service_plans import BATCH, ARCHIVE, CONFIRMATION
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.inspect_source_coverage import require, routing_contract
from app.identity.source_coverage import SOURCES
from app.identity.station_vocabulary import HEADERS, MASTER, SINHALA, validate_recovered
from collections import Counter
from app.identity.reference_plan import ReferenceCandidates, plan_reference, validate_routing
from app.identity.reference_plan_crypto import seal_reference_plan, open_reference_plan
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.staging.models import IntakeBatch, IntakeFile, RawRecord


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
        routing_document = json.loads((repository / "docs/field-routing.json").read_text())
        routing = routing_contract(routing_document)
        validate_routing(routing_document)
        settings = Settings()
        require((settings.host, settings.port, settings.name, settings.user) ==
                ("127.0.0.1", 5432, "police_identity", "police_identity_app"), "Unexpected SQL application target.")
        engine = create_identity_engine(settings)
        recovered, recovered_metadata, registered = {}, {}, {}
        with engine.connect() as connection:
            with connection.begin():
                # Enforce read-only in PostgreSQL, not merely by CLI convention.
                connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                require(tuple(connection.execute(text("SELECT current_user, current_database()")).one()) ==
                        ("police_identity_app", "police_identity"), "Unexpected connected SQL target.")
                batch = connection.execute(select(IntakeBatch.__table__).where(IntakeBatch.batch_id == BATCH)).mappings().one()
                files = connection.execute(select(IntakeFile.__table__).where(IntakeFile.batch_id == BATCH)).mappings().all()
                names = [PurePosixPath(f["archive_path"]).name for f in files]
                require(batch["archive_sha256"] == ARCHIVE and len(files) == batch["expected_file_count"] and
                        len(names) == len(set(names)) and set(names) == set(SOURCES), "Registered source membership differs.")
                confirmation = load_source_confirmation(repository / "docs/intake-source-confirmation.json",
                    expected_batch_id=BATCH, expected_archive_sha256=ARCHIVE, expected_filenames=set(names),
                    allowed_source_codes={"PF_REGISTRY", "POLICE_HR_IS", "SRB"})
                require(confirmation.confirmation_sha256 == CONFIRMATION, "Source confirmation differs.")
                for filename, headers in HEADERS.items():
                    file = next(f for f in files if PurePosixPath(f["archive_path"]).name == filename)
                    require(confirmation.source_for(filename) == "POLICE_HR_IS", "Station supplying source differs.")
                    require(tuple(file["columns"]) == headers and set(headers) == routing[filename], "Station header/routing contract differs.")
                    if filename == MASTER:
                        require(file["expected_row_count"] == 607, "Reviewed station-master count differs.")
                    # Sinhala coverage follows its verified registration, without inventing an expected count.
                    require(file["expected_row_count"] > 0, "Station registered source is empty.")
                    rows, metadata = [], []
                    raw_ids = set()
                    query = select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"]).order_by(RawRecord.source_row_number)
                    for number, raw in enumerate(connection.execute(query).mappings(), 1):
                        require(raw["raw_record_id"] not in raw_ids, "Repeated station raw-record ID.")
                        raw_ids.add(raw["raw_record_id"])
                        stored = stored_row(raw)
                        rows.append(validate_recovered(file, raw, number, open_row(crypto, stored), open_row(backup, stored)))
                        metadata.append(dict(raw_record_id=raw["raw_record_id"], source_row_number=number))
                    require(len(rows) == file["expected_row_count"], "Station staged row coverage differs.")
                    recovered[filename], recovered_metadata[filename], registered[filename] = rows, metadata, file
                master_file = registered[MASTER]
                candidates = ReferenceCandidates([(r["raw_record_id"], row) for r, row in
                    zip(recovered_metadata[MASTER], recovered[MASTER], strict=True)])
                reports = []
                for filename in HEADERS:
                    states, statuses, issues = Counter(), Counter(), Counter()
                    review_count = 0
                    file = registered[filename]
                    for raw, row in zip(recovered_metadata[filename], recovered[filename], strict=True):
                        plan = plan_reference(filename, row, raw_record_id=raw["raw_record_id"], candidates=candidates)
                        evidence = dict(batch_id=BATCH, archive_sha256=ARCHIVE, confirmation_sha256=CONFIRMATION,
                            source_system_code="POLICE_HR_IS", import_file_id=str(file["import_file_id"]),
                            source_file_sha256=file["source_file_sha256"], source_row_number=raw["source_row_number"],
                            master_import_file_id=str(master_file["import_file_id"]), master_file_sha256=master_file["source_file_sha256"],
                            master_rows=len(recovered[MASTER]))
                        cipher, version = seal_reference_plan(crypto, plan, evidence=evidence)
                        opening = dict(key_version=version, filename=filename, raw_record_id=raw["raw_record_id"], evidence=evidence)
                        primary = open_reference_plan(crypto, cipher, **opening)
                        require(primary == open_reference_plan(backup, cipher, **opening) and primary["plan"] == plan.payload,
                            "Reference plan encrypted recovery differs.")
                        require([f["source_value"] for f in primary["plan"]["fields"]] == [row[name] for name in HEADERS[filename]],
                            "Reference plan original coverage differs.")
                        statuses.update(f["status"] for f in plan.payload["fields"])
                        issues.update(plan.payload["review_issues"])
                        issues.update(plan.payload["uncertainties"])
                        states.update(c["mode"] + ":" + c["state"] for c in plan.payload["candidate_evidence"])
                        review_count += plan.payload["needs_review"]
                    reports.append(dict(filename=filename, rows_planned=len(recovered[filename]),
                        fields_preserved=len(recovered[filename])*len(HEADERS[filename]), rows_requiring_review=review_count,
                        field_status_counts=dict(sorted(statuses.items())), issue_counts=dict(sorted(issues.items())),
                        candidate_state_counts=dict(sorted(states.items()))))
        print("Read-only station/Sinhala reference planning and encrypted recovery: PASSED")
        for report in reports:
            print(json.dumps(report, sort_keys=True, ensure_ascii=False))
        print("All original fields recovered from encrypted plans; candidate raw-row references are preserved, never accepted mappings.")
        print("The conservative bilingual rule is retained; unresolved bracket labels remain review evidence without guessed splitting.")
        print("Reported hierarchy text and coordinate ranges do not establish historical scope, CRS or location accuracy.")
        print("Reference storage/import remain pending; classification remains UNASSESSED. Stage 2 remains in progress.")
        print("No database writes, Mongo connection, saved plaintext, station values or personnel-level output.")
        return 0
    except Exception as error:
        # Driver messages may contain SQL parameters; report only the exception class.
        print("Reference planning stopped:", type(error).__name__)
        print("No writes requested; inspect without sharing credentials or original values.")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
