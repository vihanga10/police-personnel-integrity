"""Read-only history planning and primary/backup encrypted recovery; aggregate output."""
import argparse
from collections import Counter
import json
from pathlib import Path, PurePosixPath

from sqlalchemy import select, text
from database import create_identity_engine
from settings import Settings
from app.identity.history_plan import ROUTES, plan_history, validate_history_routing
from app.identity.history_plan_crypto import open_history_plan, seal_history_plan
from app.identity.inspect_history_sources import HEADERS
from app.identity.inspect_service_plans import ARCHIVE, BATCH, CONFIRMATION, verified_nic_evidence
from app.identity.candidate_lookup import find_identifier_candidates
from app.identity.normalization import normalize_identifier
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.station_reference import load_staged_station_index
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.staging.models import IntakeBatch, IntakeFile, RawRecord

EXPECTED_ROWS = {"promotion_history.csv": 13974, "transfer_history.csv": 33316}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--backup-key-file", type=Path, required=True)
    args = parser.parse_args()
    engine = None
    try:
        if args.key_file.resolve() == args.backup_key_file.resolve():
            raise ValueError("Use separate primary and backup keys.")
        crypto, backup = private_key_file(args.key_file), private_key_file(args.backup_key_file)
        verify_recovery(crypto, backup)
        repository = Path(__file__).resolve().parents[3]
        validate_history_routing(json.loads((repository / "docs/field-routing.json").read_text()))
        settings = Settings()
        if (settings.host, settings.port, settings.name, settings.user) != ("127.0.0.1", 5432, "police_identity", "police_identity_app"):
            raise ValueError("Unexpected SQL application target.")
        engine = create_identity_engine(settings)
        cache, reports = {}, []
        with engine.connect() as connection:
            with connection.begin():
                # Enforce read-only SQL and one consistent snapshot for evidence checks.
                connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                if tuple(connection.execute(text("SELECT current_user, current_database()")).one()) != ("police_identity_app", "police_identity"):
                    raise ValueError("Unexpected connected SQL target.")
                batch = connection.execute(select(IntakeBatch.__table__).where(IntakeBatch.batch_id == BATCH)).mappings().one()
                files = connection.execute(select(IntakeFile.__table__).where(IntakeFile.batch_id == BATCH)).mappings().all()
                names = {PurePosixPath(f["archive_path"]).name for f in files}
                if batch["archive_sha256"] != ARCHIVE or len(files) != batch["expected_file_count"] or len(names) != len(files):
                    raise ValueError("Registered source membership differs.")
                confirmation = load_source_confirmation(repository / "docs/intake-source-confirmation.json",
                    expected_batch_id=BATCH, expected_archive_sha256=ARCHIVE, expected_filenames=names,
                    allowed_source_codes={"PF_REGISTRY", "POLICE_HR_IS", "SRB"})
                if confirmation.confirmation_sha256 != CONFIRMATION:
                    raise ValueError("Source confirmation differs.")
                stations, station_provenance = load_staged_station_index(connection, crypto, backup, batch_id=BATCH)
                for filename in ROUTES:
                    selected = [f for f in files if PurePosixPath(f["archive_path"]).name == filename]
                    if len(selected) != 1 or confirmation.source_for(filename) != "PF_REGISTRY":
                        raise ValueError("Historical source/file contract differs.")
                    file = selected[0]
                    if tuple(file["columns"]) != HEADERS[filename] or file["expected_row_count"] != EXPECTED_ROWS[filename]:
                        raise ValueError("Historical header/count contract differs.")
                    total = review = duplicate_ids = 0
                    field_counts, issues, observations = Counter(), Counter(), Counter()
                    source_ids, officers = set(), set()
                    query = select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"]).order_by(RawRecord.source_row_number)
                    for number, raw in enumerate(connection.execute(query).mappings(), 1):
                        if raw["source_row_number"] != number or any(raw[f] != file[f] for f in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
                            raise ValueError("Historical source sequence/binding differs.")
                        original = open_row(crypto, stored_row(raw))
                        if original != open_row(backup, stored_row(raw)) or original["columns"] != file["columns"]:
                            raise ValueError("Historical source/backup recovery differs.")
                        row = dict(zip(original["columns"], original["values"], strict=True))
                        nic = normalize_identifier(row["officer_nic_no"], identifier_type="NIC")
                        digest, _ = crypto.lookup_hmac(nic.value, identifier_type="NIC")
                        # Cache only opaque lookup digests within this read-only snapshot.
                        if digest not in cache:
                            candidates = find_identifier_candidates(connection, crypto, nic)
                            if candidates.status != "SINGLE_CANDIDATE":
                                raise ValueError("Historical linkage requires explicit review.")
                            refs = verified_nic_evidence(connection, crypto, backup, nic, candidates)
                            if not refs:
                                raise ValueError("No usable exact historical NIC candidate evidence.")
                            cache[digest] = (candidates.officer_uids[0], sorted(refs, key=lambda ref: ref["identifier_version_id"]))
                        officer, identifier_refs = cache[digest]
                        plan = plan_history(filename, row, officer_uid=officer, station_candidates=stations.candidates)
                        references = dict(history_source=dict(batch_id=BATCH, raw_record_id=raw["raw_record_id"],
                            import_file_id=str(raw["import_file_id"]), source_file_sha256=raw["source_file_sha256"], source_row_number=number,
                            reported_source_system_code="PF_REGISTRY", confirmation_sha256=CONFIRMATION),
                            identifier_evidence=identifier_refs, station_source=station_provenance, station_matches={})
                        for item in plan.fields:
                            if item.source_column in {"from_station_code", "to_station_code"} and item.status == "PARSED":
                                references["station_matches"][item.source_column] = dict(station_code=item.value,
                                    raw_record_id=stations.source_rows[item.value], historical_applicability="UNKNOWN")
                        # Exercise primary and backup recovery in memory; never save plaintext.
                        cipher, version = seal_history_plan(crypto, plan, raw_record_id=raw["raw_record_id"], reference_evidence=references)
                        binding = dict(key_version=version, filename=filename, officer_uid=officer, raw_record_id=raw["raw_record_id"])
                        primary = open_history_plan(crypto, cipher, **binding)
                        if open_history_plan(backup, cipher, **binding) != primary:
                            raise ValueError("Historical encrypted plan backup differs.")
                        total += 1
                        review += plan.needs_review
                        officers.add(officer)
                        key = row["transfer_id" if filename == "transfer_history.csv" else "promotion_id"].strip()
                        if key:
                            duplicate_ids += key in source_ids
                            source_ids.add(key)
                        for item in plan.fields:
                            field_counts[item.status] += 1
                            for issue in item.issues:
                                issues[item.source_column + ":" + issue] += 1
                        for issue in plan.review_issues + plan.uncertainties:
                            issues[issue] += 1
                        observations.update(plan.observations)
                    if total != EXPECTED_ROWS[filename]:
                        raise ValueError("Historical planned row coverage differs.")
                    reports.append(dict(filename=filename, rows_planned=total, fields_assessed=total * len(HEADERS[filename]),
                        rows_requiring_structural_review=review, distinct_candidate_officers=len(officers), duplicate_source_ids=duplicate_ids,
                        field_status_counts=dict(field_counts), issue_counts=dict(sorted(issues.items())), chronology_and_cancellation_observations=dict(sorted(observations.items()))))
        print("Read-only historical planning and encrypted recovery: PASSED")
        for report in reports:
            print(json.dumps(report, sort_keys=True))
        print("Planning success is not import readiness, accepted historical linkage, authority verification or source truth.")
        print("Reported dates, cancellations and unit labels remain claims; classification stays UNASSESSED.")
        print("No database writes, Mongo connection, saved plaintext plans or personnel-level output.")
        return 0
    except Exception as error:
        print("Historical planning stopped:", type(error).__name__)
        if type(error) is ValueError:
            print(str(error))
        print("No database writes requested.")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
