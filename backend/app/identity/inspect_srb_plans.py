"""Read-only SRB planning and primary/backup encrypted recovery; aggregate output."""
import argparse
from collections import Counter
import json
from pathlib import Path, PurePosixPath

from sqlalchemy import select, text
from database import create_identity_engine
from settings import Settings
from app.identity.srb_plan import ROUTES, plan_srb, validate_srb_routing
from app.identity.srb_plan_crypto import open_srb_plan, seal_srb_plan
from app.identity.inspect_srb_sources import HEADERS, SOURCE_KEYS
from app.identity.inspect_history_sources import HEADERS as HISTORY_HEADERS, inspected_link
from app.identity.srb_plan import SourceReference, ACTORS, bounded_intersection_count
from datetime import date
from app.identity.inspect_service_plans import ARCHIVE, BATCH, CONFIRMATION, verified_nic_evidence
from app.identity.candidate_lookup import find_identifier_candidates
from app.identity.normalization import normalize_identifier
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.station_reference import load_staged_station_index
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.staging.models import IntakeBatch, IntakeFile, RawRecord

EXPECTED_ROWS = {"officer_police_numbers.csv": 15123, "officer_restrictions.csv": 10971, "restriction_overrides.csv": 150}


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
        validate_srb_routing(json.loads((repository / "docs/field-routing.json").read_text()))
        settings = Settings()
        if (settings.host, settings.port, settings.name, settings.user) != ("127.0.0.1", 5432, "police_identity", "police_identity_app"):
            raise ValueError("Unexpected SQL application target.")
        engine = create_identity_engine(settings)
        cache, reports, actor_cache = {}, [], {}
        with engine.connect() as connection:
            with connection.begin():
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
                def recovered_rows(filename, expected_source, header, count):
                    # Recheck file/row provenance before building any in-memory link index.
                    selected = [f for f in files if PurePosixPath(f["archive_path"]).name == filename]
                    if len(selected) != 1 or confirmation.source_for(filename) != expected_source:
                        raise ValueError("Reference source contract differs.")
                    file = selected[0]
                    if tuple(file["columns"]) != header or file["expected_row_count"] != count:
                        raise ValueError("Reference header/count differs.")
                    query = select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"]).order_by(RawRecord.source_row_number)
                    total = 0
                    for number, raw in enumerate(connection.execute(query).mappings(), 1):
                        if raw["source_row_number"] != number or any(raw[f] != file[f] for f in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
                            raise ValueError("Reference row provenance differs.")
                        original = open_row(crypto, stored_row(raw))
                        if original != open_row(backup, stored_row(raw)) or original["columns"] != file["columns"]:
                            raise ValueError("Reference backup/header recovery differs.")
                        total += 1
                        yield raw, dict(zip(original["columns"], original["values"], strict=True))
                    if total != count:
                        raise ValueError("Reference row coverage differs.")

                # Match source-qualified IDs and subject candidates, not inferred authority.
                reference_index = {"restriction_id": {}, "transfer_id": {}}
                for filename, source, key, header, count in (
                    ("officer_restrictions.csv", "SRB", "restriction_id", HEADERS["officer_restrictions.csv"], 10971),
                    ("transfer_history.csv", "PF_REGISTRY", "transfer_id", HISTORY_HEADERS["transfer_history.csv"], 33316),
                ):
                    for raw, row in recovered_rows(filename, source, header, count):
                        state, officer = inspected_link(connection, crypto, backup, row["officer_nic_no"], actor_cache)
                        if state != "EXACT_EVIDENCE_CANDIDATE":
                            raise ValueError("Reference subject candidate requires review.")
                        key_value = row[key].strip()
                        if key_value:
                            reference_index[key].setdefault(key_value, []).append(SourceReference(filename, raw["raw_record_id"], officer))
                override_subject_index = {}
                for raw, row in recovered_rows("restriction_overrides.csv", "SRB", HEADERS["restriction_overrides.csv"], 150):
                    state, officer = inspected_link(connection, crypto, backup, row["officer_nic_no"], actor_cache)
                    if state != "EXACT_EVIDENCE_CANDIDATE":
                        raise ValueError("Override subject candidate requires review.")
                    key = row["restriction_id"].strip()
                    if key:
                        override_subject_index.setdefault(key, []).append(officer)
                for filename in ROUTES:
                    selected = [f for f in files if PurePosixPath(f["archive_path"]).name == filename]
                    if len(selected) != 1 or confirmation.source_for(filename) != "SRB":
                        raise ValueError("SRB source/file contract differs.")
                    file = selected[0]
                    if tuple(file["columns"]) != HEADERS[filename] or file["expected_row_count"] != EXPECTED_ROWS[filename]:
                        raise ValueError("SRB header/count contract differs.")
                    total = review = duplicate_ids = 0
                    field_counts, issues, observations = Counter(), Counter(), Counter()
                    source_ids, officers = set(), set()
                    bounded_numbers = {}
                    query = select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"]).order_by(RawRecord.source_row_number)
                    for number, raw in enumerate(connection.execute(query).mappings(), 1):
                        if raw["source_row_number"] != number or any(raw[f] != file[f] for f in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
                            raise ValueError("SRB source sequence/binding differs.")
                        original = open_row(crypto, stored_row(raw))
                        if original != open_row(backup, stored_row(raw)) or original["columns"] != file["columns"]:
                            raise ValueError("SRB source/backup recovery differs.")
                        row = dict(zip(original["columns"], original["values"], strict=True))
                        nic = normalize_identifier(row["officer_nic_no"], identifier_type="NIC")
                        digest, _ = crypto.lookup_hmac(nic.value, identifier_type="NIC")
                        if digest not in cache:
                            candidates = find_identifier_candidates(connection, crypto, nic)
                            if candidates.status != "SINGLE_CANDIDATE":
                                raise ValueError("SRB linkage requires explicit review.")
                            refs = verified_nic_evidence(connection, crypto, backup, nic, candidates)
                            if not refs:
                                raise ValueError("No usable exact SRB NIC candidate evidence.")
                            cache[digest] = (candidates.officer_uids[0], sorted(refs, key=lambda ref: ref["identifier_version_id"]))
                        officer, identifier_refs = cache[digest]
                        actor_candidates, actor_evidence = {}, {}
                        for name in ACTORS & row.keys():
                            if row[name].strip():
                                state, candidate = inspected_link(connection, crypto, backup, row[name], actor_cache)
                                actor_evidence[name] = dict(candidate_state=state, officer_uid=str(candidate) if candidate else None)
                                if state == "EXACT_EVIDENCE_CANDIDATE":
                                    actor_candidates[name] = candidate
                        reference_candidates = {key: tuple(reference_index[key].get(row[key].strip(), ()))
                            for key in ("restriction_id", "transfer_id") if filename == "restriction_overrides.csv"}
                        plan = plan_srb(filename, row, officer_uid=officer, station_candidates=stations.candidates,
                            actor_candidates=actor_candidates, reference_candidates=reference_candidates,
                            linked_override_subjects=override_subject_index.get(row["restriction_id"].strip(), ()) if filename == "officer_restrictions.csv" else None)
                        references = dict(srb_source=dict(batch_id=BATCH, raw_record_id=raw["raw_record_id"],
                            import_file_id=str(raw["import_file_id"]), source_file_sha256=raw["source_file_sha256"], source_row_number=number,
                            reported_source_system_code="SRB", confirmation_sha256=CONFIRMATION),
                            identifier_evidence=identifier_refs, actor_candidates=actor_evidence,
                            source_reference_candidates={key: [dict(filename=r.filename, raw_record_id=r.raw_record_id, officer_uid=str(r.officer_uid)) for r in refs] for key, refs in reference_candidates.items()},
                            station_source=station_provenance, station_matches={})
                        for item in plan.fields:
                            if item.source_column in {"restricted_station_code"} and item.status == "PARSED":
                                references["station_matches"][item.source_column] = dict(station_code=item.value,
                                    raw_record_id=stations.source_rows[item.value], historical_applicability="UNKNOWN")
                        cipher, version = seal_srb_plan(crypto, plan, raw_record_id=raw["raw_record_id"], reference_evidence=references)
                        binding = dict(key_version=version, filename=filename, officer_uid=officer, raw_record_id=raw["raw_record_id"])
                        primary = open_srb_plan(crypto, cipher, **binding)
                        if open_srb_plan(backup, cipher, **binding) != primary:
                            raise ValueError("SRB encrypted plan backup differs.")
                        total += 1
                        review += plan.needs_review
                        officers.add(officer)
                        key = row[SOURCE_KEYS[filename]].strip()
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
                        if filename == "officer_police_numbers.csv":
                            values = {f.source_column: f.value for f in plan.fields}
                            start, end = values["valid_from"], values["valid_to"]
                            if type(start) is date and type(end) is date and end > start:
                                bounded_numbers.setdefault((officer, row["number_type"].strip()), []).append((start, end))
                    if total != EXPECTED_ROWS[filename]:
                        raise ValueError("SRB planned row coverage differs.")
                    # Only explicit bounded dates are compared. Missing ends are never infinity;
                    # same-day boundary contact is not called an overlap without endpoint policy.
                    for periods in bounded_numbers.values():
                        count = bounded_intersection_count(periods)
                        if count:
                            observations["REPORTED_BOUNDED_NUMBER_PERIOD_INTERSECTION"] += count
                    reports.append(dict(filename=filename, rows_planned=total, fields_assessed=total * len(HEADERS[filename]),
                        rows_requiring_structural_review=review, distinct_candidate_officers=len(officers), duplicate_source_ids=duplicate_ids,
                        field_status_counts=dict(field_counts), issue_counts=dict(sorted(issues.items())), source_consistency_observations=dict(sorted(observations.items()))))
        print("Read-only SRB planning and encrypted recovery: PASSED")
        for report in reports:
            print(json.dumps(report, sort_keys=True))
        print("Planning success is not import readiness, accepted historical linkage, authority verification or source truth.")
        print("Reported dates, number validity, restrictions and overrides remain claims; classification stays UNASSESSED.")
        print("No database writes, Mongo connection, saved plaintext plans or personnel-level output.")
        return 0
    except Exception as error:
        print("SRB planning stopped:", type(error).__name__)
        if type(error) is ValueError:
            print(str(error))
        print("No database writes requested.")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
