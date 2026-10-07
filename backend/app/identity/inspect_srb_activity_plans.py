"""Read-only inspection of staged SRB duties, firearms and conduct evidence; aggregate output only.

No Mongo connection, evidence writes, classification or authority determination.
Date shapes are observations, never a source date-order/effective-time policy.
"""
import argparse
from collections import Counter
from datetime import date
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path, PurePosixPath

from sqlalchemy import select, text
from database import create_identity_engine
from settings import Settings
from app.identity.inspect_service_plans import ARCHIVE, BATCH, CONFIRMATION
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.service_values import RANKS
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.staging.models import IntakeBatch, IntakeFile, RawRecord

from app.identity.inspect_history_sources import date_shape, inspected_link, KNOWN_BOOLEAN_TEXT
from app.identity.inspect_srb_sources import interval_observation

from app.identity.inspect_srb_activity_sources import HEADERS, SOURCE_KEYS, ACTOR_FIELDS
from app.identity.srb_activity_plan import plan_activity, validate_activity_routing, status_vocabulary
from app.identity.srb_activity_plan_crypto import seal_activity_plan, open_activity_plan
from app.identity.station_reference import load_staged_station_index
from app.identity.candidate_lookup import find_identifier_candidates
from app.identity.inspect_service_plans import verified_nic_evidence
from app.identity.normalization import normalize_identifier

EXPECTED_ROWS = {"officer_duty_periods.csv": 3138, "officer_firearms_expertise.csv": 30348,
                 "good_conduct_register.csv": 2779, "bad_conduct_register.csv": 370}


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
        settings = Settings()
        if (settings.host, settings.port, settings.name, settings.user) != ("127.0.0.1", 5432, "police_identity", "police_identity_app"):
            raise ValueError("Unexpected SQL application target.")
        engine = create_identity_engine(settings)
        reports, cache, subject_evidence = [], {}, {}
        with engine.connect() as connection:
            with connection.begin():
                # One consistent read-only snapshot; never repair records during inspection.
                connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                if tuple(connection.execute(text("SELECT current_user, current_database()")).one()) != ("police_identity_app", "police_identity"):
                    raise ValueError("Unexpected connected SQL target.")
                batch = connection.execute(select(IntakeBatch.__table__).where(IntakeBatch.batch_id == BATCH)).mappings().one()
                files = connection.execute(select(IntakeFile.__table__).where(IntakeFile.batch_id == BATCH)).mappings().all()
                names = {PurePosixPath(f["archive_path"]).name for f in files}
                if batch["archive_sha256"] != ARCHIVE or len(files) != batch["expected_file_count"] or len(names) != len(files):
                    raise ValueError("Registered source membership differs.")
                repository = Path(__file__).resolve().parents[3]
                confirmation = load_source_confirmation(repository / "docs/intake-source-confirmation.json",
                    expected_batch_id=BATCH, expected_archive_sha256=ARCHIVE, expected_filenames=names,
                    allowed_source_codes={"PF_REGISTRY", "POLICE_HR_IS", "SRB"})
                if confirmation.confirmation_sha256 != CONFIRMATION:
                    raise ValueError("Source confirmation differs.")
                validate_activity_routing(json.loads((repository / "docs/field-routing.json").read_text()))
                stations, station_provenance = load_staged_station_index(connection, crypto, backup, batch_id=BATCH)
                for filename, header in HEADERS.items():
                    selected = [f for f in files if PurePosixPath(f["archive_path"]).name == filename]
                    if len(selected) != 1 or confirmation.source_for(filename) != "SRB":
                        raise ValueError("SRB source/file contract differs.")
                    file = selected[0]
                    if tuple(file["columns"]) != header or file["expected_row_count"] != EXPECTED_ROWS[filename]:
                        raise ValueError("SRB header order/content differs.")
                    field_counts, issues, observations, status_labels = (Counter() for _ in range(4))
                    source_ids, officer_rows = set(), Counter()
                    duplicates = total = reviews = 0
                    identifier_field = SOURCE_KEYS[filename]
                    missing_keys = 0
                    query = select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"]).order_by(RawRecord.source_row_number)
                    for number, raw in enumerate(connection.execute(query).mappings(), 1):
                        if raw["source_row_number"] != number or any(raw[f] != file[f] for f in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
                            raise ValueError("SRB source sequence/binding differs.")
                        original = open_row(crypto, stored_row(raw))
                        if original != open_row(backup, stored_row(raw)) or original["columns"] != file["columns"]:
                            raise ValueError("SRB header/backup recovery differs.")
                        row = dict(zip(original["columns"], original["values"], strict=True))
                        total += 1
                        sid = row[identifier_field].strip()
                        if not sid or sid in source_ids:
                            raise ValueError("Repeated or missing source key requires review.")
                        source_ids.add(sid)
                        state, officer = inspected_link(connection, crypto, backup, row["officer_nic_no"], cache)
                        if state != "EXACT_EVIDENCE_CANDIDATE":
                            raise ValueError("Activity subject identity requires review.")
                        officer_rows[officer] += 1
                        # Exact encrypted NIC evidence is retained separately from authority claims.
                        nic = normalize_identifier(row["officer_nic_no"], identifier_type="NIC")
                        digest, _ = crypto.lookup_hmac(nic.value, identifier_type="NIC")
                        if digest not in subject_evidence:
                            candidates = find_identifier_candidates(connection, crypto, nic)
                            if candidates.status != "SINGLE_CANDIDATE" or candidates.officer_uids != (officer,):
                                raise ValueError("Activity subject linkage differs.")
                            refs = verified_nic_evidence(connection, crypto, backup, nic, candidates)
                            if not refs:
                                raise ValueError("No usable encrypted NIC evidence.")
                            subject_evidence[digest] = sorted(refs, key=lambda ref: ref["identifier_version_id"])
                        actors, actor_refs = {}, {}
                        for name in ACTOR_FIELDS[filename]:
                            if row[name].strip():
                                actor_state, uid = inspected_link(connection, crypto, backup, row[name], cache)
                                actor_refs[name] = dict(candidate_state=actor_state, officer_uid=str(uid) if uid else None)
                                if actor_state == "EXACT_EVIDENCE_CANDIDATE":
                                    actors[name] = uid
                        plan = plan_activity(filename, row, officer_uid=officer, actor_candidates=actors, station_candidates=stations.candidates)
                        references = dict(activity_source=dict(batch_id=BATCH, raw_record_id=raw["raw_record_id"],
                            import_file_id=str(file["import_file_id"]), source_file_sha256=file["source_file_sha256"],
                            source_row_number=number, reported_source_system_code="SRB", confirmation_sha256=CONFIRMATION),
                            identifier_evidence=subject_evidence[digest], actor_candidates=actor_refs,
                            station_source=station_provenance, station_matches={})
                        # Only explicit source-scoped station candidates are included; no historical acceptance.
                        for name in ("period_station_code", "gun_performance_station_code", "current_station_code"):
                            code = row.get(name, "").strip()
                            if code in stations.source_rows:
                                references["station_matches"][name] = dict(station_code=code,
                                    raw_record_id=stations.source_rows[code], historical_applicability="UNKNOWN")
                        cipher, version = seal_activity_plan(crypto, plan, raw_record_id=raw["raw_record_id"], reference_evidence=references)
                        opening = dict(key_version=version, filename=filename, officer_uid=officer, raw_record_id=raw["raw_record_id"])
                        payload = open_activity_plan(crypto, cipher, **opening)
                        if open_activity_plan(backup, cipher, **opening) != payload:
                            raise ValueError("Activity encrypted recovery differs.")
                        reviews += plan.needs_review
                        for item in plan.fields:
                            field_counts[item.status] += 1
                            for issue in item.issues:
                                issues[item.source_column + ":" + issue] += 1
                        issues.update(plan.review_issues)
                        issues.update(plan.uncertainties)
                        observations.update(plan.observations)
                        if filename == "officer_firearms_expertise.csv":
                            status_labels[status_vocabulary(row["record_status"])] += 1
                    if total != file["expected_row_count"]:
                        raise ValueError("SRB registered row count differs.")
                    reports.append(dict(filename=filename, rows_planned=total, fields_assessed=total * len(header),
                        distinct_candidate_officers=len(officer_rows), rows_requiring_structural_review=reviews,
                        field_status_counts=dict(field_counts), issue_counts=dict(sorted(issues.items())),
                        observations=dict(sorted(observations.items())), record_status_vocabulary=dict(sorted(status_labels.items()))))
        print("Read-only SRB activity planning and encrypted recovery: PASSED")
        for report in reports:
            print(json.dumps(report, sort_keys=True))
        print("Planning success is not import readiness; structural review rows require separate assessment.")
        print("Reported ranks, signatures, scores, conduct outcomes and references are claims, not verified authority, competency or legal effect.")
        print("CID/CCIB labels are source claims; historical assignment, authority, reference linkage and date semantics remain unassessed.")
        print("No database writes, Mongo connection, saved plaintext, personnel-level output or classification changes.")
        return 0
    except Exception as error:
        print("SRB activity planning stopped:", type(error).__name__)
        print("No database writes requested.")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
