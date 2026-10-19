"""Read-only inspection of staged SRB activity vocabulary and conditional field blocks; aggregate output only.

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

from app.identity.inspect_srb_activity_sources import HEADERS as ACTIVITY_HEADERS, SOURCE_KEYS

FILENAMES = ("officer_duty_periods.csv", "officer_firearms_expertise.csv", "good_conduct_register.csv")
HEADERS = {name: ACTIVITY_HEADERS[name] for name in FILENAMES}
EXPECTED_ROWS = dict(zip(FILENAMES, (3138, 30348, 2779)))
RANK_FIELDS = {
    "officer_duty_periods.csv": ("period_recorded_by_authority_rank",),
    "officer_firearms_expertise.csv": ("h1_supervisor_police_rank", "h2_supervisor_police_rank", "annual_supervisor_police_rank"),
    "good_conduct_register.csv": (),
}
# These tokens may be observed, but are not automatically accepted rank mappings.
RANK_TOKENS = frozenset({"IGP", "SDIG", "DIG", "SSP", "SP", "ASP", "CIP", "CI", "IP", "SI", "PC", "PS",
    "Inspector", "Chief Inspector", "Assistant Superintendent", "Superintendent", "Senior Superintendent",
    "Deputy Inspector General", "Senior Deputy Inspector General", "Inspector General of Police",
    "Police Sergeant", "Police Constable", "Sergeant", "Constable"})
BOOLEAN_TOKENS = frozenset({"TRUE", "FALSE", "True", "False", "true", "false", "YES", "NO", "Yes", "No", "yes", "no", "Y", "N", "1", "0"})
STATUS_TOKENS = frozenset({"COMPLETE", "COMPLETED", "INCOMPLETE", "PENDING", "H1_ONLY", "H2_PENDING", "PARTIAL", "FULL_YEAR",
    "Complete", "Completed", "Incomplete", "Pending", "complete", "completed", "incomplete", "pending"})
H2_CORE = ("h2_weapons_fired", "h2_weapon_names", "h2_weapon_rating", "h2_total_points", "h2_practice_date",
           "h2_supervisor_nic", "h2_supervisor_police_rank", "h2_supervisor_police_name")


def rank_label(value):
    """Emit only predefined rank vocabulary, never arbitrary labels or names."""
    text = value.strip()
    return text if text in RANKS or text in RANK_TOKENS else "MISSING" if not text else "UNREVIEWED_TEXT"


def boolean_label(value):
    """Observe exact spelling; no automatic boolean conversion is applied."""
    text = value.strip()
    return text if text in BOOLEAN_TOKENS else "MISSING" if not text else "OTHER_TEXT"


def status_label(value):
    text = value.strip()
    return text if text in STATUS_TOKENS else "MISSING" if not text else "OTHER_REPORTED_STATUS"


def h2_shape(row):
    """Missing blocks are observations, not claims that H2 was unnecessary."""
    populated = sum(bool(row[name].strip()) for name in H2_CORE)
    return "ALL_CORE_MISSING" if populated == 0 else "ALL_CORE_PRESENT" if populated == len(H2_CORE) else "PARTIAL_CORE"


def total_observation(row):
    """Compare explicitly reported numbers without replacing a missing H2 by zero."""
    shape = h2_shape(row)
    names = ("h1_total_points", "year_total_points") if shape == "ALL_CORE_MISSING" else ("h1_total_points", "h2_total_points", "year_total_points")
    try:
        numbers = [Decimal(row[name].strip()) for name in names]
        if not all(n.is_finite() for n in numbers):
            return "UNCOMPARABLE_TOTALS"
    except InvalidOperation:
        return "UNCOMPARABLE_TOTALS"
    if shape == "ALL_CORE_MISSING":
        return "YEAR_EQUALS_REPORTED_H1_WITH_H2_MISSING" if numbers[0] == numbers[1] else "YEAR_DIFFERS_FROM_REPORTED_H1_WITH_H2_MISSING"
    return "YEAR_EQUALS_REPORTED_H1_PLUS_H2" if numbers[0] + numbers[1] == numbers[2] else "YEAR_DIFFERS_FROM_REPORTED_H1_PLUS_H2"


def observe(filename, row, counts):
    """Aggregate fixed labels only; originals stay in encrypted staging."""
    for name in RANK_FIELDS[filename]:
        counts["rank_labels"][name + ":" + rank_label(row[name])] += 1
    if filename == "good_conduct_register.csv":
        for name in ("accused_arrested", "accused_convicted"):
            counts["accused_text_labels"][name + ":" + boolean_label(row[name])] += 1
    if filename == "officer_firearms_expertise.csv":
        shape = h2_shape(row)
        counts["h2_block_shapes"][shape] += 1
        counts["h2_signature_context"][shape + ":" + ("PRESENT" if row["h2_supervisor_police_signature"].strip() else "MISSING")] += 1
        counts["h2_status_context"][shape + ":" + status_label(row["record_status"])] += 1
        counts["reported_total_relationships"][total_observation(row)] += 1


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
        reports, cache = [], {}
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
                for filename, header in HEADERS.items():
                    selected = [f for f in files if PurePosixPath(f["archive_path"]).name == filename]
                    if len(selected) != 1 or confirmation.source_for(filename) != "SRB":
                        raise ValueError("SRB source/file contract differs.")
                    file = selected[0]
                    if tuple(file["columns"]) != header or file["expected_row_count"] != EXPECTED_ROWS[filename]:
                        raise ValueError("SRB header order/content differs.")
                    links = Counter()
                    counters = {name: Counter() for name in ("rank_labels", "accused_text_labels", "h2_block_shapes",
                        "h2_signature_context", "h2_status_context", "reported_total_relationships")}
                    source_ids, officer_rows = set(), Counter()
                    duplicates = total = 0
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
                        # The prior inspection checked all source IDs; this review rechecks
                        # the same coverage and reports no original cell values.
                        sid = row[identifier_field].strip()
                        if sid:
                            duplicates += sid in source_ids
                            source_ids.add(sid)
                        else:
                            missing_keys += 1
                        observe(filename, row, counters)
                        state, officer = inspected_link(connection, crypto, backup, row["officer_nic_no"], cache)
                        links[state] += 1
                        if officer is not None:
                            officer_rows[officer] += 1
                    if total != file["expected_row_count"]:
                        raise ValueError("SRB registered row count differs.")
                    if duplicates or missing_keys:
                        raise ValueError("Reviewed source key coverage differs.")
                    reports.append(dict(filename=filename, reported_source="SRB", rows=total,
                        identity_candidates=dict(sorted(links.items())), distinct_candidate_officers=len(officer_rows),
                        **{name: dict(sorted(counter.items())) for name, counter in counters.items()}))
        print("Read-only SRB activity vocabulary review: PASSED")
        for report in reports:
            print(json.dumps(report, sort_keys=True))
        print("Rank tokens and boolean spellings are observed vocabulary, not accepted mappings or authority.")
        print("Missing H2 blocks, signature presence and arithmetic matches do not establish completion, authenticity or competency.")
        print("CID/CCIB labels are source claims; historical assignment, authority, reference linkage and date semantics remain unassessed.")
        print("No database writes, Mongo connection, saved plaintext, personnel-level output or classification changes.")
        return 0
    except Exception as error:
        print("SRB activity review stopped:", type(error).__name__)
        print("No database writes requested.")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
