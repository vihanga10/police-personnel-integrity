"""Read-only inspection of staged SRB number/restriction evidence; aggregate output only.

No Mongo connection, evidence writes, classification or authority determination.
Date shapes are observations, never a source date-order/effective-time policy.
"""
import argparse
from collections import Counter
from datetime import date
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

# Pin the received column order; this inspector never silently adapts source contracts.
HEADERS = {'officer_police_numbers.csv': ('police_no', 'officer_nic_no', 'number_type', 'rank_band', 'rank_band_label', 'valid_from', 'valid_to', 'issued_under', 'issue_reason'), 'officer_restrictions.csv': ('restriction_id', 'officer_nic_no', 'restriction_category', 'restriction_basis', 'restriction_effect', 'restriction_scope', 'restricted_station_code', 'restricted_station_name', 'restricted_division', 'restricted_district', 'restricted_province', 'restriction_reason', 'reference_paper_no', 'restriction_start_date', 'restriction_record_date', 'restriction_recorded_officer_nic', 'restriction_recorded_officer_rank', 'restriction_removal_date', 'restriction_removal_record_date', 'restriction_removed_officer_nic', 'restriction_removed_officer_rank', 'restriction_status', 'restriction_verifiable', 'override_recorded'), 'restriction_overrides.csv': ('override_id', 'restriction_id', 'officer_nic_no', 'transfer_id', 'override_reference', 'override_ground', 'override_reason', 'override_authority_nic', 'override_authority_rank', 'override_date')}
DATES = {
    "officer_police_numbers.csv": ("valid_from", "valid_to"),
    "officer_restrictions.csv": ("restriction_start_date", "restriction_record_date",
        "restriction_removal_date", "restriction_removal_record_date"),
    "restriction_overrides.csv": ("override_date",),
}
BOOLEAN_FIELDS = {
    "officer_police_numbers.csv": (),
    "officer_restrictions.csv": ("restriction_verifiable", "override_recorded"),
    "restriction_overrides.csv": (),
}
SOURCE_KEYS = {
    "officer_police_numbers.csv": "police_no",
    "officer_restrictions.csv": "restriction_id",
    "restriction_overrides.csv": "override_id",
}
RANK_FIELDS = {
    "officer_police_numbers.csv": (),
    "officer_restrictions.csv": ("restriction_recorded_officer_rank", "restriction_removed_officer_rank"),
    "restriction_overrides.csv": ("override_authority_rank",),
}


def interval_observation(start, end):
    """Compare only strict ISO calendar dates, without deciding endpoint semantics."""
    if date_shape(start) != "ISO_CALENDAR_DATE" or date_shape(end) != "ISO_CALENDAR_DATE":
        return "ENDPOINT_MISSING_OR_NON_ISO"
    first, last = date.fromisoformat(start.strip()), date.fromisoformat(end.strip())
    return "END_BEFORE_START" if last < first else "SAME_DATE" if last == first else "END_AFTER_START"


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
                    if tuple(file["columns"]) != header:
                        raise ValueError("SRB header order/content differs.")
                    missing, formats, links, ranks, booleans = (Counter() for _ in range(5))
                    source_ids, officer_rows = set(), Counter()
                    duplicates = total = 0
                    identifier_field = SOURCE_KEYS[filename]
                    intervals = Counter()
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
                        for name, value in row.items():
                            if not value.strip():
                                missing[name] += 1
                        # Keep reported keys internal and print only aggregate repeat counts.
                        sid = row[identifier_field].strip()
                        if sid:
                            duplicates += sid in source_ids
                            source_ids.add(sid)
                        else:
                            missing_keys += 1
                        if filename == "officer_police_numbers.csv":
                            intervals[interval_observation(row["valid_from"], row["valid_to"])] += 1
                        elif filename == "officer_restrictions.csv":
                            intervals[interval_observation(row["restriction_start_date"], row["restriction_removal_date"])] += 1
                        state, officer = inspected_link(connection, crypto, backup, row["officer_nic_no"], cache)
                        links[state] += 1
                        if officer is not None:
                            officer_rows[officer] += 1
                        for name in DATES[filename]:
                            formats[name + ":" + date_shape(row[name])] += 1
                        for name in RANK_FIELDS[filename]:
                            value = row[name].strip()
                            # Unknown values might be misplaced PII: never print them.
                            ranks[name + ":" + (value if value in RANKS else "MISSING" if not value else "UNMAPPED_LABEL")] += 1
                        for name in BOOLEAN_FIELDS[filename]:
                            value = row[name].strip()
                            booleans[name + ":" + (value if value in KNOWN_BOOLEAN_TEXT else "MISSING" if not value else "OTHER_TEXT")] += 1
                    if total != file["expected_row_count"]:
                        raise ValueError("SRB registered row count differs.")
                    reports.append(dict(filename=filename, reported_source="SRB", rows=total, headers=len(header),
                        header_columns=list(header), missing=dict(sorted(missing.items())), repeated_reported_keys=duplicates, missing_reported_keys=missing_keys,
                        interval_date_observations=dict(sorted(intervals.items())),
                        identity_candidates=dict(sorted(links.items())), distinct_candidate_officers=len(officer_rows),
                        officers_with_multiple_rows=sum(n > 1 for n in officer_rows.values()),
                        date_shapes=dict(sorted(formats.items())), recognized_rank_labels=dict(sorted(ranks.items())),
                        boolean_text_shapes=dict(sorted(booleans.items()))))
        print("Read-only SRB source inspection: PASSED")
        for report in reports:
            print(json.dumps(report, sort_keys=True))
        print("Repeated police numbers can represent versions or reuse; repeated keys are observations, not automatic duplicate findings.")
        print("Reported restriction_verifiable flags do not establish verification; restriction/override references require separate linkage planning.")
        print("Authority identity, delegation, restriction effect, number eligibility and date endpoint semantics remain unassessed.")
        print("No database writes, Mongo connection, saved plaintext, personnel-level output or classification changes.")
        return 0
    except Exception as error:
        print("SRB inspection stopped:", type(error).__name__)
        if type(error) is ValueError:
            print(str(error))
        print("No database writes requested.")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
