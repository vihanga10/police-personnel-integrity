"""Read-only inspection of staged transfer/promotion evidence; aggregate output only.

No Mongo connection, evidence writes, classification or authority determination.
Date shapes are observations, never a source date-order/effective-time policy.
"""
import argparse
from collections import Counter
from datetime import date
import json
from pathlib import Path, PurePosixPath
import re

from sqlalchemy import select, text
from database import create_identity_engine
from settings import Settings
from app.identity.candidate_lookup import find_identifier_candidates
from app.identity.inspect_service_plans import ARCHIVE, BATCH, CONFIRMATION, verified_nic_evidence
from app.identity.normalization import IdentifierInputError, normalize_identifier
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.service_values import RANKS
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.staging.models import IntakeBatch, IntakeFile, RawRecord

HEADERS = {'promotion_history.csv': ('promotion_id', 'officer_nic_no', 'from_rank', 'to_rank', 'is_same_unit', 'from_unit_name', 'to_unit_name', 'effective_date', 'new_unit_arrive_date', 'current_unit_departure_date', 'promotion_category', 'promotion_reason', 'regimental_no', 'previous_police_no', 'new_police_no', 'promotion_order_date', 'promotion_order_no', 'promotion_authority', 'promotion_authority_signed_date', 'RTM_CRTM', 'years_in_previous_rank'), 'transfer_history.csv': ('transfer_id', 'officer_nic_no', 'police_id_at_transfer', 'previous_police_no', 'new_police_no', 'from_station_code', 'from_station_name', 'from_unit_type', 'from_unit_name', 'from_division', 'from_province', 'from_rank', 'to_station_code', 'to_station_name', 'to_unit_type', 'to_unit_name', 'to_division', 'to_province', 'to_rank', 'departure_date', 'effective_date', 'arrival_date', 'transfer_type', 'transfer_authority', 'transfer_order_no', 'transfer_signed_date', 'transfer_reason', 'transfer_reason_category', 'transfer_requested_by', 'originating_complaint_id', 'is_same_unit', 'days_in_previous_posting', 'is_cancelled', 'cancellation_ref', 'cancellation_date')}
DATES = {"transfer_history.csv": ("departure_date", "effective_date", "arrival_date", "transfer_signed_date", "cancellation_date"),
         "promotion_history.csv": ("effective_date", "new_unit_arrive_date", "current_unit_departure_date", "promotion_order_date", "promotion_authority_signed_date")}
BOOLEAN_FIELDS = {"transfer_history.csv": ("is_same_unit", "is_cancelled"), "promotion_history.csv": ("is_same_unit",)}
KNOWN_BOOLEAN_TEXT = frozenset({"True", "False", "true", "false", "TRUE", "FALSE", "1", "0", "Yes", "No", "YES", "NO", "Y", "N"})


def date_shape(value):
    """Inspect syntax/calendar feasibility without choosing ambiguous date order."""
    value = value.strip()
    if not value:
        return "MISSING"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        try:
            date.fromisoformat(value)
            return "ISO_CALENDAR_DATE"
        except ValueError:
            return "INVALID_ISO_CALENDAR_DATE"
    match = re.fullmatch(r"(\d{1,2})/(\d{1,2})/(\d{4})", value)
    if match:
        first, second, year = map(int, match.groups())
        valid = []
        for label, month, day in (("DAY_FIRST_ONLY", second, first), ("MONTH_FIRST_ONLY", first, second)):
            try:
                date(year, month, day)
                valid.append(label)
            except ValueError:
                pass
        if len(valid) == 2:
            return "SLASH_DATE_ORDER_UNCONFIRMED" if first == second else "SLASH_DATE_ORDER_AMBIGUOUS"
        return "SLASH_" + valid[0] if valid else "INVALID_SLASH_CALENDAR_DATE"
    return "OTHER_DATE_TEXT"


def inspected_link(connection, crypto, backup, original_nic, cache):
    """Cache verified evidence within one read-only snapshot, using protected keys."""
    try:
        identifier = normalize_identifier(original_nic, identifier_type="NIC")
    except IdentifierInputError:
        return "UNUSABLE_NIC", None
    digest, _ = crypto.lookup_hmac(identifier.value, identifier_type="NIC")
    if digest not in cache:
        candidates = find_identifier_candidates(connection, crypto, identifier)
        if candidates.status != "SINGLE_CANDIDATE":
            cache[digest] = (candidates.status, None)
        else:
            refs = verified_nic_evidence(connection, crypto, backup, identifier, candidates)
            cache[digest] = ("EXACT_EVIDENCE_CANDIDATE" if refs else "NO_USABLE_NIC_EVIDENCE",
                            candidates.officer_uids[0] if refs else None)
    return cache[digest]


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
                    if len(selected) != 1 or confirmation.source_for(filename) != "PF_REGISTRY":
                        raise ValueError("Historical source/file contract differs.")
                    file = selected[0]
                    if tuple(file["columns"]) != header:
                        raise ValueError("Historical header order/content differs.")
                    missing, formats, links, ranks, booleans, unit_mentions = (Counter() for _ in range(6))
                    source_ids, officer_rows = set(), Counter()
                    duplicates = total = 0
                    identifier_field = "transfer_id" if filename == "transfer_history.csv" else "promotion_id"
                    query = select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"]).order_by(RawRecord.source_row_number)
                    for number, raw in enumerate(connection.execute(query).mappings(), 1):
                        if raw["source_row_number"] != number or any(raw[f] != file[f] for f in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
                            raise ValueError("Historical source sequence/binding differs.")
                        original = open_row(crypto, stored_row(raw))
                        if original != open_row(backup, stored_row(raw)) or original["columns"] != file["columns"]:
                            raise ValueError("Historical header/backup recovery differs.")
                        row = dict(zip(original["columns"], original["values"], strict=True))
                        total += 1
                        for name, value in row.items():
                            if not value.strip():
                                missing[name] += 1
                        sid = row[identifier_field].strip()
                        if sid:
                            duplicates += sid in source_ids
                            source_ids.add(sid)
                        state, officer = inspected_link(connection, crypto, backup, row["officer_nic_no"], cache)
                        links[state] += 1
                        if officer is not None:
                            officer_rows[officer] += 1
                        for name in DATES[filename]:
                            formats[name + ":" + date_shape(row[name])] += 1
                        for name in ("from_rank", "to_rank"):
                            value = row[name].strip()
                            # Unknown values might be misplaced PII: never print them.
                            ranks[name + ":" + (value if value in RANKS else "MISSING" if not value else "UNMAPPED_LABEL")] += 1
                        for name in BOOLEAN_FIELDS[filename]:
                            value = row[name].strip()
                            booleans[name + ":" + (value if value in KNOWN_BOOLEAN_TEXT else "MISSING" if not value else "OTHER_TEXT")] += 1
                        for name in ("from_unit_type", "to_unit_type"):
                            if name in row and row[name].strip() in {"CID", "CCIB"}:
                                unit_mentions[name + ":" + row[name].strip()] += 1
                    if total != file["expected_row_count"]:
                        raise ValueError("Historical registered row count differs.")
                    reports.append(dict(filename=filename, reported_source="PF_REGISTRY", rows=total, headers=len(header),
                        header_columns=list(header), missing=dict(sorted(missing.items())), duplicate_source_ids=duplicates,
                        identity_candidates=dict(sorted(links.items())), distinct_candidate_officers=len(officer_rows),
                        officers_with_multiple_rows=sum(n > 1 for n in officer_rows.values()),
                        date_shapes=dict(sorted(formats.items())), recognized_rank_labels=dict(sorted(ranks.items())),
                        boolean_text_shapes=dict(sorted(booleans.items())), explicit_unit_label_mentions=dict(sorted(unit_mentions.items()))))
        print("Read-only historical source inspection: PASSED")
        for report in reports:
            print(json.dumps(report, sort_keys=True))
        print("Repeated officer rows can represent legitimate history; source IDs and chronology need separate planning.")
        print("CID/CCIB mentions are source claims, not accepted periods, current assignments or access grants.")
        print("Authority identity, delegation, cancellation effect and date semantics remain unassessed.")
        print("No database writes, Mongo connection, saved plaintext, personnel-level output or classification changes.")
        return 0
    except Exception as error:
        print("Historical inspection stopped:", type(error).__name__)
        if type(error) is ValueError:
            print(str(error))
        print("No database writes requested.")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
