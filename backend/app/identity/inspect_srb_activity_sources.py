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

# Pin the received column order; this inspector never silently adapts source contracts.
HEADERS = {'officer_duty_periods.csv': ('period_id', 'officer_nic_no', 'date_of_entry', 'period_rank', 'period_station_code', 'period_station_name', 'period_station_division', 'period_station_province', 'in_what_capacity_employed', 'period_from', 'period_to', 'period_recorded_by_authority_rank', 'period_recorded_by_authority_nic', 'current_unit_type', 'current_station_code', 'current_division', 'current_province'), 'officer_firearms_expertise.csv': ('officer_nic_no', 'gun_record_id', 'gun_performance_year', 'gun_performance_rank', 'current_rank', 'gun_performance_station_code', 'gun_performance_station_name', 'gun_performance_division', 'gun_performance_province', 'h1_weapons_fired', 'h1_weapon_names', 'h1_weapon_rating', 'h1_total_points', 'h1_practice_date', 'h1_supervisor_nic', 'h1_supervisor_police_rank', 'h1_supervisor_police_name', 'h1_supervisor_police_signature', 'h2_weapons_fired', 'h2_weapon_names', 'h2_weapon_rating', 'h2_total_points', 'h2_practice_date', 'h2_supervisor_nic', 'h2_supervisor_police_rank', 'h2_supervisor_police_name', 'h2_supervisor_police_signature', 'year_total_points', 'year_rating', 'max_possible_points', 'score_percentage', 'class_of_shoot', 'annual_supervisor_nic', 'annual_supervisor_police_rank', 'annual_supervisor_police_name', 'annual_supervisor_police_signature', 'record_status', 'current_unit_type', 'current_station_code', 'current_division', 'current_province'), 'good_conduct_register.csv': ('good_conduct_id', 'operation_no', 'officer_nic_no', 'event_type', 'event_date', 'reference_no', 'reason', 'approving_authority', 'approving_order_date', 'approving_order_no', 'reward_voucher_no', 'voucher_station_no', 'voucher_application_date', 'reward_basis', 'court_no', 'property_value_stolen', 'property_value_recovered', 'accused_arrested', 'accused_convicted', 'date_of_conviction', 'amount_recommended_rs', 'amount_sanctioned_rs', 'amount_paid_rs', 'non_payment_reason', 'recommending_asp_name', 'recommending_asp_nic', 'sanctioning_tier', 'sanctioning_authority_name', 'sanctioning_authority_nic', 'sanction_date', 'payment_certified_date', 'co_recipient_count', 'private_informant_paid_rs'), 'bad_conduct_register.csv': ('punishment_id', 'officer_nic_no', 'originating_complaint_id', 'detection_source', 'date_of_offence', 'charge_sheet_no', 'charge_sheet_date', 'offence_code', 'nature_of_offence', 'offence_severity', 'plea', 'inquiry_type', 'inquiry_officer_rank', 'finding', 'punishment_imposed', 'date_of_punishment', 'punishment_notice_no', 'recovery_amount_rs', 'promotion_bar_until', 'interdiction_start', 'interdiction_end', 'reduction_in_rank_enacted', 'hardship_transfer_enacted', 'hardship_transfer_id', 'appeal_filed', 'appeal_authority', 'appeal_outcome', 'appeal_decision_date', 'legal_status', 'approving_authority', 'delegation_instrument')}
DATES = {'officer_duty_periods.csv': ('date_of_entry', 'period_from', 'period_to'), 'officer_firearms_expertise.csv': ('h1_practice_date', 'h2_practice_date'), 'good_conduct_register.csv': ('event_date', 'approving_order_date', 'voucher_application_date', 'date_of_conviction', 'sanction_date', 'payment_certified_date'), 'bad_conduct_register.csv': ('date_of_offence', 'charge_sheet_date', 'date_of_punishment', 'promotion_bar_until', 'interdiction_start', 'interdiction_end', 'appeal_decision_date')}
BOOLEAN_FIELDS = {'officer_duty_periods.csv': (), 'officer_firearms_expertise.csv': (), 'good_conduct_register.csv': (), 'bad_conduct_register.csv': ('reduction_in_rank_enacted', 'hardship_transfer_enacted', 'appeal_filed')}
SOURCE_KEYS = {'officer_duty_periods.csv': 'period_id', 'officer_firearms_expertise.csv': 'gun_record_id', 'good_conduct_register.csv': 'good_conduct_id', 'bad_conduct_register.csv': 'punishment_id'}
RANK_FIELDS = {'officer_duty_periods.csv': ('period_rank', 'period_recorded_by_authority_rank'), 'officer_firearms_expertise.csv': ('gun_performance_rank', 'current_rank', 'h1_supervisor_police_rank', 'h2_supervisor_police_rank', 'annual_supervisor_police_rank'), 'good_conduct_register.csv': (), 'bad_conduct_register.csv': ('inquiry_officer_rank',)}
ACTOR_FIELDS = {'officer_duty_periods.csv': ('period_recorded_by_authority_nic',), 'officer_firearms_expertise.csv': ('h1_supervisor_nic', 'h2_supervisor_nic', 'annual_supervisor_nic'), 'good_conduct_register.csv': ('recommending_asp_nic', 'sanctioning_authority_nic'), 'bad_conduct_register.csv': ()}
NUMERIC_FIELDS = {'officer_duty_periods.csv': (), 'officer_firearms_expertise.csv': ('gun_performance_year', 'h1_total_points', 'h2_total_points', 'year_total_points', 'max_possible_points', 'score_percentage'), 'good_conduct_register.csv': ('property_value_stolen', 'property_value_recovered', 'accused_arrested', 'accused_convicted', 'amount_recommended_rs', 'amount_sanctioned_rs', 'amount_paid_rs', 'co_recipient_count', 'private_informant_paid_rs'), 'bad_conduct_register.csv': ('recovery_amount_rs',)}
REFERENCE_FIELDS = {'officer_duty_periods.csv': (), 'officer_firearms_expertise.csv': (), 'good_conduct_register.csv': ('operation_no', 'court_no'), 'bad_conduct_register.csv': ('originating_complaint_id', 'hardship_transfer_id', 'delegation_instrument')}

def numeric_shape(value):
    """Observe finite numeric text without printing values or inventing units."""
    text = value.strip()
    if not text:
        return "MISSING"
    try:
        number = Decimal(text)
        if not number.is_finite():
            return "NONFINITE"
        return "NEGATIVE" if number < 0 else "ZERO" if number == 0 else "POSITIVE"
    except InvalidOperation:
        return "NONNUMERIC_TEXT"


def presence_shape(value):
    """A populated signature/reference is not evidence of authenticity or linkage."""
    return "PRESENT" if value.strip() else "MISSING"


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
                    missing, formats, links, ranks, booleans, actor_links, numeric, references, signatures, units = (Counter() for _ in range(10))
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
                        if filename == "officer_duty_periods.csv":
                            intervals[interval_observation(row["period_from"], row["period_to"])] += 1
                        elif filename == "bad_conduct_register.csv":
                            intervals[interval_observation(row["interdiction_start"], row["interdiction_end"])] += 1
                        # Aggregate candidate states only; no actor NICs or names leave memory.
                        for name in ACTOR_FIELDS[filename]:
                            actor_state, _ = inspected_link(connection, crypto, backup, row[name], cache)
                            actor_links[name + ":" + actor_state] += 1
                        for name in NUMERIC_FIELDS[filename]:
                            numeric[name + ":" + numeric_shape(row[name])] += 1
                        for name in REFERENCE_FIELDS[filename]:
                            references[name + ":" + presence_shape(row[name])] += 1
                        for name in header:
                            if name.endswith("_signature"):
                                signatures[name + ":" + presence_shape(row[name])] += 1
                        if "current_unit_type" in row:
                            label = row["current_unit_type"].strip()
                            units[label if label in {"CID", "CCIB"} else "MISSING" if not label else "OTHER_REPORTED_UNIT"] += 1
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
                        boolean_text_shapes=dict(sorted(booleans.items())),
                        actor_identity_candidates=dict(sorted(actor_links.items())), numeric_text_shapes=dict(sorted(numeric.items())),
                        source_reference_presence=dict(sorted(references.items())), signature_text_presence=dict(sorted(signatures.items())),
                        restricted_unit_label_mentions=dict(sorted(units.items()))))
        print("Read-only SRB activity source inspection: PASSED")
        for report in reports:
            print(json.dumps(report, sort_keys=True))
        print("Repeated officer rows can represent legitimate activity history; repeated source keys require separate planning.")
        print("Reported ranks, signatures, scores, conduct outcomes and references are claims, not verified authority, competency or legal effect.")
        print("CID/CCIB labels are source claims; historical assignment, authority, reference linkage and date semantics remain unassessed.")
        print("No database writes, Mongo connection, saved plaintext, personnel-level output or classification changes.")
        return 0
    except Exception as error:
        print("SRB activity inspection stopped:", type(error).__name__)
        print("No database writes requested.")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
