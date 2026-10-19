"""Read-only inspection of remaining HR/PF staged evidence; aggregate output only.

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

# Frozen received headers; unknown content never becomes an output label.
HEADERS = {'officer_education.csv': ('officer_nic_no', 'ol_school_name', 'ol_year', 'ol_index', 'ol_subject', 'ol_grades', 'al_school_name', 'al_year', 'al_index', 'al_stream', 'al_subject', 'al_grades', 'other_qualifications', 'uni_name', 'uni_degree_name', 'uni_degree_year', 'uni_index', 'uni_class', 'uni_gpa'), 'officer_family_details.csv': ('officer_nic_no', 'spouse_name', 'spouse_sex', 'spouse_date_of_birth', 'spouse_place_of_birth', 'date_of_marriage', 'reference_Marriage_certificate', 'date_of_divorce', 'reference_divorce_certificate', 'date_of_death', 'reference_death_certificate', 'children_no', 'childern_fullname', 'children_age', 'next_of_near_relative_name', 'next_of_relative_relationship', 'next_of_relative_address', 'datails_entry_date', 'recorded_by_signature', 'recorded_by_officer_name', 'recorded_by_officer_nic', 'Certified_signed_date', 'recorded_by_officer_rank'), 'operations.csv': ('operation_no', 'complaint_number', 'operation_type', 'crime_type_code', 'crime_type_label', 'is_major', 'risk_level', 'operation_handle_station_code', 'operation_handle_station_name', 'operation_handle_division', 'operation_handle_province', 'operation_date', 'operation_start_time', 'offence_description', 'operation_end_time', 'duration_minutes', 'location_description', 'commanding_officer_nic_no', 'commanding_officer_rank', 'investigating_officers_nic_numbers', 'investigating_officers_rank', 'field_team_size', 'supporting_unit', 'no_suspects_arrested', 'items_seized', 'seizure_value_lkr', 'weapons_recovered', 'resistance_encountered', 'officers_injured', 'operation_outcome', 'commendation_recommended', 'report_reference'), 'court_details.csv': ('court_no', 'operation_no', 'complaint_no', 'court_name', 'court_type', 'court_town', 'court_province', 'case_instituted_date', 'crime_type_code', 'crime_type_label', 'is_major', 'appearances_to_date', 'case_status', 'case_outcome', 'outcome_date', 'participate_officers_details'), 'public_complaints.csv': ('complaint_id', 'intake_channel', 'date_received', 'receiving_office', 'complaint_mode', 'is_anonymous', 'complainant_id', 'complainant_district', 'complainant_type', 'complainant_gender', 'officer_nic_no', 'officer_nic_as_recorded', 'officer_rank_at_complaint', 'station_code', 'division', 'province', 'officers_named_count', 'allegation_code', 'allegation_category', 'allegation_description', 'incident_date', 'incident_place', 'linked_case_no', 'npc_reference_no', 'npc_received_date', 'referred_to', 'referral_date', 'investigating_officer_nic', 'investigating_officer_rank', 'unit_senior_questioned_nic', 'unit_senior_questioned_rank', 'officer_questioned', 'investigation_start_date', 'investigation_end_date', 'npc_decision', 'npc_decision_date', 'internal_decision', 'npc_directive', 'npc_directive_complied', 'compliance_date', 'complainant_informed_date', 'complainant_appeal_filed', 'linked_punishment_id', 'linked_transfer_id', 'linked_court_case_no', 'linked_hrc_reference', 'reduction_in_rank_directed', 'outcome_class', 'complaint_status', 'days_to_npc', 'days_to_decision', 'days_to_compliance', 'is_time_barred', 'escalated_to_court'), '_demotions_enacted.csv': ('officer_nic_no', 'punishment_date', 'floor_rank', 'punishment_id')}
DATES = {'officer_education.csv': (), 'officer_family_details.csv': ('spouse_date_of_birth', 'date_of_marriage', 'date_of_divorce', 'date_of_death', 'datails_entry_date', 'Certified_signed_date'), 'operations.csv': ('operation_date',), 'court_details.csv': ('case_instituted_date', 'outcome_date'), 'public_complaints.csv': ('date_received', 'incident_date', 'npc_received_date', 'referral_date', 'investigation_start_date', 'investigation_end_date', 'npc_decision_date', 'compliance_date', 'complainant_informed_date'), '_demotions_enacted.csv': ('punishment_date',)}
SOURCE_KEYS = {'officer_education.csv': None, 'officer_family_details.csv': None, 'operations.csv': 'operation_no', 'court_details.csv': 'court_no', 'public_complaints.csv': 'complaint_id', '_demotions_enacted.csv': 'punishment_id'}
RANK_FIELDS = {'officer_education.csv': (), 'officer_family_details.csv': ('recorded_by_officer_rank',), 'operations.csv': ('commanding_officer_rank',), 'court_details.csv': (), 'public_complaints.csv': ('officer_rank_at_complaint', 'investigating_officer_rank', 'unit_senior_questioned_rank'), '_demotions_enacted.csv': ('floor_rank',)}
ACTOR_FIELDS = {'officer_education.csv': (), 'officer_family_details.csv': ('recorded_by_officer_nic',), 'operations.csv': ('commanding_officer_nic_no',), 'court_details.csv': (), 'public_complaints.csv': ('officer_nic_as_recorded', 'investigating_officer_nic', 'unit_senior_questioned_nic'), '_demotions_enacted.csv': ()}
BOOLEAN_FIELDS = {'officer_education.csv': (), 'officer_family_details.csv': (), 'operations.csv': ('is_major', 'weapons_recovered', 'resistance_encountered', 'commendation_recommended'), 'court_details.csv': ('is_major',), 'public_complaints.csv': ('is_anonymous', 'officer_questioned', 'npc_directive_complied', 'complainant_appeal_filed', 'reduction_in_rank_directed', 'is_time_barred', 'escalated_to_court'), '_demotions_enacted.csv': ()}
NUMERIC_FIELDS = {'officer_education.csv': ('ol_year', 'al_year', 'uni_degree_year', 'uni_gpa'), 'officer_family_details.csv': ('children_no',), 'operations.csv': ('duration_minutes', 'field_team_size', 'no_suspects_arrested', 'seizure_value_lkr', 'officers_injured'), 'court_details.csv': ('appearances_to_date',), 'public_complaints.csv': ('officers_named_count', 'days_to_npc', 'days_to_decision', 'days_to_compliance'), '_demotions_enacted.csv': ()}
REFERENCE_FIELDS = {'officer_education.csv': ('ol_index', 'al_index', 'uni_index'), 'officer_family_details.csv': ('reference_Marriage_certificate', 'reference_divorce_certificate', 'reference_death_certificate'), 'operations.csv': ('complaint_number', 'report_reference'), 'court_details.csv': ('operation_no', 'complaint_no'), 'public_complaints.csv': ('linked_case_no', 'npc_reference_no', 'linked_punishment_id', 'linked_transfer_id', 'linked_court_case_no', 'linked_hrc_reference'), '_demotions_enacted.csv': ('punishment_id',)}
STRUCTURED_FIELDS = {'officer_education.csv': ('ol_subject', 'ol_grades', 'al_subject', 'al_grades', 'other_qualifications'), 'officer_family_details.csv': ('childern_fullname', 'children_age'), 'operations.csv': ('investigating_officers_nic_numbers', 'investigating_officers_rank', 'items_seized'), 'court_details.csv': ('participate_officers_details',), 'public_complaints.csv': (), '_demotions_enacted.csv': ()}
SOURCES = {'officer_education.csv': 'POLICE_HR_IS', 'officer_family_details.csv': 'POLICE_HR_IS', 'operations.csv': 'PF_REGISTRY', 'court_details.csv': 'PF_REGISTRY', 'public_complaints.csv': 'PF_REGISTRY', '_demotions_enacted.csv': 'PF_REGISTRY'}

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


def structured_shape(value):
    """Observe container/text shape without accepting participant or family linkage."""
    text = value.strip()
    if not text:
        return "MISSING"
    # Never print unknown keys, names, identifiers or the parsed contents.
    if len(text) > 1048576:
        return "OVERSIZED_TEXT_NOT_PARSED"
    try:
        parsed = json.loads(text)
        return ("JSON_LIST" if isinstance(parsed, list) else "JSON_OBJECT" if isinstance(parsed, dict)
                else "JSON_SCALAR")
    except (ValueError, RecursionError):
        return "JSON_LIKE_INVALID" if text[0] in "[{" else "DELIMITED_TEXT" if any(c in text for c in ";|,\n") else "OTHER_TEXT"


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
                    if len(selected) != 1 or confirmation.source_for(filename) != SOURCES[filename]:
                        raise ValueError("Remaining source/file contract differs.")
                    file = selected[0]
                    if tuple(file["columns"]) != header:
                        raise ValueError("Remaining source header order/content differs.")
                    missing, formats, links, ranks, booleans, actor_links, numeric, references, signatures, units = (Counter() for _ in range(10))
                    source_ids, officer_rows = set(), Counter()
                    duplicates = total = 0
                    identifier_field = SOURCE_KEYS[filename]
                    structured = Counter()
                    missing_keys = 0
                    query = select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"]).order_by(RawRecord.source_row_number)
                    for number, raw in enumerate(connection.execute(query).mappings(), 1):
                        if raw["source_row_number"] != number or any(raw[f] != file[f] for f in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
                            raise ValueError("Remaining source sequence/binding differs.")
                        original = open_row(crypto, stored_row(raw))
                        if original != open_row(backup, stored_row(raw)) or original["columns"] != file["columns"]:
                            raise ValueError("Remaining source header/backup recovery differs.")
                        row = dict(zip(original["columns"], original["values"], strict=True))
                        total += 1
                        for name, value in row.items():
                            if not value.strip():
                                missing[name] += 1
                        # Keep reported keys internal and print only aggregate repeat counts.
                        sid = row[identifier_field].strip() if identifier_field is not None else None
                        if sid:
                            duplicates += sid in source_ids
                            source_ids.add(sid)
                        elif identifier_field is not None:
                            missing_keys += 1
                        for name in STRUCTURED_FIELDS[filename]:
                            structured[name + ":" + structured_shape(row[name])] += 1
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
                        if "officer_nic_no" in row:
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
                        raise ValueError("Remaining registered row count differs.")
                    reports.append(dict(filename=filename, reported_source=SOURCES[filename], reported_key_column=identifier_field,
                        subject_identifier_column="officer_nic_no" if "officer_nic_no" in header else None, rows=total, headers=len(header),
                        header_columns=list(header), missing=dict(sorted(missing.items())), repeated_reported_keys=duplicates, missing_reported_keys=missing_keys,
                        structured_text_shapes=dict(sorted(structured.items())),
                        identity_candidates=dict(sorted(links.items())), distinct_candidate_officers=len(officer_rows),
                        officers_with_multiple_rows=sum(n > 1 for n in officer_rows.values()),
                        date_shapes=dict(sorted(formats.items())), recognized_rank_labels=dict(sorted(ranks.items())),
                        boolean_text_shapes=dict(sorted(booleans.items())),
                        actor_identity_candidates=dict(sorted(actor_links.items())), numeric_text_shapes=dict(sorted(numeric.items())),
                        source_reference_presence=dict(sorted(references.items())), signature_text_presence=dict(sorted(signatures.items())),
                        restricted_unit_label_mentions=dict(sorted(units.items()))))
        print("Read-only remaining source inspection: PASSED")
        for report in reports:
            print(json.dumps(report, sort_keys=True))
        print("Repeated officer rows can represent legitimate evidence; missing/repeated source keys need separate planning.")
        print("Nested participant/family text is only shape-inspected; no participant, court, operation, complaint or demotion linkage is accepted.")
        print("PF supplies the complaint file here; NPC mentions do not establish a direct independent NPC source. Date semantics, authority and source truth remain unassessed.")
        print("No database writes, Mongo connection, saved plaintext, personnel-level output or classification changes.")
        return 0
    except Exception as error:
        print("Remaining source inspection stopped:", type(error).__name__)
        print("No database writes requested.")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
