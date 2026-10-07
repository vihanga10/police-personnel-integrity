"""Plan remaining source claims without applying outcomes or granting disclosure."""
from dataclasses import dataclass, field
from datetime import date, time
from decimal import Decimal, InvalidOperation
import re
from uuid import UUID
from types import MappingProxyType
from app.identity.inspect_remaining_sources import (HEADERS, DATES, SOURCE_KEYS, ACTOR_FIELDS,
    RANK_FIELDS, BOOLEAN_FIELDS, NUMERIC_FIELDS, REFERENCE_FIELDS, STRUCTURED_FIELDS)
from app.identity.inspect_remaining_review import split_reported_items, PAIRED_FIELDS
from app.identity.service_values import RANKS

REMAINING_PLAN_POLICY = "REMAINING_SOURCE_PLAN_V1"
ROUTES = MappingProxyType({name: MappingProxyType(fields) for name, fields in {'_demotions_enacted.csv': {'officer_nic_no': ('mongodb.demotion_events', 'officer_uid'), 'punishment_date': ('mongodb.demotion_events', 'reported_punishment_date'), 'floor_rank': ('mongodb.demotion_events', 'reported_floor_rank_code'), 'punishment_id': ('mongodb.demotion_events', 'punishment_reference')}, 'court_details.csv': {'court_no': ('mongodb.court_records', 'case_reference_ciphertext'), 'operation_no': ('mongodb.court_records', 'links.operation_reference_ciphertext'), 'complaint_no': ('mongodb.court_records', 'links.complaint_reference_ciphertext'), 'court_name': ('mongodb.court_records', 'reported_court_name'), 'court_type': ('mongodb.court_records', 'reported_court_type'), 'court_town': ('mongodb.court_records', 'reported_court_town'), 'court_province': ('mongodb.court_records', 'reported_court_province'), 'case_instituted_date': ('mongodb.court_records', 'reported_case_instituted_date'), 'crime_type_code': ('mongodb.court_records', 'reported_crime_type_code'), 'crime_type_label': ('mongodb.court_records', 'reported_crime_type_label'), 'is_major': ('mongodb.court_records', 'reported_major_case'), 'appearances_to_date': ('mongodb.court_records', 'reported_appearance_count'), 'case_status': ('mongodb.court_records', 'reported_case_status'), 'case_outcome': ('mongodb.court_records', 'reported_case_outcome_ciphertext'), 'outcome_date': ('mongodb.court_records', 'reported_outcome_date'), 'participate_officers_details': ('mongodb.court_records', 'participant_details_ciphertext')}, 'officer_education.csv': {'officer_nic_no': ('mongodb.education_records', 'officer_uid'), 'ol_school_name': ('mongodb.education_records', 'ol.reported_school_name'), 'ol_year': ('mongodb.education_records', 'ol.reported_examination_year'), 'ol_index': ('mongodb.education_records', 'ol.examination_identifier_ciphertext'), 'ol_subject': ('mongodb.education_records', 'ol.reported_subjects'), 'ol_grades': ('mongodb.education_records', 'ol.reported_grades'), 'al_school_name': ('mongodb.education_records', 'al.reported_school_name'), 'al_year': ('mongodb.education_records', 'al.reported_examination_year'), 'al_index': ('mongodb.education_records', 'al.examination_identifier_ciphertext'), 'al_stream': ('mongodb.education_records', 'al.reported_stream'), 'al_subject': ('mongodb.education_records', 'al.reported_subjects'), 'al_grades': ('mongodb.education_records', 'al.reported_grades'), 'other_qualifications': ('mongodb.education_records', 'other_qualifications_ciphertext'), 'uni_name': ('mongodb.education_records', 'university.reported_institution_name'), 'uni_degree_name': ('mongodb.education_records', 'university.reported_degree_name'), 'uni_degree_year': ('mongodb.education_records', 'university.reported_degree_year'), 'uni_index': ('mongodb.education_records', 'university.student_identifier_ciphertext'), 'uni_class': ('mongodb.education_records', 'university.reported_degree_class'), 'uni_gpa': ('mongodb.education_records', 'university.reported_gpa')}, 'officer_family_details.csv': {'officer_nic_no': ('postgresql.identity.source_assertion', 'officer_uid'), 'spouse_name': ('postgresql.identity.officer_family_relation', 'related_person_name'), 'spouse_sex': ('postgresql.identity.officer_family_relation', 'related_person_gender_code'), 'spouse_date_of_birth': ('postgresql.identity.officer_family_relation', 'related_person_date_of_birth'), 'spouse_place_of_birth': ('postgresql.identity.officer_family_relation', 'related_person_place_of_birth'), 'date_of_marriage': ('postgresql.identity.officer_family_civil_event_version', 'event_date'), 'reference_Marriage_certificate': ('postgresql.identity.officer_family_civil_event_version', 'evidence_reference_ciphertext'), 'date_of_divorce': ('postgresql.identity.officer_family_civil_event_version', 'event_date'), 'reference_divorce_certificate': ('postgresql.identity.officer_family_civil_event_version', 'evidence_reference_ciphertext'), 'date_of_death': ('postgresql.identity.source_assertion', 'asserted_value_ciphertext'), 'reference_death_certificate': ('postgresql.identity.source_assertion', 'asserted_value_ciphertext'), 'children_no': ('postgresql.identity.source_assertion', 'asserted_value_ciphertext'), 'childern_fullname': ('postgresql.identity.officer_family_relation', 'related_person_name'), 'children_age': ('postgresql.identity.source_assertion', 'asserted_value_ciphertext'), 'next_of_near_relative_name': ('postgresql.identity.officer_next_of_kin_version', 'related_person_name'), 'next_of_relative_relationship': ('postgresql.identity.officer_next_of_kin_version', 'relationship_type'), 'next_of_relative_address': ('postgresql.identity.officer_next_of_kin_version', 'address_ciphertext'), 'datails_entry_date': ('postgresql.identity.source_assertion', 'source_recorded_at'), 'recorded_by_signature': ('postgresql.identity.source_attestation', 'signature_reference_ciphertext'), 'recorded_by_officer_name': ('postgresql.identity.source_attestation', 'actor_name_ciphertext'), 'recorded_by_officer_nic': ('postgresql.identity.source_attestation', 'actor_identifier_ciphertext'), 'Certified_signed_date': ('postgresql.identity.source_attestation', 'attested_on'), 'recorded_by_officer_rank': ('postgresql.identity.source_attestation', 'actor_rank_asserted')}, 'operations.csv': {'operation_no': ('mongodb.operation_records', 'source_record_id'), 'complaint_number': ('mongodb.operation_records', 'complaint_reference_ciphertext'), 'operation_type': ('mongodb.operation_records', 'reported_operation_type'), 'crime_type_code': ('mongodb.operation_records', 'reported_crime_type_code'), 'crime_type_label': ('mongodb.operation_records', 'reported_crime_type_label'), 'is_major': ('mongodb.operation_records', 'reported_major_operation'), 'risk_level': ('mongodb.operation_records', 'reported_risk_level'), 'operation_handle_station_code': ('mongodb.operation_records', 'handling_station_reference'), 'operation_handle_station_name': ('mongodb.operation_records', 'reported_handling_station_name'), 'operation_handle_division': ('mongodb.operation_records', 'reported_handling_division'), 'operation_handle_province': ('mongodb.operation_records', 'reported_handling_province'), 'operation_date': ('mongodb.operation_records', 'reported_operation_date'), 'operation_start_time': ('mongodb.operation_records', 'reported_start_time'), 'offence_description': ('mongodb.operation_records', 'offence_description_ciphertext'), 'operation_end_time': ('mongodb.operation_records', 'reported_end_time'), 'duration_minutes': ('mongodb.operation_records', 'reported_duration_minutes'), 'location_description': ('mongodb.operation_records', 'location_description_ciphertext'), 'commanding_officer_nic_no': ('mongodb.operation_records', 'commander.actor_officer_uid'), 'commanding_officer_rank': ('mongodb.operation_records', 'commander.reported_rank_code'), 'investigating_officers_nic_numbers': ('mongodb.operation_records', 'participants.investigating_officer_references'), 'investigating_officers_rank': ('mongodb.operation_records', 'reported_investigating_rank_claims'), 'field_team_size': ('mongodb.operation_records', 'reported_field_team_size'), 'supporting_unit': ('mongodb.operation_records', 'reported_supporting_unit'), 'no_suspects_arrested': ('mongodb.operation_records', 'reported_suspects_arrested_count'), 'items_seized': ('mongodb.operation_records', 'reported_items_seized_ciphertext'), 'seizure_value_lkr': ('mongodb.operation_records', 'reported_seizure_value_lkr'), 'weapons_recovered': ('mongodb.operation_records', 'reported_weapons_recovered_ciphertext'), 'resistance_encountered': ('mongodb.operation_records', 'reported_resistance_ciphertext'), 'officers_injured': ('mongodb.operation_records', 'reported_officer_injuries_ciphertext'), 'operation_outcome': ('mongodb.operation_records', 'reported_operation_outcome'), 'commendation_recommended': ('mongodb.operation_records', 'reported_commendation_recommended'), 'report_reference': ('mongodb.operation_records', 'report_reference_ciphertext')}, 'public_complaints.csv': {'complaint_id': ('mongodb.complaint_records', 'source_record_id'), 'intake_channel': ('mongodb.complaint_records', 'reported_intake_channel'), 'date_received': ('mongodb.complaint_records', 'reported_received_date'), 'receiving_office': ('mongodb.complaint_records', 'reported_receiving_office_reference'), 'complaint_mode': ('mongodb.complaint_records', 'reported_complaint_mode'), 'is_anonymous': ('mongodb.complaint_records', 'reported_anonymous'), 'complainant_id': ('mongodb.complaint_records', 'complainant.identifier_ciphertext'), 'complainant_district': ('mongodb.complaint_records', 'complainant.reported_district_ciphertext'), 'complainant_type': ('mongodb.complaint_records', 'complainant.reported_type'), 'complainant_gender': ('mongodb.complaint_records', 'complainant.reported_gender'), 'officer_nic_no': ('mongodb.complaint_records', 'subject.officer_uid'), 'officer_nic_as_recorded': ('mongodb.complaint_records', 'subject.recorded_identifier_evidence_reference'), 'officer_rank_at_complaint': ('mongodb.complaint_records', 'subject.reported_rank_code'), 'station_code': ('mongodb.complaint_records', 'reported_station_reference'), 'division': ('mongodb.complaint_records', 'reported_division'), 'province': ('mongodb.complaint_records', 'reported_province'), 'officers_named_count': ('mongodb.complaint_records', 'reported_officers_named_count'), 'allegation_code': ('mongodb.complaint_records', 'allegation.reported_code'), 'allegation_category': ('mongodb.complaint_records', 'allegation.reported_category'), 'allegation_description': ('mongodb.complaint_records', 'allegation.description_ciphertext'), 'incident_date': ('mongodb.complaint_records', 'incident.reported_date'), 'incident_place': ('mongodb.complaint_records', 'incident.place_ciphertext'), 'linked_case_no': ('mongodb.complaint_records', 'links.case_reference_ciphertext'), 'npc_reference_no': ('mongodb.complaint_records', 'npc.reference_ciphertext'), 'npc_received_date': ('mongodb.complaint_records', 'npc.reported_received_date'), 'referred_to': ('mongodb.complaint_records', 'referral.recipient_claim_ciphertext'), 'referral_date': ('mongodb.complaint_records', 'referral.reported_date'), 'investigating_officer_nic': ('mongodb.complaint_records', 'investigator.actor_officer_uid'), 'investigating_officer_rank': ('mongodb.complaint_records', 'investigator.reported_rank_code'), 'unit_senior_questioned_nic': ('mongodb.complaint_records', 'questioned_senior.actor_officer_uid'), 'unit_senior_questioned_rank': ('mongodb.complaint_records', 'questioned_senior.reported_rank_code'), 'officer_questioned': ('mongodb.complaint_records', 'reported_officer_questioned'), 'investigation_start_date': ('mongodb.complaint_records', 'investigation.reported_start_date'), 'investigation_end_date': ('mongodb.complaint_records', 'investigation.reported_end_date'), 'npc_decision': ('mongodb.complaint_records', 'decisions.reported_npc_decision'), 'npc_decision_date': ('mongodb.complaint_records', 'decisions.reported_npc_decision_date'), 'internal_decision': ('mongodb.complaint_records', 'decisions.reported_internal_decision'), 'npc_directive': ('mongodb.complaint_records', 'decisions.npc_directive_ciphertext'), 'npc_directive_complied': ('mongodb.complaint_records', 'reported_directive_complied'), 'compliance_date': ('mongodb.complaint_records', 'reported_compliance_date'), 'complainant_informed_date': ('mongodb.complaint_records', 'reported_complainant_informed_date'), 'complainant_appeal_filed': ('mongodb.complaint_records', 'reported_appeal_filed'), 'linked_punishment_id': ('mongodb.complaint_records', 'links.punishment_reference_ciphertext'), 'linked_transfer_id': ('mongodb.complaint_records', 'links.transfer_reference_ciphertext'), 'linked_court_case_no': ('mongodb.complaint_records', 'links.court_case_reference_ciphertext'), 'linked_hrc_reference': ('mongodb.complaint_records', 'links.hrc_reference_ciphertext'), 'reduction_in_rank_directed': ('mongodb.complaint_records', 'reported_rank_reduction_directed'), 'outcome_class': ('mongodb.complaint_records', 'reported_outcome_class'), 'complaint_status': ('mongodb.complaint_records', 'reported_complaint_status'), 'days_to_npc': ('mongodb.complaint_records', 'reported_days_to_npc'), 'days_to_decision': ('mongodb.complaint_records', 'reported_days_to_decision'), 'days_to_compliance': ('mongodb.complaint_records', 'reported_days_to_compliance'), 'is_time_barred': ('mongodb.complaint_records', 'reported_time_barred'), 'escalated_to_court': ('mongodb.complaint_records', 'reported_escalated_to_court')}}.items()})
EXPECTED_ROWS = {"officer_education.csv": 6596, "officer_family_details.csv": 6596,
    "operations.csv": 19554, "court_details.csv": 9538, "public_complaints.csv": 998, "_demotions_enacted.csv": 8}
# Only the observed family recorder vocabulary gets an abbreviation mapping.
FAMILY_RANK_ALIASES = {"ASP": "ASP", "SP": "SP", "SSP": "SSP", "DIG": "DIG", "SDIG": "SDIG"}
INTEGER_FIELDS = frozenset(name for names in NUMERIC_FIELDS.values() for name in names) - {"uni_gpa", "seizure_value_lkr"}


@dataclass(frozen=True)
class RemainingField:
    source_column: str
    destination: str
    target_field: str
    source_value: str = field(repr=False)
    value: object = field(repr=False)
    status: str = "PARSED"
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class RemainingPlan:
    filename: str
    officer_uid: UUID | None
    fields: tuple[RemainingField, ...] = field(repr=False)
    observations: tuple[str, ...] = ()
    review_issues: tuple[str, ...] = ()
    policy_version: str = REMAINING_PLAN_POLICY
    uncertainties: tuple[str, ...] = (
        "IDENTIFIER_TEMPORAL_ELIGIBILITY_UNASSESSED", "SOURCE_INDEPENDENCE_UNVERIFIED",
        "REPORTED_DATE_SEMANTICS_UNASSESSED", "AUTHORITY_IDENTITY_SCOPE_AND_DELEGATION_UNASSESSED",
        "REFERENCE_AUTHENTICITY_AND_LINKAGE_UNASSESSED", "CLASSIFICATION_UNASSESSED",
        "REPORTED_OUTCOME_NOT_APPLIED", "SNAPSHOT_APPLICABILITY_UNKNOWN")

    @property
    def needs_review(self):
        return bool(self.review_issues) or any(f.status == "REVIEW_REQUIRED" for f in self.fields)


def validate_remaining_routing(document):
    """Reject missing, duplicated or changed routes before preparing any source plan."""
    for filename in HEADERS:
        selected = [f for f in document.get("files", []) if f.get("filename") == filename]
        if len(selected) != 1:
            raise ValueError("Remaining routing source membership differs.")
        fields = selected[0]["fields"]
        actual = {f["source_column"]: (f["destination"], f["target_field"]) for f in fields}
        if len(fields) != len(actual) or actual != dict(ROUTES[filename]) or any(f.get("preserve_in_protected_staging") is not True for f in fields):
            raise ValueError("Remaining routing coverage or preservation differs.")


def plan_remaining(filename, row, *, officer_uid=None, identity_candidates=None):
    """Preserve every original cell and parse claims without accepting their effects.

    Operations/courts are multi-person evidence: no single officer is fabricated.
    Candidate UUIDs are caller-supplied evidence observations, never authority.
    """
    if filename not in HEADERS or set(row) != set(HEADERS[filename]) or any(not isinstance(v, str) for v in row.values()):
        raise ValueError("Remaining source columns/types differ.")
    has_subject = "officer_nic_no" in row
    if officer_uid is not None and not isinstance(officer_uid, UUID):
        raise ValueError("Officer candidate must be a UUID.")
    if not has_subject and officer_uid is not None:
        raise ValueError("Multi-person source cannot be bound to a fabricated subject.")
    candidates = identity_candidates or {}
    if any(uid is not None and not isinstance(uid, UUID) for uid in candidates.values()):
        raise ValueError("Identity candidates must be UUIDs or unknown.")
    fields, observations, review = [], [], []
    for name in HEADERS[filename]:
        original = row[name]; text = original.strip()
        destination, target = ROUTES[filename][name]
        value, status, issues = text, "PARSED", ()
        required = name == "officer_nic_no" or name == SOURCE_KEYS[filename]
        if not text:
            value, status = None, "REVIEW_REQUIRED" if required else "MISSING"
            issues = ("REQUIRED_VALUE_MISSING",) if required else ()
        elif "\x00" in original:
            value, status, issues = None, "REVIEW_REQUIRED", ("NUL_TEXT_VALUE",)
        elif name == "officer_nic_no":
            value = officer_uid
            status = "PARSED" if value is not None else "REVIEW_REQUIRED"
            issues = ("SUBJECT_CANDIDATE_NOT_ACCEPTED_HISTORICAL_IDENTITY",) if value else ("SUBJECT_IDENTITY_UNRESOLVED",)
        elif name == "officer_nic_as_recorded" or name in ACTOR_FIELDS[filename]:
            value = candidates.get(name)
            status = "PARSED" if value is not None else "REVIEW_REQUIRED"
            issues = ("ALTERNATE_SUBJECT_CANDIDATE_UNASSESSED",) if name == "officer_nic_as_recorded" else ("ACTOR_CANDIDATE_NOT_AUTHORITY",)
            if value is None: issues += ("REPORTED_IDENTITY_UNRESOLVED",)
        elif name in DATES[filename]:
            try:
                if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text) is None: raise ValueError()
                value = date.fromisoformat(text)
                issues = ("REPORTED_DATE_NOT_ACCEPTED_EFFECTIVE_TIME",)
            except ValueError:
                value, status, issues = None, "REVIEW_REQUIRED", ("INVALID_OR_UNSUPPORTED_DATE",)
        elif name in {"operation_start_time", "operation_end_time"}:
            try:
                if re.fullmatch(r"[0-9]{2}:[0-9]{2}(?::[0-9]{2})?", text) is None: raise ValueError()
                value = time.fromisoformat(text)
                issues = ("TIMEZONE_DAY_BOUNDARY_AND_DURATION_UNASSESSED",)
            except ValueError:
                value, status, issues = None, "REVIEW_REQUIRED", ("UNSUPPORTED_REPORTED_TIME",)
        elif name in RANK_FIELDS[filename]:
            value = RANKS.get(text)
            if value is None and filename == "officer_family_details.csv": value = FAMILY_RANK_ALIASES.get(text)
            status = "PARSED" if value is not None else "REVIEW_REQUIRED"
            issues = ("REPORTED_RANK_NOT_AUTHORITY",) if value else ("UNMAPPED_REPORTED_RANK",)
        elif name in BOOLEAN_FIELDS[filename]:
            value = {"TRUE": True, "FALSE": False}.get(text)
            status = "PARSED" if value is not None else "REVIEW_REQUIRED"
            issues = ("REPORTED_FLAG_NOT_VERIFICATION",) if value is not None else ("UNMAPPED_BOOLEAN_TEXT",)
        elif name in NUMERIC_FIELDS[filename]:
            try:
                if name in INTEGER_FIELDS:
                    if re.fullmatch(r"[0-9]+", text) is None: raise ValueError()
                    value = int(text)
                else: value = Decimal(text)
                if isinstance(value, Decimal) and not value.is_finite() or value < 0: raise ValueError()
                issues = ("NUMERIC_UNITS_BASIS_AND_PLAUSIBILITY_UNASSESSED",)
            except (ValueError, InvalidOperation):
                value, status, issues = None, "REVIEW_REQUIRED", ("INVALID_REPORTED_NONNEGATIVE_NUMBER",)
        elif name in STRUCTURED_FIELDS[filename]:
            shape, items = split_reported_items(text)
            # Retain structural hints, not accepted identities or positional joins.
            value = {"reported_shape": shape, "reported_item_count": len(items) if items is not None else None}
            issues = ("STRUCTURED_CONTENT_AND_PARTICIPANT_LINKAGE_UNASSESSED",)
            if shape in {"INVALID_JSON_LIKE", "MIXED_DELIMITERS", "EMPTY_LIST_MEMBER", "OVERSIZED"}:
                status = "REVIEW_REQUIRED"
                issues += ("STRUCTURED_FORMAT_REQUIRES_REVIEW",)
        elif name in REFERENCE_FIELDS[filename]:
            issues = ("REPORTED_REFERENCE_LINKAGE_AND_MEANING_UNASSESSED",)
        else:
            # Narrative, outcome and category claims are retained without invented vocabularies.
            issues = ("SOURCE_CLAIM_SEMANTICS_UNASSESSED",)
        fields.append(RemainingField(name, destination, target, original, value, status, issues))
    for left, right in PAIRED_FIELDS.get(filename, ()):
        sa, a = split_reported_items(row[left]); sb, b = split_reported_items(row[right])
        if a is not None and b is not None:
            if len(a) != len(b): review.append(left + ":REPORTED_LIST_LENGTH_MISMATCH")
            else: observations.append(left + ":EQUAL_LENGTH_NOT_ACCEPTED_POSITIONAL_LINKAGE")
        elif sa != sb or sa != "MISSING": observations.append(left + ":LIST_RELATIONSHIP_UNASSESSED")
    alternate = candidates.get("officer_nic_as_recorded")
    if filename == "public_complaints.csv" and alternate is not None and officer_uid is not None and alternate != officer_uid:
        review.append("ALTERNATE_SUBJECT_CANDIDATE_DIFFERS")
    if filename == "officer_family_details.csv":
        shape, children = split_reported_items(row["childern_fullname"])
        count = next(f.value for f in fields if f.source_column == "children_no")
        if type(count) is int and children is not None and len(children) != count:
            review.append("REPORTED_CHILD_COUNT_LIST_MISMATCH")
        elif type(count) is int and count > 0 and shape == "MISSING":
            review.append("REPORTED_CHILD_COUNT_WITH_MISSING_LIST")
    if not has_subject: observations.append("MULTI_PERSON_EVIDENCE_NO_SINGLE_SUBJECT")
    if filename == "_demotions_enacted.csv": observations.append("REPORTED_DEMOTION_PRESERVED_NOT_APPLIED")
    return RemainingPlan(filename, officer_uid, tuple(fields), tuple(observations), tuple(review))
