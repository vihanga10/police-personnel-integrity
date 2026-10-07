"""Plan SRB activity claims without deciding authority, competency or legal effect."""
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal, InvalidOperation
import re
from types import MappingProxyType
from uuid import UUID

from app.identity.inspect_srb_activity_sources import (
    HEADERS, DATES, ACTOR_FIELDS, RANK_FIELDS, SOURCE_KEYS, BOOLEAN_FIELDS, NUMERIC_FIELDS,
)
from app.identity.inspect_srb_activity_vocabulary import H2_CORE, h2_shape, total_observation
from app.identity.service_values import RANKS, SERVICE_VALUE_POLICY

ACTIVITY_PLAN_POLICY = "SRB_ACTIVITY_PLAN_V1"
ROUTES = MappingProxyType({name: MappingProxyType(fields) for name, fields in {'officer_duty_periods.csv': {'period_id': 'source_record_id', 'officer_nic_no': 'officer_uid', 'date_of_entry': 'reported_source_entry_date', 'period_rank': 'reported_period_rank_code', 'period_station_code': 'period_station_reference', 'period_station_name': 'reported_period_station_name', 'period_station_division': 'reported_period_station_division', 'period_station_province': 'reported_period_station_province', 'in_what_capacity_employed': 'reported_duty_capacity_ciphertext', 'period_from': 'reported_period_start_date', 'period_to': 'reported_period_end_date', 'period_recorded_by_authority_rank': 'recorder.reported_rank_code', 'period_recorded_by_authority_nic': 'recorder.actor_officer_uid', 'current_unit_type': 'source_snapshot.reported_unit_type_code', 'current_station_code': 'source_snapshot.reported_station_reference', 'current_division': 'source_snapshot.reported_division', 'current_province': 'source_snapshot.reported_province'}, 'officer_firearms_expertise.csv': {'officer_nic_no': 'officer_uid', 'gun_record_id': 'source_record_id', 'gun_performance_year': 'reported_performance_year', 'gun_performance_rank': 'reported_performance_rank_code', 'current_rank': 'source_snapshot.reported_rank_code', 'gun_performance_station_code': 'performance_station_reference', 'gun_performance_station_name': 'reported_performance_station_name', 'gun_performance_division': 'reported_performance_division', 'gun_performance_province': 'reported_performance_province', 'h1_weapons_fired': 'assessments.h1.reported_weapons_fired', 'h1_weapon_names': 'assessments.h1.reported_weapon_names', 'h1_weapon_rating': 'assessments.h1.reported_weapon_ratings', 'h1_total_points': 'assessments.h1.reported_total_points', 'h1_practice_date': 'assessments.h1.reported_practice_date', 'h1_supervisor_nic': 'assessments.h1.supervisor.actor_officer_uid', 'h1_supervisor_police_rank': 'assessments.h1.supervisor.reported_rank_code', 'h1_supervisor_police_name': 'assessments.h1.supervisor.actor_name_ciphertext', 'h1_supervisor_police_signature': 'assessments.h1.supervisor.signature_reference_ciphertext', 'h2_weapons_fired': 'assessments.h2.reported_weapons_fired', 'h2_weapon_names': 'assessments.h2.reported_weapon_names', 'h2_weapon_rating': 'assessments.h2.reported_weapon_ratings', 'h2_total_points': 'assessments.h2.reported_total_points', 'h2_practice_date': 'assessments.h2.reported_practice_date', 'h2_supervisor_nic': 'assessments.h2.supervisor.actor_officer_uid', 'h2_supervisor_police_rank': 'assessments.h2.supervisor.reported_rank_code', 'h2_supervisor_police_name': 'assessments.h2.supervisor.actor_name_ciphertext', 'h2_supervisor_police_signature': 'assessments.h2.supervisor.signature_reference_ciphertext', 'year_total_points': 'reported_annual_total_points', 'year_rating': 'reported_annual_rating', 'max_possible_points': 'reported_max_possible_points', 'score_percentage': 'reported_score_percentage', 'class_of_shoot': 'reported_shooting_class', 'annual_supervisor_nic': 'annual_supervisor.actor_officer_uid', 'annual_supervisor_police_rank': 'annual_supervisor.reported_rank_code', 'annual_supervisor_police_name': 'annual_supervisor.actor_name_ciphertext', 'annual_supervisor_police_signature': 'annual_supervisor.signature_reference_ciphertext', 'record_status': 'reported_source_record_status', 'current_unit_type': 'source_snapshot.reported_unit_type_code', 'current_station_code': 'source_snapshot.reported_station_reference', 'current_division': 'source_snapshot.reported_division', 'current_province': 'source_snapshot.reported_province'}, 'good_conduct_register.csv': {'good_conduct_id': 'source_record_id', 'operation_no': 'links.operation_reference_ciphertext', 'officer_nic_no': 'officer_uid', 'event_type': 'reported_event_type', 'event_date': 'reported_event_date', 'reference_no': 'reference_ciphertext', 'reason': 'reason_ciphertext', 'approving_authority': 'approval.authority_claim_ciphertext', 'approving_order_date': 'approval.reported_order_date', 'approving_order_no': 'approval.order_reference_ciphertext', 'reward_voucher_no': 'reward.voucher_reference_ciphertext', 'voucher_station_no': 'reward.reported_voucher_station_reference', 'voucher_application_date': 'reward.reported_application_date', 'reward_basis': 'reward.reported_basis', 'court_no': 'links.court_reference_ciphertext', 'property_value_stolen': 'reported_property_value_stolen', 'property_value_recovered': 'reported_property_value_recovered', 'accused_arrested': 'reported_accused_arrested', 'accused_convicted': 'reported_accused_convicted', 'date_of_conviction': 'reported_conviction_date', 'amount_recommended_rs': 'reward.reported_amount_recommended_rs', 'amount_sanctioned_rs': 'reward.reported_amount_sanctioned_rs', 'amount_paid_rs': 'reward.reported_amount_paid_rs', 'non_payment_reason': 'reward.non_payment_reason_ciphertext', 'recommending_asp_name': 'recommendation.actor_name_ciphertext', 'recommending_asp_nic': 'recommendation.actor_officer_uid', 'sanctioning_tier': 'sanction.reported_tier', 'sanctioning_authority_name': 'sanction.actor_name_ciphertext', 'sanctioning_authority_nic': 'sanction.actor_officer_uid', 'sanction_date': 'sanction.reported_date', 'payment_certified_date': 'payment.reported_certification_date', 'co_recipient_count': 'reported_co_recipient_count', 'private_informant_paid_rs': 'reward.reported_private_informant_payment_rs'}, 'bad_conduct_register.csv': {'punishment_id': 'source_record_id', 'officer_nic_no': 'officer_uid', 'originating_complaint_id': 'links.complaint_reference_ciphertext', 'detection_source': 'reported_detection_source', 'date_of_offence': 'reported_offence_date', 'charge_sheet_no': 'charge_sheet.reference_ciphertext', 'charge_sheet_date': 'charge_sheet.reported_date', 'offence_code': 'reported_offence_code', 'nature_of_offence': 'offence_description_ciphertext', 'offence_severity': 'reported_offence_severity', 'plea': 'reported_plea', 'inquiry_type': 'reported_inquiry_type', 'inquiry_officer_rank': 'inquiry.reported_officer_rank', 'finding': 'inquiry.finding_ciphertext', 'punishment_imposed': 'punishment.description_ciphertext', 'date_of_punishment': 'punishment.reported_date', 'punishment_notice_no': 'punishment.notice_reference_ciphertext', 'recovery_amount_rs': 'punishment.reported_recovery_amount_rs', 'promotion_bar_until': 'restriction.reported_promotion_bar_until', 'interdiction_start': 'restriction.reported_interdiction_start', 'interdiction_end': 'restriction.reported_interdiction_end', 'reduction_in_rank_enacted': 'reported_rank_reduction_enacted', 'hardship_transfer_enacted': 'reported_hardship_transfer_enacted', 'hardship_transfer_id': 'links.transfer_reference_ciphertext', 'appeal_filed': 'appeal.reported_filed', 'appeal_authority': 'appeal.authority_claim_ciphertext', 'appeal_outcome': 'appeal.outcome_ciphertext', 'appeal_decision_date': 'appeal.reported_decision_date', 'legal_status': 'reported_legal_status', 'approving_authority': 'approval.authority_claim_ciphertext', 'delegation_instrument': 'approval.delegation_reference_ciphertext'}}.items()})
DESTINATIONS = MappingProxyType({'officer_duty_periods.csv': 'mongodb.duty_periods', 'officer_firearms_expertise.csv': 'mongodb.firearms_assessments', 'good_conduct_register.csv': 'mongodb.good_conduct_records', 'bad_conduct_register.csv': 'mongodb.bad_conduct_records'})

# Observed abbreviations are mapped only in recording/supervisor rank fields.
# Mapping a source claim does not establish a historical rank or permission.
ACTOR_RANK_ALIASES = MappingProxyType({"ASP": "ASP", "CI": "CIP", "IP": "IP", "SP": "SP", "SSP": "SSP", "DIG": "DIG", "SDIG": "SDIG"})
ALIAS_FIELDS = frozenset({"period_recorded_by_authority_rank", "h1_supervisor_police_rank",
                         "h2_supervisor_police_rank", "annual_supervisor_police_rank"})
CATEGORIES = frozenset({"record_status", "year_rating", "class_of_shoot", "event_type", "reward_basis", "sanctioning_tier",
    "detection_source", "offence_code", "offence_severity", "plea", "inquiry_type", "legal_status"})
DATE_PAIRS = {"officer_duty_periods.csv": (("period_from", "period_to"),),
    "officer_firearms_expertise.csv": (), "good_conduct_register.csv": (),
    "bad_conduct_register.csv": (("interdiction_start", "interdiction_end"),)}
STATION_PAIRS = {"officer_duty_periods.csv": ("period_station_code", "period_station_name"),
    "officer_firearms_expertise.csv": ("gun_performance_station_code", "gun_performance_station_name")}
INTEGER_FIELDS = frozenset({"co_recipient_count", "gun_performance_year"})
STATUS_WORDS = frozenset({"H1", "H2", "HALF", "HALF1", "HALF2", "FIRST", "SECOND", "1", "2", "FULL", "FULLY", "YEAR",
    "ANNUAL", "COMPLETE", "COMPLETED", "INCOMPLETE", "PARTIAL", "ONLY", "PENDING", "MISSING", "NOT", "AVAILABLE",
    "RECORDED", "ASSESSMENT", "PRACTICE", "FINAL", "PROVISIONAL", "UNASSESSED", "IN", "PROGRESS"})


def status_vocabulary(value):
    """Emit only status words from a fixed vocabulary; arbitrary text stays private."""
    text = value.strip()
    words = re.split(r"[ _+()/\-]+", text.upper())
    if not text:
        return "MISSING"
    return text if len(text) <= 64 and all(word in STATUS_WORDS for word in words) else "UNREVIEWED_STATUS_TEXT"


@dataclass(frozen=True)
class ActivityField:
    source_column: str
    target_field: str
    source_value: str = field(repr=False)
    value: object = field(repr=False)
    status: str
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class ActivityPlan:
    filename: str
    officer_uid: UUID
    fields: tuple[ActivityField, ...] = field(repr=False)
    review_issues: tuple[str, ...] = ()
    observations: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = (
        "AUTHORITY_IDENTITY_RANK_SCOPE_AND_DELEGATION_UNASSESSED", "IDENTIFIER_TEMPORAL_ELIGIBILITY_UNASSESSED",
        "SOURCE_INDEPENDENCE_UNVERIFIED", "REPORTED_DATE_SEMANTICS_UNASSESSED",
        "REFERENCE_AUTHENTICITY_AND_LINKAGE_UNASSESSED", "SNAPSHOT_APPLICABILITY_UNKNOWN",
        "ACTIVITY_EFFECT_COMPETENCY_AND_LEGAL_STATUS_UNASSESSED",
    )
    policy_version: str = ACTIVITY_PLAN_POLICY
    value_policy_version: str = SERVICE_VALUE_POLICY

    @property
    def needs_review(self):
        return bool(self.review_issues) or any(f.status == "REVIEW_REQUIRED" for f in self.fields)


def plan_activity(filename, row, *, officer_uid, actor_candidates=None, station_candidates=None):
    """Parse supplied cells, preserving exact originals and all unresolved semantics."""
    if filename not in ROUTES or not isinstance(officer_uid, UUID):
        raise ValueError("Supported activity source and officer UUID required.")
    if set(row) != set(HEADERS[filename]) or any(not isinstance(v, str) for v in row.values()):
        raise ValueError("Exact source fields and original text required.")
    actors, stations = actor_candidates or {}, station_candidates or {}
    fields = []
    required = {SOURCE_KEYS[filename], "officer_nic_no"}
    for name, target in ROUTES[filename].items():
        original, text = row[name], row[name].strip()
        if not text:
            fields.append(ActivityField(name, target, original, None,
                "REVIEW_REQUIRED" if name in required else "MISSING", ("REQUIRED_VALUE_MISSING",) if name in required else ()))
            continue
        value, status, issues = text, "PARSED", ()
        if "\x00" in original:
            value, status, issues = None, "REVIEW_REQUIRED", ("NUL_TEXT_VALUE",)
        elif name == "officer_nic_no":
            value, issues = officer_uid, ("IDENTIFIER_TEMPORAL_ELIGIBILITY_UNASSESSED",)
        elif name in DATES[filename]:
            try:
                if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text) is None:
                    raise ValueError()
                value = date.fromisoformat(text)
                issues = ("REPORTED_DATE_NOT_ACCEPTED_EFFECTIVE_TIME",)
            except ValueError:
                value, status, issues = None, "REVIEW_REQUIRED", ("INVALID_OR_UNSUPPORTED_DATE",)
        elif name in RANK_FIELDS[filename]:
            value = RANKS.get(text)
            if value is None and name in ALIAS_FIELDS:
                value = ACTOR_RANK_ALIASES.get(text)
            status = "PARSED" if value is not None else "REVIEW_REQUIRED"
            issues = ("REPORTED_RANK_NOT_AUTHORITY",) if value is not None else ("UNMAPPED_REPORTED_RANK",)
        elif name in ACTOR_FIELDS[filename]:
            value = actors.get(name)
            status = "PARSED" if isinstance(value, UUID) else "REVIEW_REQUIRED"
            issues = ("ACTOR_CANDIDATE_NOT_HISTORICAL_AUTHORITY",) if status == "PARSED" else ("ACTOR_IDENTITY_UNRESOLVED",)
        elif name in BOOLEAN_FIELDS[filename] or name in {"accused_arrested", "accused_convicted"}:
            if text in {"TRUE", "FALSE"}:
                value, issues = text == "TRUE", ("REPORTED_FLAG_NOT_VERIFICATION",)
            else:
                value, status, issues = None, "REVIEW_REQUIRED", ("UNMAPPED_BOOLEAN_TEXT",)
        elif name in NUMERIC_FIELDS[filename] and name not in {"accused_arrested", "accused_convicted"}:
            try:
                if name in INTEGER_FIELDS:
                    if re.fullmatch(r"[0-9]+", text) is None:
                        raise ValueError()
                    value = int(text)
                else:
                    value = Decimal(text)
                    if not value.is_finite():
                        raise ValueError()
                if value < 0:
                    raise ValueError()
                issues = ("REPORTED_NUMERIC_BASIS_POLICY_UNASSESSED",)
            except (ValueError, InvalidOperation):
                value, status, issues = None, "REVIEW_REQUIRED", ("INVALID_REPORTED_NONNEGATIVE_NUMBER",)
        elif name in CATEGORIES or name == "current_unit_type":
            value, issues = {"reported_label": text, "code": None}, ("CATEGORY_OR_UNIT_MEANING_UNASSESSED",)
        elif name.endswith("_signature"):
            issues = ("SIGNATURE_REFERENCE_NOT_AUTHENTICATED",)
        elif name.endswith("_station_code") or name == "voucher_station_no":
            # Historical station applicability and voucher numbering remain separate questions.
            issues = ("STATION_REFERENCE_AND_HISTORICAL_SCOPE_UNASSESSED",)
        elif any(word in name for word in ("authority", "reference", "_id", "court_no", "operation_no", "delegation")):
            issues = ("DOCUMENT_OR_SOURCE_REFERENCE_LINKAGE_UNASSESSED",)
        fields.append(ActivityField(name, target, original, value, status, issues))
    reviews, observations = [], []
    values = {f.source_column: f.value for f in fields}
    for first, last in DATE_PAIRS[filename]:
        if type(values[first]) is date and type(values[last]) is date and values[last] < values[first]:
            reviews.append("REPORTED_INTERVAL_END_BEFORE_START")
    if filename in STATION_PAIRS:
        code_name, label_name = STATION_PAIRS[filename]
        code, label = row[code_name].strip(), row[label_name].strip()
        if bool(code) != bool(label):
            reviews.append("STATION_CODE_NAME_INCOMPLETE")
        elif code and (code not in stations.get(label, ()) or len(stations.get(label, ())) != 1):
            reviews.append("SOURCE_SCOPED_STATION_REFERENCE_UNRESOLVED")
    if filename == "officer_firearms_expertise.csv":
        shape = h2_shape(row)
        observations.append("H2_" + shape)
        if shape == "PARTIAL_CORE":
            reviews.append("H2_CORE_PARTIALLY_POPULATED")
        if shape == "ALL_CORE_MISSING" and row["h2_supervisor_police_signature"].strip():
            reviews.append("H2_SIGNATURE_WITHOUT_CORE_EVIDENCE")
        observations.append(total_observation(row))
        for name in ("h1_supervisor_police_signature", "h2_supervisor_police_signature", "annual_supervisor_police_signature"):
            if not row[name].strip():
                observations.append(name.upper() + "_MISSING_NOT_AUTHENTICITY_RESULT")
    if filename == "bad_conduct_register.csv":
        if not row["date_of_punishment"].strip():
            observations.append("PUNISHMENT_DATE_MISSING_EFFECT_UNKNOWN")
        if not row["delegation_instrument"].strip():
            observations.append("DELEGATION_REFERENCE_MISSING_NOT_PROOF_OF_NO_AUTHORITY")
    return ActivityPlan(filename, officer_uid, tuple(fields), tuple(reviews), tuple(observations))


def validate_activity_routing(document):
    for filename, routes in ROUTES.items():
        matches = [f for f in document.get("files", []) if f.get("filename") == filename]
        if len(matches) != 1 or len(matches[0]["fields"]) != len(routes):
            raise ValueError("Activity routing coverage differs.")
        fields = matches[0]["fields"]
        if {f["source_column"] for f in fields} != set(routes) or any(
            f["target_field"] != routes[f["source_column"]] or f["destination"] != DESTINATIONS[filename]
            or f.get("preserve_in_protected_staging") is not True for f in fields):
            raise ValueError("Activity routing or protected staging differs.")
