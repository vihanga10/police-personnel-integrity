"""Plan transfer/promotion claims without approving authority or reconstructing state."""
from dataclasses import dataclass, field, replace
from datetime import date
from decimal import Decimal
import re
from types import MappingProxyType
from uuid import UUID

from app.identity.inspect_history_sources import DATES, HEADERS
from app.identity.service_values import RANKS, UNITS, SERVICE_VALUE_POLICY

HISTORY_PLAN_POLICY = "PF_HISTORY_PLAN_V1"
# Freeze the agreed field routes; no source column may disappear during planning.
ROUTES = MappingProxyType({
    name: MappingProxyType(fields)
    for name, fields in {'promotion_history.csv': {'promotion_id': 'source_record_id',
                           'officer_nic_no': 'officer_uid',
                           'from_rank': 'from_rank_code',
                           'to_rank': 'to_rank_code',
                           'is_same_unit': 'reported_same_unit',
                           'from_unit_name': 'from_unit_reference',
                           'to_unit_name': 'to_unit_reference',
                           'effective_date': 'effective_date',
                           'new_unit_arrive_date': 'reported_arrival_date',
                           'current_unit_departure_date': 'reported_departure_date',
                           'promotion_category': 'promotion_category_code',
                           'promotion_reason': 'reason_ciphertext',
                           'regimental_no': 'regimental_identifier_reference',
                           'previous_police_no': 'previous_police_number_ciphertext',
                           'new_police_no': 'new_police_number_ciphertext',
                           'promotion_order_date': 'order_date',
                           'promotion_order_no': 'order_reference_ciphertext',
                           'promotion_authority': 'authority_claim_ciphertext',
                           'promotion_authority_signed_date': 'authority_signed_date',
                           'RTM_CRTM': 'uninterpreted_reference_ciphertext',
                           'years_in_previous_rank': 'reported_years_in_previous_rank'},
 'transfer_history.csv': {'transfer_id': 'source_record_id',
                          'officer_nic_no': 'officer_uid',
                          'police_id_at_transfer': 'source_identifier_reference',
                          'previous_police_no': 'previous_police_number_ciphertext',
                          'new_police_no': 'new_police_number_ciphertext',
                          'from_station_code': 'from_station_reference',
                          'from_station_name': 'reported_from_station_name',
                          'from_unit_type': 'from_unit_type_code',
                          'from_unit_name': 'from_unit_reference',
                          'from_division': 'reported_from_division',
                          'from_province': 'reported_from_province',
                          'from_rank': 'from_rank_code',
                          'to_station_code': 'to_station_reference',
                          'to_station_name': 'reported_to_station_name',
                          'to_unit_type': 'to_unit_type_code',
                          'to_unit_name': 'to_unit_reference',
                          'to_division': 'reported_to_division',
                          'to_province': 'reported_to_province',
                          'to_rank': 'to_rank_code',
                          'departure_date': 'departure_date',
                          'effective_date': 'effective_date',
                          'arrival_date': 'arrival_date',
                          'transfer_type': 'transfer_type_code',
                          'transfer_authority': 'authority_claim_ciphertext',
                          'transfer_order_no': 'order_reference_ciphertext',
                          'transfer_signed_date': 'signed_date',
                          'transfer_reason': 'reason_ciphertext',
                          'transfer_reason_category': 'reason_category_code',
                          'transfer_requested_by': 'requester_claim_ciphertext',
                          'originating_complaint_id': 'complaint_reference',
                          'is_same_unit': 'reported_same_unit',
                          'days_in_previous_posting': 'reported_days_in_previous_posting',
                          'is_cancelled': 'reported_cancelled',
                          'cancellation_ref': 'cancellation_reference_ciphertext',
                          'cancellation_date': 'cancellation_date'}}.items()
})
REQUIRED = {
    "transfer_history.csv": frozenset({"transfer_id", "officer_nic_no", "to_rank", "effective_date", "is_same_unit", "is_cancelled"}),
    "promotion_history.csv": frozenset({"promotion_id", "officer_nic_no", "from_rank", "to_rank", "effective_date", "is_same_unit"}),
}
BOOL_FIELDS = frozenset({"is_same_unit", "is_cancelled"})
BOOL_TEXT = MappingProxyType({"TRUE": True, "FALSE": False})
RANK_FIELDS = frozenset({"from_rank", "to_rank"})
UNIT_TYPES = frozenset({"from_unit_type", "to_unit_type"})
UNIT_NAMES = frozenset({"from_unit_name", "to_unit_name"})
CATEGORY_FIELDS = frozenset({"promotion_category", "transfer_type", "transfer_reason_category"})
REFERENCE_FIELDS = frozenset({"promotion_authority", "transfer_authority", "transfer_requested_by",
    "originating_complaint_id", "cancellation_ref", "RTM_CRTM", "regimental_no", "police_id_at_transfer"})


@dataclass(frozen=True)
class HistoryField:
    source_column: str
    target_field: str
    source_value: str = field(repr=False)
    value: object = field(repr=False)
    status: str
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class HistoryPlan:
    filename: str
    officer_uid: UUID
    fields: tuple[HistoryField, ...] = field(repr=False)
    review_issues: tuple[str, ...] = ()
    observations: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = (
        "IDENTIFIER_TEMPORAL_ELIGIBILITY_UNASSESSED", "SOURCE_INDEPENDENCE_UNVERIFIED",
        "AUTHORITY_IDENTITY_UNRESOLVED", "AUTHORITY_POLICY_UNASSESSED",
        "REPORTED_EFFECTIVE_DATE_SEMANTICS_UNASSESSED", "UNIT_REFERENCE_UNRESOLVED",
    )
    policy_version: str = HISTORY_PLAN_POLICY
    value_policy_version: str = SERVICE_VALUE_POLICY

    @property
    def needs_review(self):
        return bool(self.review_issues) or any(f.status == "REVIEW_REQUIRED" for f in self.fields)


def plan_history(filename, row, *, officer_uid, station_candidates=None):
    """Preserve missing initial postings, cancelled orders and exact source strings."""
    if filename not in ROUTES or not isinstance(officer_uid, UUID):
        raise ValueError("Supported source and established officer UUID required.")
    if set(row) != set(HEADERS[filename]) or any(not isinstance(v, str) for v in row.values()):
        raise ValueError("Historical rows require the exact text-valued source fields.")
    fields = []
    for name, target in ROUTES[filename].items():
        original, text = row[name], row[name].strip()
        if not text:
            required = name in REQUIRED[filename]
            fields.append(HistoryField(name, target, original, None, "REVIEW_REQUIRED" if required else "MISSING",
                                       ("REQUIRED_VALUE_MISSING",) if required else ()))
            continue
        value, status, issues = text, "PARSED", ()
        # Narrative newlines remain intact. NUL is flagged, never removed.
        if "\x00" in original:
            value, status, issues = None, "REVIEW_REQUIRED", ("NUL_TEXT_VALUE",)
        elif name in DATES[filename]:
            if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text) is None:
                value, status, issues = None, "REVIEW_REQUIRED", ("UNSUPPORTED_DATE_FORMAT",)
            else:
                try:
                    value = date.fromisoformat(text)
                    issues = ("REPORTED_DATE_SEMANTICS_UNASSESSED",)
                except ValueError:
                    value, status, issues = None, "REVIEW_REQUIRED", ("INVALID_CALENDAR_DATE",)
        elif name in BOOL_FIELDS:
            if text not in BOOL_TEXT:
                value, status, issues = None, "REVIEW_REQUIRED", ("UNMAPPED_BOOLEAN_TEXT",)
            else:
                value = BOOL_TEXT[text]
        elif name in RANK_FIELDS or name in UNIT_TYPES:
            values = RANKS if name in RANK_FIELDS else UNITS
            value = values.get(text)
            if value is None:
                status, issues = "REVIEW_REQUIRED", ("UNMAPPED_REPORTED_RANK" if name in RANK_FIELDS else "UNMAPPED_REPORTED_UNIT_TYPE",)
            elif name in UNIT_TYPES:
                issues = ("UNIT_IDENTITY_AND_HISTORICAL_SCOPE_UNASSESSED",)
        elif name in UNIT_NAMES:
            value, issues = {"reported_label": text, "resolution": "UNRESOLVED"}, ("UNIT_REFERENCE_UNRESOLVED",)
        elif name in CATEGORY_FIELDS:
            # No category dictionary has been approved from the inspected source.
            value, issues = {"reported_label": text, "code": None}, ("CATEGORY_VOCABULARY_UNASSESSED",)
        elif name == "officer_nic_no":
            value, issues = officer_uid, ("IDENTIFIER_TEMPORAL_ELIGIBILITY_UNASSESSED",)
        elif name == "days_in_previous_posting":
            if re.fullmatch(r"[0-9]{1,12}", text):
                value, issues = int(text), ("REPORTED_DURATION_NOT_RECONSTRUCTED_INTERVAL",)
            else:
                value, status, issues = None, "REVIEW_REQUIRED", ("INVALID_REPORTED_NONNEGATIVE_INTEGER",)
        elif name == "years_in_previous_rank":
            if re.fullmatch(r"[0-9]{1,12}(\.[0-9]{1,8})?", text):
                value, issues = Decimal(text), ("DURATION_BASIS_AND_PRECISION_UNASSESSED",)
            else:
                value, status, issues = None, "REVIEW_REQUIRED", ("INVALID_REPORTED_NONNEGATIVE_DECIMAL",)
        elif name in REFERENCE_FIELDS:
            issues = ("REFERENCE_IDENTITY_SCOPE_AND_VALIDITY_UNASSESSED",)
        elif name.endswith("_division") or name.endswith("_province"):
            issues = ("HIERARCHY_APPLICABILITY_UNASSESSED",)
        fields.append(HistoryField(name, target, original, value, status, issues))
    index = {f.source_column: number for number, f in enumerate(fields)}
    reviews, observations = [], []
    if filename == "transfer_history.csv":
        for prefix in ("from", "to"):
            code_name, label_name = prefix + "_station_code", prefix + "_station_name"
            code, label = fields[index[code_name]], fields[index[label_name]]
            if code.status == label.status == "MISSING":
                continue  # Non-station postings and initial history may lack both.
            if code.status == "REVIEW_REQUIRED" or label.status == "REVIEW_REQUIRED":
                continue
            if code.status == "MISSING" or label.status == "MISSING":
                reviews.append(prefix.upper() + "_STATION_CODE_NAME_INCOMPLETE")
                if code.status != "MISSING":
                    fields[index[code_name]] = replace(code, value=None, status="REVIEW_REQUIRED",
                        issues=("STATION_REFERENCE_INCOMPLETE",))
            elif station_candidates is None or tuple(station_candidates.get(label.source_value.strip(), ())) != (code.source_value.strip(),):
                fields[index[code_name]] = replace(code, value=None, status="REVIEW_REQUIRED", issues=("STATION_REFERENCE_UNRESOLVED_OR_CONFLICTING",))
            else:
                fields[index[code_name]] = replace(code, issues=("STATION_REFERENCE_SOURCE_SCOPED_HISTORICAL_APPLICABILITY_UNKNOWN",))
        cancellation = fields[index["is_cancelled"]]
        if cancellation.status == "PARSED":
            evidence = [fields[index[f]] for f in ("cancellation_ref", "cancellation_date")]
            if cancellation.value and any(f.status == "MISSING" for f in evidence):
                reviews.append("CANCELLED_CLAIM_WITH_INCOMPLETE_CANCELLATION_EVIDENCE")
            elif not cancellation.value and any(f.status != "MISSING" for f in evidence):
                reviews.append("CANCELLATION_EVIDENCE_WITH_FALSE_FLAG")
            if cancellation.value:
                observations.append("SOURCE_REPORTS_CANCELLED_TRANSFER_PRESERVE_ORIGINAL")
        pairs = (("departure_date", "arrival_date", "REPORTED_ARRIVAL_PRECEDES_DEPARTURE"),
                 ("transfer_signed_date", "effective_date", "REPORTED_EFFECTIVE_DATE_PRECEDES_SIGNATURE"))
    else:
        pairs = (("current_unit_departure_date", "new_unit_arrive_date", "REPORTED_ARRIVAL_PRECEDES_DEPARTURE"),
                 ("promotion_order_date", "effective_date", "REPORTED_EFFECTIVE_DATE_PRECEDES_ORDER"),
                 ("promotion_authority_signed_date", "effective_date", "REPORTED_EFFECTIVE_DATE_PRECEDES_SIGNATURE"))
    # Chronology observations are not automatic invalidity findings: backdating,
    # retroactive effect and cancellation require separate policy evidence.
    for earlier, later, issue in pairs:
        first, second = fields[index[earlier]], fields[index[later]]
        if type(first.value) is date and type(second.value) is date and second.value < first.value:
            observations.append(issue)
    uncertainties = HistoryPlan.__dataclass_fields__["uncertainties"].default
    uncertainties += (("CANCELLATION_EFFECT_UNASSESSED",) if filename == "transfer_history.csv" else ("RTM_CRTM_MEANING_UNASSESSED",))
    return HistoryPlan(filename, officer_uid, tuple(fields), tuple(reviews), tuple(observations), uncertainties)


def validate_history_routing(document):
    for filename, routes in ROUTES.items():
        files = [f for f in document.get("files", []) if f.get("filename") == filename]
        destination = "mongodb.transfer_events" if filename == "transfer_history.csv" else "mongodb.promotion_events"
        if len(files) != 1 or len(files[0]["fields"]) != len(routes):
            raise ValueError("Historical routing source/coverage differs.")
        for item in files[0]["fields"]:
            if item["source_column"] not in routes or item["target_field"] != routes[item["source_column"]] or item["destination"] != destination or item.get("preserve_in_protected_staging") is not True:
                raise ValueError("Historical field routing differs.")
        if {f["source_column"] for f in files[0]["fields"]} != set(routes):
            raise ValueError("Historical routing has duplicate/missing fields.")
