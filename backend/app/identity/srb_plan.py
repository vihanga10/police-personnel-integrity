"""Preserve SRB claims; do not approve restrictions, overrides or number validity."""
from dataclasses import dataclass, field, replace
from datetime import date
import re
from types import MappingProxyType
from uuid import UUID

from app.identity.inspect_srb_sources import HEADERS, DATES, RANK_FIELDS
from app.identity.normalization import normalize_identifier, IdentifierInputError
from app.identity.service_values import RANKS, SERVICE_VALUE_POLICY

SRB_PLAN_POLICY = "SRB_PLAN_V1"
ROUTES = MappingProxyType({name: MappingProxyType(fields) for name, fields in {'officer_police_numbers.csv': {'police_no': 'police_number_ciphertext', 'officer_nic_no': 'officer_uid', 'number_type': 'number_type_code', 'rank_band': 'reported_rank_band_code', 'rank_band_label': 'reported_rank_band_label', 'valid_from': 'valid_from', 'valid_to': 'valid_to', 'issued_under': 'issue_authority_claim_ciphertext', 'issue_reason': 'issue_reason_ciphertext'}, 'officer_restrictions.csv': {'restriction_id': 'source_record_id', 'officer_nic_no': 'officer_uid', 'restriction_category': 'reported_category', 'restriction_basis': 'reported_basis_ciphertext', 'restriction_effect': 'reported_effect_ciphertext', 'restriction_scope': 'reported_scope_ciphertext', 'restricted_station_code': 'scope.reported_station_reference', 'restricted_station_name': 'scope.reported_station_name', 'restricted_division': 'scope.reported_division', 'restricted_district': 'scope.reported_district', 'restricted_province': 'scope.reported_province', 'restriction_reason': 'reason_ciphertext', 'reference_paper_no': 'document_reference_ciphertext', 'restriction_start_date': 'reported_effective_start_date', 'restriction_record_date': 'reported_source_record_date', 'restriction_recorded_officer_nic': 'recording_actor.officer_uid', 'restriction_recorded_officer_rank': 'recording_actor.reported_rank_code', 'restriction_removal_date': 'reported_effective_removal_date', 'restriction_removal_record_date': 'reported_source_removal_record_date', 'restriction_removed_officer_nic': 'removal_actor.officer_uid', 'restriction_removed_officer_rank': 'removal_actor.reported_rank_code', 'restriction_status': 'reported_source_status', 'restriction_verifiable': 'reported_source_verifiable', 'override_recorded': 'reported_override_recorded'}, 'restriction_overrides.csv': {'override_id': 'source_record_id', 'restriction_id': 'restriction_reference', 'officer_nic_no': 'officer_uid', 'transfer_id': 'transfer_reference', 'override_reference': 'document_reference_ciphertext', 'override_ground': 'reported_ground_ciphertext', 'override_reason': 'reason_ciphertext', 'override_authority_nic': 'authority.actor_officer_uid', 'override_authority_rank': 'authority.reported_rank_code', 'override_date': 'reported_override_date'}}.items()})
DESTINATIONS = MappingProxyType({'officer_police_numbers.csv': 'mongodb.police_number_intervals', 'officer_restrictions.csv': 'mongodb.restriction_records', 'restriction_overrides.csv': 'mongodb.restriction_overrides'})
REQUIRED = {
    "officer_police_numbers.csv": frozenset({"police_no", "officer_nic_no", "number_type", "valid_from"}),
    "officer_restrictions.csv": frozenset({"restriction_id", "officer_nic_no", "restriction_start_date", "restriction_record_date"}),
    "restriction_overrides.csv": frozenset(HEADERS["restriction_overrides.csv"]),
}
ACTORS = frozenset({"restriction_recorded_officer_nic", "restriction_removed_officer_nic", "override_authority_nic"})
BOOLS = frozenset({"restriction_verifiable", "override_recorded"})
CATEGORIES = frozenset({"number_type", "rank_band", "rank_band_label", "restriction_category", "restriction_status"})


@dataclass(frozen=True)
class SourceReference:
    """A recovered source row candidate, never an accepted legal relationship."""
    filename: str
    raw_record_id: str
    officer_uid: UUID

    def __post_init__(self):
        if self.filename not in {"officer_restrictions.csv", "transfer_history.csv"} or not isinstance(self.officer_uid, UUID) or not isinstance(self.raw_record_id, str) or re.fullmatch("[0-9a-f]{64}", self.raw_record_id) is None:
            raise ValueError("Source reference binding differs.")


@dataclass(frozen=True)
class SrbField:
    source_column: str
    target_field: str
    source_value: str = field(repr=False)
    value: object = field(repr=False)
    status: str
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class SrbPlan:
    filename: str
    officer_uid: UUID
    fields: tuple[SrbField, ...] = field(repr=False)
    review_issues: tuple[str, ...] = ()
    observations: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = (
        "IDENTIFIER_TEMPORAL_ELIGIBILITY_UNASSESSED", "SOURCE_INDEPENDENCE_UNVERIFIED",
        "AUTHORITY_POLICY_AND_DELEGATION_UNASSESSED", "REPORTED_DATE_BOUNDARIES_UNASSESSED",
    )
    policy_version: str = SRB_PLAN_POLICY
    value_policy_version: str = SERVICE_VALUE_POLICY

    @property
    def needs_review(self):
        return bool(self.review_issues) or any(f.status == "REVIEW_REQUIRED" for f in self.fields)


def plan_srb(filename, row, *, officer_uid, station_candidates=None, actor_candidates=None, reference_candidates=None, linked_override_subjects=None):
    """Assess syntax and source-qualified candidate relationships, preserving all text."""
    if filename not in ROUTES or not isinstance(officer_uid, UUID):
        raise ValueError("Supported source and established officer UUID required.")
    if set(row) != set(HEADERS[filename]) or any(not isinstance(v, str) for v in row.values()):
        raise ValueError("SRB rows require exact text-valued source fields.")
    fields = []
    for name, target in ROUTES[filename].items():
        original, text = row[name], row[name].strip()
        if not text:
            required = name in REQUIRED[filename]
            fields.append(SrbField(name, target, original, None, "REVIEW_REQUIRED" if required else "MISSING",
                ("REQUIRED_VALUE_MISSING",) if required else ()))
            continue
        value, status, issues = text, "PARSED", ()
        if "\x00" in original:
            value, status, issues = None, "REVIEW_REQUIRED", ("NUL_TEXT_VALUE",)
        elif name in DATES[filename]:
            try:
                if re.fullmatch("[0-9]{4}-[0-9]{2}-[0-9]{2}", text) is None:
                    raise ValueError("Non-ISO date.")
                value = date.fromisoformat(text)
                issues = ("REPORTED_DATE_SEMANTICS_UNASSESSED",)
            except ValueError:
                value, status, issues = None, "REVIEW_REQUIRED", ("UNSUPPORTED_OR_INVALID_DATE",)
        elif name in BOOLS:
            if text not in {"TRUE", "FALSE"}:
                value, status, issues = None, "REVIEW_REQUIRED", ("UNMAPPED_BOOLEAN_TEXT",)
            else:
                value, issues = text == "TRUE", ("SOURCE_FLAG_NOT_VERIFICATION_RESULT",)
        elif name in RANK_FIELDS[filename]:
            value = RANKS.get(text)
            if value is None:
                status, issues = "REVIEW_REQUIRED", ("UNMAPPED_REPORTED_RANK",)
            else:
                issues = ("REPORTED_RANK_NOT_AUTHORITY_VERIFICATION",)
        elif name == "officer_nic_no":
            value, issues = officer_uid, ("IDENTIFIER_TEMPORAL_ELIGIBILITY_UNASSESSED",)
        elif name in ACTORS:
            try:
                normalize_identifier(text, identifier_type="NIC")
                candidate = (actor_candidates or {}).get(name)
                if not isinstance(candidate, UUID):
                    value, status, issues = None, "REVIEW_REQUIRED", ("ACTOR_IDENTITY_UNRESOLVED",)
                else:
                    value, issues = candidate, ("ACTOR_CANDIDATE_NOT_HISTORICAL_AUTHORITY",)
            except IdentifierInputError:
                value, status, issues = None, "REVIEW_REQUIRED", ("UNUSABLE_ACTOR_IDENTIFIER",)
        elif filename == "restriction_overrides.csv" and name in {"restriction_id", "transfer_id"}:
            candidates = tuple((reference_candidates or {}).get(name, ()))
            expected = "officer_restrictions.csv" if name == "restriction_id" else "transfer_history.csv"
            if len(candidates) != 1 or not isinstance(candidates[0], SourceReference) or candidates[0].filename != expected:
                value, status, issues = None, "REVIEW_REQUIRED", ("REFERENCE_UNRESOLVED_OR_AMBIGUOUS",)
            elif candidates[0].officer_uid != officer_uid:
                value, status, issues = None, "REVIEW_REQUIRED", ("REFERENCE_SUBJECT_CONFLICT",)
            else:
                value, issues = candidates[0].raw_record_id, ("SOURCE_REFERENCE_MATCH_NOT_OVERRIDE_AUTHORIZATION",)
        elif name in CATEGORIES:
            value, issues = {"reported_label": text, "code": None}, ("CATEGORY_VOCABULARY_UNASSESSED",)
        elif name.startswith("restricted_"):
            issues = ("SCOPE_MEANING_AND_HISTORICAL_HIERARCHY_UNASSESSED",)
        elif name in {"issued_under", "reference_paper_no", "override_reference"}:
            issues = ("DOCUMENT_REFERENCE_AUTHENTICITY_UNASSESSED",)
        elif name in {"restriction_basis", "restriction_effect", "restriction_scope", "override_ground"}:
            issues = ("REPORTED_DESCRIPTION_NOT_ACCEPTED_LEGAL_EFFECT",)
        # Police numbers remain text, including leading zeros; raw originals never change.
        fields.append(SrbField(name, target, original, value, status, issues))
    index = {f.source_column: i for i, f in enumerate(fields)}
    reviews, observations = [], []
    def item(name):
        return fields[index[name]]
    if filename == "officer_restrictions.csv":
        code, label = item("restricted_station_code"), item("restricted_station_name")
        if code.status == label.status == "MISSING":
            pass  # Restrictions can have broader scopes; do not invent a station.
        elif "REVIEW_REQUIRED" not in {code.status, label.status}:
            if "MISSING" in {code.status, label.status}:
                reviews.append("STATION_CODE_NAME_INCOMPLETE")
                if code.status != "MISSING":
                    fields[index[code.source_column]] = replace(code, value=None, status="REVIEW_REQUIRED", issues=("STATION_REFERENCE_INCOMPLETE",))
            elif station_candidates is None or tuple(station_candidates.get(label.source_value.strip(), ())) != (code.source_value.strip(),):
                fields[index[code.source_column]] = replace(code, value=None, status="REVIEW_REQUIRED", issues=("STATION_REFERENCE_UNRESOLVED_OR_CONFLICTING",))
            else:
                fields[index[code.source_column]] = replace(code, issues=("STATION_REFERENCE_SOURCE_SCOPED_HISTORICAL_APPLICABILITY_UNKNOWN",))
        removal = [item(n) for n in ("restriction_removal_date", "restriction_removal_record_date", "restriction_removed_officer_nic", "restriction_removed_officer_rank")]
        if any(f.status != "MISSING" for f in removal) and any(f.status == "MISSING" for f in removal):
            reviews.append("REMOVAL_EVIDENCE_INCOMPLETE")
        if item("restriction_removal_date").status == "MISSING":
            observations.append("MISSING_REMOVAL_NOT_PROOF_OF_ACTIVE_RESTRICTION")
        # A source flag must be compared with supplied override rows, not trusted alone.
        if linked_override_subjects is not None:
            subjects = tuple(linked_override_subjects)
            if any(not isinstance(subject, UUID) for subject in subjects):
                raise ValueError("Override subject candidates must be UUIDs.")
            if any(subject != officer_uid for subject in subjects):
                reviews.append("LINKED_OVERRIDE_SUBJECT_CONFLICT")
            flag = item("override_recorded")
            matching = any(subject == officer_uid for subject in subjects)
            if flag.status == "PARSED" and flag.value != matching:
                reviews.append("OVERRIDE_FLAG_REFERENCE_INCONSISTENT")
        pairs = (("restriction_start_date", "restriction_removal_date"),
                 ("restriction_start_date", "restriction_record_date"),
                 ("restriction_removal_date", "restriction_removal_record_date"))
        uncertainty = "RESTRICTION_EFFECT_AND_STATUS_UNASSESSED"
    elif filename == "officer_police_numbers.csv":
        pairs = (("valid_from", "valid_to"),)
        if item("valid_to").status == "MISSING":
            observations.append("MISSING_END_NOT_EXPLICIT_OPEN_INTERVAL")
        uncertainty = "NUMBER_ELIGIBILITY_AND_RANK_BAND_MEANING_UNASSESSED"
    else:
        pairs = ()
        observations.append("OVERRIDE_CLAIM_PRESERVED_NOT_APPLIED")
        uncertainty = "OVERRIDE_EFFECT_SCOPE_DURATION_AND_AUTHORITY_UNASSESSED"
    # Adverse date ordering is flagged for review; no corrected date is generated.
    for first, last in pairs:
        if type(item(first).value) is date and type(item(last).value) is date and item(last).value < item(first).value:
            observations.append(last.upper() + "_PRECEDES_" + first.upper())
            reviews.append(last.upper() + "_PRECEDES_" + first.upper())
    return SrbPlan(filename, officer_uid, tuple(fields), tuple(reviews), tuple(observations), SrbPlan.__dataclass_fields__["uncertainties"].default + (uncertainty,))


def validate_srb_routing(document):
    """Require complete, nonduplicated protected routing for each source column."""
    for filename, routes in ROUTES.items():
        files = [f for f in document.get("files", []) if f.get("filename") == filename]
        if len(files) != 1 or len(files[0]["fields"]) != len(routes):
            raise ValueError("SRB routing coverage differs.")
        fields = files[0]["fields"]
        if {f["source_column"] for f in fields} != set(routes):
            raise ValueError("SRB routing repeats or omits fields.")
        if any(f["target_field"] != routes[f["source_column"]] or f["destination"] != DESTINATIONS[filename] or f.get("preserve_in_protected_staging") is not True for f in fields):
            raise ValueError("SRB protected routing differs.")


def bounded_intersection_count(periods):
    """Observe positive intersections only; unknown ends and touching bounds are excluded."""
    bounded = sorted((start, end) for start, end in periods if type(start) is date and type(end) is date and end > start)
    count = 0
    for i, (start, end) in enumerate(bounded):
        for later_start, later_end in bounded[i + 1:]:
            if later_start >= end:
                break
            count += max(start, later_start) < min(end, later_end)
    return count
