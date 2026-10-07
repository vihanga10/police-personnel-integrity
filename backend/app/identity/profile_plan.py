"""In-memory PF profile mapping. No database writes or disclosure permission.

All source values are retained in memory for subsequent encrypted evidence.
Do not log, serialize or expose plans except through protected storage.
"""

import re
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal
from typing import Mapping

from app.identity.profile_values import map_category, parse_birth_date

PLAN_POLICY = "PF_PROFILE_PLAN_V1"
IDENTIFIER_FIELDS = frozenset({"officer_nic_no", "police_id", "regimental_no", "officer_tin_number"})
ROUTES = {
    "full_name": ("officer_name_version", "full_name"),
    "name_with_initials": ("officer_name_version", "name_with_initials"),
    "father_name": ("officer_family_relation", "related_person_name"),
    "gender": ("officer_demographic_version", "gender_code"),
    "date_of_birth": ("officer_demographic_version", "date_of_birth"),
    "age": ("source_assertion", "asserted_value_ciphertext"),
    "place_of_birth": ("officer_demographic_version", "place_of_birth"),
    "nationality": ("officer_demographic_version", "nationality_code"),
    "religion": ("officer_demographic_version", "religion_code"),
    "present_address": ("officer_address_version", "address_text"),
    "present_address_local_police_station_name": ("officer_address_version", "local_station_reference"),
    "height_cm": ("officer_physical_profile_version", "height_cm"),
    "chest_cm": ("officer_physical_profile_version", "chest_cm"),
    "blood_group": ("officer_restricted_profile_version", "blood_group_code"),
    "identifying_marks": ("officer_restricted_profile_version", "identifying_marks_ciphertext"),
    "mo_remark": ("officer_restricted_profile_version", "medical_officer_remark_ciphertext"),
    "marital_status": ("officer_demographic_version", "marital_status_code"),
    "prev_employment_dept": ("officer_previous_employment_version", "employer_department_name"),
    "officer_email": ("officer_contact_version", "contact_value_ciphertext"),
    "officer_mobile_number": ("officer_contact_version", "contact_value_ciphertext"),
}
EXPECTED_COLUMNS = IDENTIFIER_FIELDS | ROUTES.keys()
LENGTHS = {"full_name": 300, "name_with_initials": 250, "father_name": 300,
           "place_of_birth": 250, "prev_employment_dept": 300}


@dataclass(frozen=True)
class PlannedField:
    source_column: str
    table: str
    target_field: str
    source_value: str = field(repr=False)
    value: object = field(repr=False)
    status: str
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProfilePlan:
    fields: tuple[PlannedField, ...] = field(repr=False)
    policy_version: str = PLAN_POLICY

    @property
    def needs_review(self):
        return any(item.status == "REVIEW_REQUIRED" for item in self.fields)


def validate_routing(contract):
    files = [item for item in contract["files"] if item["filename"] == "officer_personal_information.csv"]
    if len(files) != 1:
        raise ValueError("Expected one personal-information routing entry.")
    entries = files[0]["fields"]
    by_name = {item["source_column"]: item for item in entries}
    if len(by_name) != len(entries) or set(by_name) != EXPECTED_COLUMNS:
        raise ValueError("Profile routing coverage differs from planner policy.")
    for name, (table, target) in ROUTES.items():
        item = by_name[name]
        if (item["destination"], item["target_field"]) != ("postgresql.identity." + table, target):
            raise ValueError("Profile routing destination differs from planner policy.")
        if item.get("preserve_in_protected_staging") is not True:
            raise ValueError("Original-value preservation must be enabled.")


def _email(value):
    # Conservative application subset. Other forms require review, not guessing.
    if len(value) > 254 or value.count("@") != 1 or not value.isascii():
        return None
    local, domain = value.split("@")
    if not local or len(local) > 64 or local.startswith(".") or local.endswith(".") or ".." in local:
        return None
    if re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local) is None:
        return None
    labels = domain.split(".")
    if len(labels) < 2 or any(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", p) is None for p in labels):
        return None
    return local + "@" + domain.lower()


def plan_profile(values: Mapping[str, str], *, snapshot_date: date | None = None,
                 phone_region: str | None = None,
                 station_candidates: Mapping[str, tuple[str, ...]] | None = None) -> ProfilePlan:
    if set(values) != EXPECTED_COLUMNS or any(not isinstance(v, str) for v in values.values()):
        raise ValueError("Profile columns or value types differ from the contract.")
    if snapshot_date is not None and type(snapshot_date) is not date:
        raise ValueError("Snapshot must be a date without a time component.")
    if phone_region not in (None, "LK"):
        raise ValueError("Unsupported phone-region policy.")
    result = []
    for name, (table, target) in ROUTES.items():
        original = values[name]
        value = original.strip()
        status, issues = "PARSED", ()
        if not value:
            value = None
            status = "REVIEW_REQUIRED" if name == "full_name" else "MISSING"
            issues = ("REQUIRED_NAME_MISSING",) if name == "full_name" else ()
        elif "\x00" in value:
            value, status, issues = None, "REVIEW_REQUIRED", ("UNSUPPORTED_NUL",)
        elif name in LENGTHS and len(value) > LENGTHS[name]:
            value, status, issues = None, "REVIEW_REQUIRED", ("TEXT_TOO_LONG",)
        elif name in {"gender", "nationality", "religion", "marital_status", "blood_group"}:
            parsed = map_category(name, original)
            value, status, issues = parsed.value, parsed.status, parsed.issues
        elif name == "date_of_birth":
            parsed = parse_birth_date(original, snapshot_date=snapshot_date)
            value, status, issues = parsed.value, parsed.status, parsed.issues
        elif name in {"height_cm", "chest_cm"}:
            if re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,2})?", value) is None or Decimal(value) <= 0:
                value, status, issues = None, "REVIEW_REQUIRED", ("INVALID_MEASUREMENT",)
            else:
                value = Decimal(value)
                issues = ("MEASUREMENT_DATE_UNKNOWN", "PLAUSIBILITY_POLICY_UNASSESSED")
        elif name == "age":
            if re.fullmatch(r"[0-9]{1,3}", value) is None:
                value, status, issues = None, "REVIEW_REQUIRED", ("INVALID_REPORTED_AGE",)
            else:
                value = int(value)
                birth = parse_birth_date(values["date_of_birth"], snapshot_date=snapshot_date)
                if snapshot_date is None or birth.value is None:
                    issues = ("AGE_COMPARISON_UNASSESSED",)
                else:
                    dob = birth.value
                    derived = snapshot_date.year - dob.year - ((snapshot_date.month, snapshot_date.day) < (dob.month, dob.day))
                    if value != derived:
                        status, issues = "REVIEW_REQUIRED", ("REPORTED_AGE_MISMATCH",)
        elif name == "present_address_local_police_station_name":
            candidates = () if station_candidates is None else station_candidates.get(value, ())
            if not isinstance(candidates, tuple) or any(not isinstance(x, str) or not x.strip() or len(x) > 100 for x in candidates):
                raise ValueError("Invalid trusted station-reference mapping.")
            if len(candidates) != 1:
                value, status, issues = None, "REVIEW_REQUIRED", ("STATION_REFERENCE_UNRESOLVED",)
            else:
                value = candidates[0]
        elif name == "officer_email":
            value = _email(value)
            if value is None:
                status, issues = "REVIEW_REQUIRED", ("EMAIL_OUTSIDE_SUPPORTED_SYNTAX",)
        elif name == "officer_mobile_number":
            if re.fullmatch(r"\+947[0-9]{8}", value):
                pass
            elif phone_region == "LK" and re.fullmatch(r"07[0-9]{8}", value):
                value = "+94" + value[1:]
            else:
                value, status, issues = None, "REVIEW_REQUIRED", ("MOBILE_NORMALIZATION_UNRESOLVED",)
        result.append(PlannedField(name, table, target, original, value, status, issues))
    return ProfilePlan(tuple(result))
