"""Convert validated plans into logical normalized records for protected storage."""

import json
import re
from dataclasses import dataclass, field
from uuid import UUID
from app.identity.profile_plan import ProfilePlan, PLAN_POLICY
from app.identity.profile_plan_crypto import _encoded


WRITER_POLICY = "PF_PROFILE_WRITER_V1"
PROTECTED_TABLES = frozenset({
    "officer_address_version", "officer_demographic_version", "officer_family_relation",
    "officer_physical_profile_version", "officer_previous_employment_version",
    "officer_restricted_profile_version",
})


@dataclass(frozen=True)
class LogicalRecord:
    table: str
    kind: str
    values: dict = field(repr=False)


def logical_records(plan):
    if not isinstance(plan, ProfilePlan) or plan.policy_version != PLAN_POLICY or plan.needs_review:
        raise ValueError("A fully parsed, supported profile plan is required.")
    groups = {}
    contacts = []
    for item in plan.fields:
        if item.value is None or item.table == "source_assertion":
            continue
        if item.table == "officer_contact_version":
            kind = "EMAIL" if item.source_column == "officer_email" else "MOBILE"
            contacts.append(LogicalRecord(item.table, kind, {"value": item.value}))
        else:
            groups.setdefault(item.table, {})[item.target_field] = _encoded(item.value)
    result = []
    for table, values in groups.items():
        kind = "PRESENT" if table == "officer_address_version" else "FATHER" if table == "officer_family_relation" else "PROFILE"
        result.append(LogicalRecord(table, kind, values))
    return tuple(sorted(result + contacts, key=lambda r: (r.table, r.kind)))


def storage_context(purpose, *, raw_record_id, officer_uid, record_id, table):
    if purpose not in {"ASSERTION", "DESTINATION", "RECEIPT"}:
        raise ValueError("Unsupported profile encryption purpose.")
    if not isinstance(officer_uid, UUID) or not isinstance(record_id, UUID):
        raise ValueError("Established officer and evidence UUIDs are required.")
    if not isinstance(raw_record_id, str) or re.fullmatch(r"[0-9a-f]{64}", raw_record_id) is None:
        raise ValueError("A validated raw record fingerprint is required.")
    allowed = PROTECTED_TABLES | {"officer_name_version", "officer_contact_version"}
    if (purpose == "DESTINATION" and table not in allowed) or (purpose == "ASSERTION" and table != "source_assertion") or (purpose == "RECEIPT" and table != "profile_transform_receipt"):
        raise ValueError("Profile encryption purpose and destination differ.")
    return json.dumps(["PF_PROFILE_STORAGE_V1", WRITER_POLICY, purpose,
                       raw_record_id, str(officer_uid), table, str(record_id)], separators=(",", ":"))
