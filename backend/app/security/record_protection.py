"""Determine disclosure protection, not permission to access a record.

Inputs must come from trusted backend evidence resolution. This module does
not infer historical classification from current assignment, decrypt values,
grant a role access, or change stored classifications. NORMAL still requires
ordinary authorization and protected storage. WITHHOLD blocks disclosure
until the missing or conflicting evidence is resolved.
"""

from dataclasses import dataclass
from enum import Enum


POLICY_VERSION = "CID_CCIB_PROTECTION_V2"


class AssignmentProtection(Enum):
    ORDINARY = "ORDINARY"
    CID_CCIB = "CID_CCIB"
    UNRESOLVED = "UNRESOLVED"


class RecordClassification(Enum):
    ORDINARY = "ORDINARY"
    CID_CCIB_RESTRICTED = "CID_CCIB_RESTRICTED"
    UNASSESSED = "UNASSESSED"


class DisclosureCategory(Enum):
    # Only the subject officer's own name/NIC projection qualifies. Family
    # names, linked identities and entire profile objects do not qualify.
    OFFICER_NAME_NIC = "OFFICER_NAME_NIC"
    PERSONNEL_DETAILS = "PERSONNEL_DETAILS"
    # Trusted backend projection only: previous unit and service-period dates.
    # Full history rows, operations, duties and narratives never qualify.
    FORMER_CID_CCIB_SERVICE_PERIOD = "FORMER_CID_CCIB_SERVICE_PERIOD"


class ProtectionLevel(Enum):
    NORMAL = "NORMAL"
    RESTRICTED = "RESTRICTED"
    WITHHOLD = "WITHHOLD"


@dataclass(frozen=True)
class ProtectionDecision:
    level: ProtectionLevel
    reason_code: str
    policy_version: str = POLICY_VERSION


def required_protection(
    *,
    assignment: AssignmentProtection,
    record_classification: RecordClassification,
    category: DisclosureCategory,
) -> ProtectionDecision:
    """Combine current assignment and persistent record classification.

No defaults: the caller must explicitly supply each assessment. Untrusted
request fields must never be passed through as classification inputs.
"""
    for value, expected in (
        (assignment, AssignmentProtection),
        (record_classification, RecordClassification),
        (category, DisclosureCategory),
    ):
        if not isinstance(value, expected):
            raise TypeError("Protection inputs must use the declared enums.")

    if category is DisclosureCategory.OFFICER_NAME_NIC:
        return ProtectionDecision(
            ProtectionLevel.NORMAL, "IDENTITY_PROJECTION_REQUIRES_BASE_ACCESS"
        )
    if assignment is AssignmentProtection.UNRESOLVED:
        return ProtectionDecision(
            ProtectionLevel.WITHHOLD, "CURRENT_ASSIGNMENT_UNRESOLVED"
        )
    if record_classification is RecordClassification.UNASSESSED:
        return ProtectionDecision(
            ProtectionLevel.WITHHOLD, "RECORD_CLASSIFICATION_UNASSESSED"
        )
    if category is DisclosureCategory.FORMER_CID_CCIB_SERVICE_PERIOD:
        # Classification must be assessed before any former-service projection.
        # Current CID/CCIB personnel still require restricted access to this view.
        if assignment is AssignmentProtection.CID_CCIB:
            return ProtectionDecision(
                ProtectionLevel.RESTRICTED, "CURRENT_CID_CCIB_ASSIGNMENT"
            )
        if record_classification is not RecordClassification.CID_CCIB_RESTRICTED:
            return ProtectionDecision(
                ProtectionLevel.WITHHOLD, "FORMER_SERVICE_CLASSIFICATION_NOT_ESTABLISHED"
            )
        return ProtectionDecision(
            ProtectionLevel.NORMAL, "FORMER_SERVICE_SUMMARY_REQUIRES_RECEIVING_SCOPE"
        )
    if record_classification is RecordClassification.CID_CCIB_RESTRICTED:
        return ProtectionDecision(
            ProtectionLevel.RESTRICTED, "PERSISTENT_CID_CCIB_RESTRICTION"
        )
    if assignment is AssignmentProtection.CID_CCIB:
        return ProtectionDecision(
            ProtectionLevel.RESTRICTED, "CURRENT_CID_CCIB_ASSIGNMENT"
        )
    return ProtectionDecision(
        ProtectionLevel.NORMAL, "ORDINARY_RECORD_REQUIRES_BASE_ACCESS"
    )
