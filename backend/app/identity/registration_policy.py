"""Conservative registration rules for single-officer PF profile rows."""

from dataclasses import dataclass
from typing import Literal

from app.identity.candidate_lookup import (
    CandidateResult,
    summarize_candidates,
)
from app.identity.normalization import (
    NORMALIZATION_PROFILE,
    NormalizedIdentifier,
)


POLICY_VERSION = "PF_PROFILE_REGISTRATION_V1"
REQUIRED_IDENTIFIERS = frozenset({"NIC", "POLICE_ID"})
ALLOWED_IDENTIFIERS = frozenset({
    "NIC",
    "POLICE_ID",
    "REGIMENTAL_NUMBER",
    "TIN",
})


@dataclass(frozen=True)
class RegistrationPlan:
    """A proposed action; no database record has been created yet."""

    action: Literal["CREATE_NEW", "REVIEW_REQUIRED"]
    reason_code: str
    policy_version: str = POLICY_VERSION


def review(reason_code: str) -> RegistrationPlan:
    return RegistrationPlan(
        action="REVIEW_REQUIRED",
        reason_code=reason_code,
    )


def plan_registration(
    *,
    source_code: str,
    identifiers: dict[str, NormalizedIdentifier],
    candidates: dict[str, CandidateResult],
    lookup_scope_complete: bool,
    invalid_identifier_fields: tuple[str, ...] = (),
) -> RegistrationPlan:
    """Evaluate a PF profile without certifying identity or accepting matches.

    The registration service must establish lookup coverage and perform
    lookup plus writes inside its concurrency-controlled transaction.
    """
    if source_code != "PF_REGISTRY":
        return review("UNSUPPORTED_PROFILE_SOURCE")

    # Invalid optional identifiers also require attention; do not discard them.
    if invalid_identifier_fields:
        return review("INVALID_IDENTIFIER_INPUT")

    if not REQUIRED_IDENTIFIERS.issubset(identifiers):
        return review("MISSING_REQUIRED_IDENTIFIERS")

    # Missing keys or unsupported historical profiles can hide existing matches.
    if lookup_scope_complete is not True:
        return review("INCOMPLETE_LOOKUP_SCOPE")

    # Every supplied identifier must have a corresponding lookup result.
    if set(candidates) != set(identifiers):
        raise ValueError("Candidate lookups do not cover supplied identifiers.")

    searched_versions = None
    officer_uids = set()
    ambiguous = False

    for identifier_type, identifier in identifiers.items():
        if (
            identifier_type not in ALLOWED_IDENTIFIERS
            or identifier.identifier_type != identifier_type
            or identifier.normalization_profile != NORMALIZATION_PROFILE
        ):
            raise ValueError("Unsupported identifier configuration.")

        result = candidates[identifier_type]
        if result.normalization_profile != identifier.normalization_profile:
            raise ValueError("Candidate normalization profile does not match.")

        versions = result.searched_lookup_key_versions
        if not versions or len(set(versions)) != len(versions):
            raise ValueError("Candidate lookup key coverage is invalid.")

        # All lookups in this decision must use the same retained key set.
        if searched_versions is None:
            searched_versions = frozenset(versions)
        elif frozenset(versions) != searched_versions:
            raise ValueError("Candidate lookups used different key sets.")

        # Reject inconsistent summaries instead of trusting their status label.
        expected = summarize_candidates(
            list(result.evidence),
            normalization_profile=result.normalization_profile,
            searched_lookup_key_versions=versions,
        )
        if (
            result.status != expected.status
            or result.officer_uids != expected.officer_uids
        ):
            raise ValueError("Candidate summary is inconsistent.")

        officer_uids.update(result.officer_uids)
        if len(result.officer_uids) > 1:
            ambiguous = True

    if ambiguous:
        return review("AMBIGUOUS_IDENTIFIER_CANDIDATES")

    if len(officer_uids) > 1:
        return review("CONFLICTING_IDENTIFIER_CANDIDATES")

    if officer_uids:
        # Discovery alone does not establish an eligible match.
        # This version deliberately preserves such cases for review.
        return review("EXISTING_CANDIDATE_REQUIRES_REVIEW")

    return RegistrationPlan(
        action="CREATE_NEW",
        reason_code="PF_PROFILE_WITH_NO_EXISTING_CANDIDATE",
    )