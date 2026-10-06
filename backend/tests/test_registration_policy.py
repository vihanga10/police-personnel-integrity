"""Test conservative registration decisions without accessing personnel data."""

from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.identity.candidate_lookup import (
    IdentifierEvidence,
    summarize_candidates,
)
from app.identity.normalization import (
    NORMALIZATION_PROFILE,
    normalize_identifier,
)
from app.identity.registration_policy import plan_registration


def candidate_result(officer_uids=()):
    """Build realistic candidate metadata without readable identifiers."""
    evidence = [
        IdentifierEvidence(
            officer_uid=officer_uid,
            identifier_version_id=uuid4(),
            source_assertion_id=uuid4(),
            record_state="ASSERTED",
            assertion_state="ACTIVE",
            registry_state="REGISTERED",
            valid_from=None,
            valid_to=None,
            transaction_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            transaction_end=None,
        )
        for officer_uid in officer_uids
    ]
    return summarize_candidates(
        evidence,
        normalization_profile=NORMALIZATION_PROFILE,
        searched_lookup_key_versions=("test-lookup-v1",),
    )


@pytest.fixture
def inputs():
    # These are normalizer inputs, not claims of valid NIC format.
    identifiers = {
        kind: normalize_identifier(
            f"TEST-{kind}",
            identifier_type=kind,
        )
        for kind in ("NIC", "POLICE_ID")
    }
    return {
        "source_code": "PF_REGISTRY",
        "identifiers": identifiers,
        "candidates": {
            kind: candidate_result()
            for kind in identifiers
        },
        "lookup_scope_complete": True,
    }


def test_no_candidates_permits_new_internal_registration(inputs):
    result = plan_registration(**inputs)
    assert result.action == "CREATE_NEW"
    assert result.reason_code == "PF_PROFILE_WITH_NO_EXISTING_CANDIDATE"


@pytest.mark.parametrize("missing", ["NIC", "POLICE_ID"])
def test_missing_required_identifier_requires_review(inputs, missing):
    del inputs["identifiers"][missing]
    del inputs["candidates"][missing]

    result = plan_registration(**inputs)
    assert result.action == "REVIEW_REQUIRED"
    assert result.reason_code == "MISSING_REQUIRED_IDENTIFIERS"


def test_incomplete_lookup_scope_prevents_creation(inputs):
    inputs["lookup_scope_complete"] = False
    assert plan_registration(**inputs).reason_code == "INCOMPLETE_LOOKUP_SCOPE"


def test_invalid_optional_identifier_requires_review(inputs):
    inputs["invalid_identifier_fields"] = ("officer_tin_number",)
    assert plan_registration(**inputs).reason_code == "INVALID_IDENTIFIER_INPUT"


def test_other_source_does_not_use_pf_registration_policy(inputs):
    inputs["source_code"] = "POLICE_HR_IS"
    assert plan_registration(**inputs).reason_code == "UNSUPPORTED_PROFILE_SOURCE"


def test_agreeing_existing_candidates_still_require_review(inputs):
    officer_uid = uuid4()
    inputs["candidates"] = {
        kind: candidate_result((officer_uid,))
        for kind in inputs["identifiers"]
    }

    result = plan_registration(**inputs)
    assert result.action == "REVIEW_REQUIRED"
    assert result.reason_code == "EXISTING_CANDIDATE_REQUIRES_REVIEW"


def test_different_identifiers_pointing_to_different_officers_conflict(inputs):
    inputs["candidates"]["NIC"] = candidate_result((uuid4(),))
    inputs["candidates"]["POLICE_ID"] = candidate_result((uuid4(),))

    assert (
        plan_registration(**inputs).reason_code
        == "CONFLICTING_IDENTIFIER_CANDIDATES"
    )


def test_one_identifier_with_multiple_officers_is_ambiguous(inputs):
    inputs["candidates"]["NIC"] = candidate_result((uuid4(), uuid4()))

    assert (
        plan_registration(**inputs).reason_code
        == "AMBIGUOUS_IDENTIFIER_CANDIDATES"
    )


def test_missing_lookup_result_is_rejected(inputs):
    del inputs["candidates"]["NIC"]
    with pytest.raises(ValueError, match="cover supplied identifiers"):
        plan_registration(**inputs)


def test_inconsistent_candidate_summary_is_rejected(inputs):
    existing = candidate_result((uuid4(),))
    inputs["candidates"]["NIC"] = replace(
        existing,
        status="NO_CANDIDATE_FOUND",
        officer_uids=(),
    )

    with pytest.raises(ValueError, match="summary is inconsistent"):
        plan_registration(**inputs)


def test_different_lookup_key_sets_are_rejected(inputs):
    inputs["candidates"]["POLICE_ID"] = replace(
        inputs["candidates"]["POLICE_ID"],
        searched_lookup_key_versions=("other-key",),
    )

    with pytest.raises(ValueError, match="different key sets"):
        plan_registration(**inputs)