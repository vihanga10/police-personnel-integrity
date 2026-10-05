"""Test candidate classification without claiming identity acceptance."""

from datetime import datetime, timezone
from uuid import uuid4

from app.identity.candidate_lookup import (
    IdentifierEvidence,
    summarize_candidates,
)
from app.identity.normalization import NORMALIZATION_PROFILE


def evidence_for(officer_uid, *, state="ASSERTED"):
    """Construct illustrative evidence metadata without personal identifiers."""
    return IdentifierEvidence(
        officer_uid=officer_uid,
        identifier_version_id=uuid4(),
        source_assertion_id=uuid4(),
        record_state=state,
        assertion_state="ACTIVE",
        registry_state="REGISTERED",
        valid_from=None,
        valid_to=None,
        transaction_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        transaction_end=None,
    )


def summarize(evidence):
    return summarize_candidates(
        evidence,
        normalization_profile=NORMALIZATION_PROFILE,
        searched_lookup_key_versions=("lookup-v1",),
    )


def test_no_evidence_has_no_candidate():
    result = summarize([])
    assert result.status == "NO_CANDIDATE_FOUND"
    assert result.officer_uids == ()


def test_multiple_versions_of_one_officer_are_one_candidate():
    officer_uid = uuid4()
    result = summarize([
        evidence_for(officer_uid),
        evidence_for(officer_uid),
    ])

    assert result.status == "SINGLE_CANDIDATE"
    assert result.officer_uids == (officer_uid,)
    assert len(result.evidence) == 2


def test_two_officers_are_ambiguous():
    first, second = uuid4(), uuid4()
    result = summarize([evidence_for(first), evidence_for(second)])

    assert result.status == "MULTIPLE_CANDIDATES"
    assert set(result.officer_uids) == {first, second}


def test_disputed_evidence_remains_visible():
    result = summarize([evidence_for(uuid4(), state="DISPUTED")])

    assert result.status == "SINGLE_CANDIDATE"
    assert result.evidence[0].record_state == "DISPUTED"