"""Find possible officer identities without creating or accepting matches."""

from dataclasses import dataclass
from datetime import date, datetime
from typing import Literal
from uuid import UUID

from sqlalchemy import Connection, and_, or_, select

from app.identity.normalization import (
    NORMALIZATION_PROFILE,
    NormalizedIdentifier,
)
from app.models import Officer, OfficerIdentifierVersion, SourceAssertion
from app.security.identity_crypto import IdentityCrypto


@dataclass(frozen=True)
class IdentifierEvidence:
    """Matching evidence metadata, excluding identifier values and lookup hashes."""

    officer_uid: UUID
    identifier_version_id: UUID
    source_assertion_id: UUID
    record_state: str
    assertion_state: str
    registry_state: str
    valid_from: date | None
    valid_to: date | None
    transaction_start: datetime
    transaction_end: datetime | None


@dataclass(frozen=True)
class CandidateResult:
    """Candidate discovery only; this result never authorizes officer creation."""

    status: Literal[
        "NO_CANDIDATE_FOUND",
        "SINGLE_CANDIDATE",
        "MULTIPLE_CANDIDATES",
    ]
    officer_uids: tuple[UUID, ...]
    evidence: tuple[IdentifierEvidence, ...]
    normalization_profile: str
    searched_lookup_key_versions: tuple[str, ...]


def summarize_candidates(
    evidence: list[IdentifierEvidence],
    *,
    normalization_profile: str,
    searched_lookup_key_versions: tuple[str, ...],
) -> CandidateResult:
    """Count distinct officers rather than the number of matching versions."""
    officer_uids = tuple(sorted(
        {item.officer_uid for item in evidence},
        key=str,
    ))

    if not officer_uids:
        status = "NO_CANDIDATE_FOUND"
    elif len(officer_uids) == 1:
        status = "SINGLE_CANDIDATE"
    else:
        status = "MULTIPLE_CANDIDATES"

    return CandidateResult(
        status=status,
        officer_uids=officer_uids,
        evidence=tuple(evidence),
        normalization_profile=normalization_profile,
        searched_lookup_key_versions=searched_lookup_key_versions,
    )


def find_identifier_candidates(
    connection: Connection,
    crypto: IdentityCrypto,
    identifier: NormalizedIdentifier,
) -> CandidateResult:
    """Find all matching retained versions under one normalization profile.

    This discovery query does not evaluate historical eligibility, accept a
    match, or certify that the identifier belongs to an officer.
    """
    if identifier.normalization_profile != NORMALIZATION_PROFILE:
        raise ValueError("Unsupported identifier normalization profile.")

    versions = tuple(sorted(crypto.lookup_keys))
    if not versions:
        raise ValueError("No lookup keys are available.")

    identifiers = OfficerIdentifierVersion.__table__
    officers = Officer.__table__
    assertions = SourceAssertion.__table__

    # Pair each digest with the key version that produced it.
    predicates = []
    for version in versions:
        digest, used_version = crypto.lookup_hmac(
            identifier.value,
            identifier_type=identifier.identifier_type,
            key_version=version,
        )
        predicates.append(and_(
            identifiers.c.lookup_key_version == used_version,
            identifiers.c.identifier_lookup_hmac == digest,
        ))

    statement = (
        select(
            identifiers.c.officer_uid,
            identifiers.c.identifier_version_id,
            identifiers.c.source_assertion_id,
            identifiers.c.record_state,
            assertions.c.assertion_state,
            officers.c.registry_state,
            identifiers.c.valid_from,
            identifiers.c.valid_to,
            identifiers.c.transaction_start,
            identifiers.c.transaction_end,
        )
        .select_from(
            identifiers
            .join(
                officers,
                identifiers.c.officer_uid == officers.c.officer_uid,
            )
            .join(
                assertions,
                identifiers.c.source_assertion_id
                == assertions.c.source_assertion_id,
            )
        )
        .where(
            identifiers.c.identifier_type == identifier.identifier_type,
            identifiers.c.normalization_profile
            == identifier.normalization_profile,
            or_(*predicates),
        )
        .order_by(
            identifiers.c.officer_uid,
            identifiers.c.transaction_start,
            identifiers.c.identifier_version_id,
        )
    )

    # Do not filter away disputed, closed or archived matches at discovery time.
    rows = connection.execute(statement).mappings()
    evidence = [IdentifierEvidence(**dict(row)) for row in rows]

    return summarize_candidates(
        evidence,
        normalization_profile=identifier.normalization_profile,
        searched_lookup_key_versions=versions,
    )