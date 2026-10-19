"""Bounded parser for reviewed court NIC (text) entries; candidate links only."""
from dataclasses import dataclass, field
import re
from uuid import UUID

POLICY = "COURT_PARTICIPANT_MEMBERSHIP_V1"
ENTRY = re.compile(r"\s*(?P<nic>[0-9]{9}[VvXx]|[0-9]{12})\s*\((?P<description>[^();]+)\)\s*")


@dataclass(frozen=True)
class CourtMembership:
    state: str
    participants: tuple = field(default=(), repr=False)


def parse_court_participants(text):
    """All-or-none grammar parsing avoids guessed links from malformed cells.

    Raw entries and parenthesized text are preserved in encrypted catalogs.
    Descriptor semantics are deliberately unassessed, not interpreted as rank.
    """
    if not isinstance(text, str):
        raise ValueError("Court participant source must be text.")
    if not text.strip():
        return CourtMembership("MISSING_REVIEW")
    if len(text) > 1048576:
        return CourtMembership("OVERSIZED_REVIEW")
    segments = text.split(';')
    if len(segments) > 1000:
        return CourtMembership("PARTICIPANT_LIMIT_REVIEW")
    parsed = []
    for position, original in enumerate(segments, 1):
        match = ENTRY.fullmatch(original)
        if match is None or not match['description'].strip():
            return CourtMembership("GRAMMAR_REVIEW_REQUIRED")
        parsed.append(dict(position=position, original_entry=original,
            reported_nic=match['nic'], parenthesized_text=match['description'],
            descriptor_semantics="UNASSESSED"))
    return CourtMembership("PARSED_SOURCE_CLAIMS", tuple(parsed))


def candidate_membership(text, resolve):
    """Resolve each reported token separately, preserving repeats and unknowns."""
    result = parse_court_participants(text)
    participants = []
    if result.state != "PARSED_SOURCE_CLAIMS":
        return result
    for parsed in result.participants:
        state, officer = resolve(parsed['reported_nic'])
        if not isinstance(state, str) or not state:
            raise ValueError("Candidate verifier status differs.")
        if officer is not None and (not isinstance(officer, UUID) or state != 'EXACT_EVIDENCE_CANDIDATE'):
            raise ValueError("Candidate verifier identity differs.")
        participants.append(dict(parsed, officer_uid=str(officer) if officer is not None else None,
            candidate_status=state, linkage_accepted=False, historical_identity="UNASSESSED",
            reported_role="COURT_PARTICIPANT_CLAIM", authority="UNASSESSED"))
    return CourtMembership(result.state, tuple(participants))
