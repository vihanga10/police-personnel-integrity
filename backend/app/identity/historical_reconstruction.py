"""Conservative reported-state projections, never accepted historical state.

Pure in-memory algorithm. Research callers must authenticate the captured
inventory, commitments and a fresh audit permit before using these functions.
No database reader, disclosure endpoint, persistence or chain writer lives here.
"""
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from uuid import UUID
import json

# Version the interpretation rules separately from source evidence and commitments.
LEGACY_POLICY = 'REPORTED_HISTORICAL_RECONSTRUCTION_V1'
POLICY = 'REPORTED_HISTORICAL_RECONSTRUCTION_V2'
SUPPORTED_POLICIES = (LEGACY_POLICY, POLICY)
DIMENSIONS = ('rank', 'posting', 'police_number', 'service_status', 'restrictions')
UNCERTAINTIES = ('CLASSIFICATION_UNASSESSED', 'HISTORICAL_IDENTITY_UNASSESSED',
    'REPORTED_DATE_SEMANTICS_UNASSESSED', 'AUTHORITY_AND_DELEGATION_UNASSESSED',
    'SOURCE_INDEPENDENCE_UNVERIFIED', 'SOURCE_COVERAGE_NOT_HISTORICAL_COMPLETENESS')


def require(test, message):
    if not test:
        raise ValueError(message)


def day(value):
    require(type(value) is date, 'A calendar date is required.')
    return value


def instant(value):
    require(isinstance(value, datetime) and value.tzinfo is not None and
        value.utcoffset() is not None, 'An aware capture timestamp is required.')
    return value.astimezone(timezone.utc)


# Immutable claims retain provenance without exposing sensitive fields in repr().
@dataclass(frozen=True)
class Claim:
    claim_id: str
    officer_uid: str = field(repr=False)
    dimension: str
    value: str = field(repr=False)
    source_reference: str = field(repr=False)
    destination_digest: str = field(repr=False)
    mode: str = 'EVENT'
    start: date | None = None
    end: date | None = None
    issues: tuple[str, ...] = ()

    def __post_init__(self):
        require(str(UUID(self.officer_uid)) == self.officer_uid, 'Officer UUID differs.')
        require(self.dimension in DIMENSIONS and self.mode in {'EVENT', 'INTERVAL', 'SNAPSHOT', 'REVIEW'},
            'Unsupported reconstruction claim.')
        require(all(isinstance(v, str) and v for v in (self.claim_id, self.value,
            self.source_reference, self.destination_digest)), 'Complete provenance and value are required.')
        require(len(self.destination_digest) == 64 and all(c in '0123456789abcdef' for c in self.destination_digest),
            'Destination digest differs.')
        if self.start is not None:
            day(self.start)
        if self.end is not None:
            day(self.end)
        require(self.end is None or self.start is None or self.end >= self.start,
            'Inverted reported interval.')
        require(self.mode == 'INTERVAL' or self.end is None, 'Only intervals may have an end.')
        require(isinstance(self.issues, tuple) and all(isinstance(x, str) and x for x in self.issues),
            'Claim issue shape differs.')


# Keep candidate, review, future and expired evidence separate in each answer.
@dataclass(frozen=True)
class Projection:
    dimension: str
    status: str
    candidates: tuple[Claim, ...] = field(repr=False)
    supporting: tuple[Claim, ...] = field(repr=False)
    review: tuple[Claim, ...] = field(repr=False)
    future: tuple[Claim, ...] = field(repr=False)
    expired: tuple[Claim, ...] = field(repr=False)
    reasons: tuple[str, ...]
    accepted_state: None = None


def police_number_comparison(candidates):
    """Compare exact reported numbers only inside an exact nonblank type.

    Type spelling is preserved: no case folding, alias merging or inferred
    precedence. Missing type/number prevents a unique answer. Malformed typed
    claims stop processing with a value-free error rather than guessing a shape.
    """
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Police number candidate shape differs.')
            result[key] = value
        return result
    grouped, incomplete = {}, False
    for claim in candidates:
        try:
            value = json.loads(claim.value, object_pairs_hook=unique_fields)
        except (ValueError, TypeError):
            raise ValueError('Police number candidate shape differs.') from None
        require(isinstance(value, dict) and set(value) == {'police_no', 'number_type'} and
            all(isinstance(v, str) for v in value.values()), 'Police number candidate shape differs.')
        number, kind = value['police_no'], value['number_type']
        if not kind.strip() or not number.strip():
            incomplete = True
            continue
        grouped.setdefault(kind, set()).add(number)
    return any(len(numbers) > 1 for numbers in grouped.values()), incomplete


def reconstruct(officer_uid, claims, *, on, captured_at, known_at=None, policy=POLICY):
    """Project reports at a date using only one captured knowledge snapshot.

    Latest-event carry-forward is a named hypothesis, not an accepted interval.
    Same-day ties are retained. Intervals are closed for candidate inclusion only;
    end-day semantics are unresolved. Restrictions may legitimately be concurrent.
    A blank end never proves continuing validity, and absence never proves freedom
    from restrictions. Snapshot labels are not backdated. No override is applied.
    """
    require(policy in SUPPORTED_POLICIES, 'Unsupported reconstruction policy.')
    day(on)
    capture = instant(captured_at)
    # A single captured snapshot cannot answer what the database knew at another time.
    knowledge = capture if known_at is None else instant(known_at)
    require(knowledge == capture, 'Earlier or later transaction-time history is unavailable in this snapshot.')
    require(str(UUID(officer_uid)) == officer_uid, 'Officer UUID differs.')
    claims = tuple(claims)
    require(all(isinstance(c, Claim) for c in claims), 'Typed claims required.')
    require(len({c.claim_id for c in claims}) == len(claims), 'Repeated claim identifier.')
    # Do not silently filter another officer from a caller-selected evidence set.
    require(all(c.officer_uid == officer_uid for c in claims), 'Claim officer differs.')
    results = []
    for dimension in DIMENSIONS:
        selected = sorted((c for c in claims if c.dimension == dimension), key=lambda c: c.claim_id)
        review, future, expired, events, intervals = [], [], [], [], []
        for c in selected:
            # Unplaced or semantically uncertain evidence must not become an active state.
            if c.mode in {'SNAPSHOT', 'REVIEW'} or c.start is None or c.issues:
                review.append(c)
            elif c.start > on:
                future.append(c)
            elif c.mode == 'INTERVAL':
                (expired if c.end is not None and c.end < on else intervals).append(c)
            else:
                events.append(c)
        # Keep every latest-date tie; never let input ordering choose the winning report.
        latest = max((c.start for c in events), default=None)
        current_events = [c for c in events if c.start == latest]
        candidates = sorted(current_events + intervals, key=lambda c: c.claim_id)
        reasons = list(UNCERTAINTIES)
        if on > capture.date():
            reasons.append('REQUEST_AFTER_CAPTURE_CANNOT_ESTABLISH_FUTURE_STATE')
        if current_events:
            reasons.append('LATEST_REPORTED_EVENT_CARRY_FORWARD_HYPOTHESIS')
        if intervals:
            reasons.append('REPORTED_INTERVAL_BOUNDARIES_UNASSESSED')
            if any(c.end is None for c in intervals):
                reasons.append('OPEN_END_DOES_NOT_PROVE_CONTINUING_VALIDITY')
            if any(c.end == on for c in intervals):
                reasons.append('END_DAY_INCLUSION_IS_CANDIDATE_ONLY')
        if review:
            reasons.append('UNPLACED_OR_UNASSESSED_EVIDENCE_REQUIRES_REVIEW')
        conflict = dimension != 'restrictions' and len({c.value for c in candidates}) > 1
        incomplete_number = False
        # Keep v1 byte-for-byte result semantics for archived replay only. New
        # queries use v2; changing interpretation never changes anchored evidence.
        if dimension == 'police_number' and policy == POLICY and candidates:
            conflict, incomplete_number = police_number_comparison(candidates)
            reasons.append('POLICE_NUMBER_TYPES_AND_EQUIVALENCE_UNASSESSED')
            if incomplete_number:
                reasons.append('POLICE_NUMBER_TYPE_OR_VALUE_MISSING')
        # A workflow may succeed while the historical question remains unanswerable.
        if not candidates:
            status = 'CANNOT_VERIFY'
            reasons.append('NO_DATED_CANDIDATE_AT_REQUESTED_DATE')
        # Multiple restrictions can coexist; scalar state dimensions can conflict.
        elif conflict:
            status = 'CONFLICTING_REPORTS'
            reasons.append('COMPETING_REPORTED_VALUES_WITHOUT_ACCEPTED_PRECEDENCE')
        elif review or incomplete_number or on > capture.date():
            status = 'CANNOT_VERIFY'
        else:
            status = 'REPORTED_CANDIDATES'
        if dimension == 'restrictions':
            reasons.append('NO_RESTRICTION_OR_OVERRIDE_EFFECT_ACCEPTED')
        results.append(Projection(dimension, status, tuple(candidates), tuple(events),
            tuple(review), tuple(future), tuple(expired), tuple(reasons)))
    return tuple(results)
