"""Pure reported-state queries over an explicit, receipt-backed version history.

Callers authenticate recording receipts and coverage before research use. This
module neither reads stores nor issues permits, accepts truth, or anchors data.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from hashlib import sha256
import json
from uuid import UUID

from app.identity.historical_reconstruction import Claim, Projection, reconstruct, instant, day, require
from app.identity.historical_reconstruction import POLICY as RECONSTRUCTION_POLICY

POLICY = 'REPORTED_BITEMPORAL_RECONSTRUCTION_V1'


def text(value):
    require(isinstance(value, str) and bool(value.strip()), 'Nonempty version provenance required.')


def fingerprint(value):
    require(isinstance(value, str) and len(value) == 64 and
        all(c in '0123456789abcdef' for c in value), 'Recording receipt digest differs.')


@dataclass(frozen=True)
class EvidenceVersion:
    version_id: str = field(repr=False)
    claim: Claim = field(repr=False)
    source_key: str = field(repr=False)
    recorded_at: datetime
    receipt_reference: str = field(repr=False)
    receipt_digest: str = field(repr=False)
    supersedes: str | None = field(default=None, repr=False)
    withdrawn: bool = False

    def __post_init__(self):
        for v in (self.version_id, self.source_key, self.receipt_reference):
            text(v)
        require(type(self.claim) is Claim, 'Typed immutable reported claim required.')
        object.__setattr__(self, 'recorded_at', instant(self.recorded_at))
        fingerprint(self.receipt_digest)
        if self.supersedes is not None:
            text(self.supersedes)
        require(type(self.withdrawn) is bool, 'Explicit withdrawal flag required.')


@dataclass(frozen=True)
class RecordingHistory:
    officer_uid: str = field(repr=False)
    coverage_start: datetime
    coverage_end: datetime
    coverage_reference: str = field(repr=False)
    coverage_digest: str = field(repr=False)
    versions: tuple[EvidenceVersion, ...] = field(repr=False)

    def __post_init__(self):
        require(str(UUID(self.officer_uid)) == self.officer_uid, 'Officer UUID differs.')
        object.__setattr__(self, 'coverage_start', instant(self.coverage_start))
        object.__setattr__(self, 'coverage_end', instant(self.coverage_end))
        require(self.coverage_start <= self.coverage_end, 'Inverted recording coverage.')
        text(self.coverage_reference)
        fingerprint(self.coverage_digest)
        require(isinstance(self.versions, tuple) and all(type(v) is EvidenceVersion
            for v in self.versions), 'Immutable typed recording history required.')
        require(len({v.version_id for v in self.versions}) == len(self.versions),
            'Repeated evidence version identifier.')
        heads = {}
        for v in sorted(self.versions, key=lambda v: (v.recorded_at, v.version_id)):
            c = v.claim
            require(c.officer_uid == self.officer_uid, 'History officer differs.')
            require(self.coverage_start <= v.recorded_at <= self.coverage_end,
                'Version falls outside recording coverage.')
            previous = heads.get(c.claim_id)
            if previous is None:
                require(v.supersedes is None and not v.withdrawn,
                    'Baseline cannot supersede missing history or withdraw an unseen claim.')
            else:
                require(v.supersedes == previous.version_id,
                    'Correction must reference the immediately previous version; forks and gaps rejected.')
                require(v.recorded_at > previous.recorded_at,
                    'Correction requires a strictly later recorded timestamp.')
                require(v.source_key == previous.source_key and
                    c.dimension == previous.claim.dimension,
                    'Correction cannot change source identity or state dimension.')
                require(not v.withdrawn or c == previous.claim,
                    'Withdrawal must retain its predecessor claim unchanged.')
            heads[c.claim_id] = v


@dataclass(frozen=True)
class BitemporalResult:
    policy: str
    reconstruction_policy: str
    effective_on: object
    known_at: datetime
    projections: tuple[Projection, ...] = field(repr=False)
    visible_versions: tuple[EvidenceVersion, ...] = field(repr=False)
    query_digest: str
    accepted_state: None = None
    receipt_authenticity_claim: bool = False


def canonical(value):
    if isinstance(value, datetime):
        return instant(value).isoformat()
    if hasattr(value, 'isoformat'):
        return value.isoformat()
    raise TypeError('Unsupported fingerprint value.')


def query(history, *, effective_on, known_at):
    """Knowledge timestamps include arrivals at that instant; old heads end there.

Full replacement corrections affect only the same stable claim ID/source key.
Independent claims are never collapsed. Visible withdrawals remove candidates
but remain in result provenance. Reported effective boundaries and uncertainty
semantics are inherited unchanged from historical_reconstruction.
"""
    require(type(history) is RecordingHistory, 'Explicit recording history required.')
    day(effective_on)
    knowledge = instant(known_at)
    require(history.coverage_start <= knowledge <= history.coverage_end,
        'Requested knowledge timestamp is outside established recording history.')
    heads = {}
    for version in sorted(history.versions, key=lambda v: (v.recorded_at, v.version_id)):
        if version.recorded_at <= knowledge:
            heads[version.claim.claim_id] = version
    visible = tuple(heads[k] for k in sorted(heads))
    claims = tuple(v.claim for v in visible if not v.withdrawn)
    projections = reconstruct(history.officer_uid, claims, on=effective_on,
        captured_at=knowledge, known_at=knowledge, policy=RECONSTRUCTION_POLICY)
    # Only visible evidence binds the result. Later arrivals cannot change an
    # earlier query fingerprint. Coverage authenticity belongs to the adapter.
    payload = dict(policy=POLICY, reconstruction_policy=RECONSTRUCTION_POLICY,
        officer_uid=history.officer_uid,
        effective_on=effective_on, known_at=knowledge,
        visible_versions=[asdict(v) for v in visible],
        projections=[asdict(p) for p in projections])
    digest = sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'),
        default=canonical, allow_nan=False).encode()).hexdigest()
    return BitemporalResult(POLICY, RECONSTRUCTION_POLICY, effective_on, knowledge,
        projections, visible, digest)
