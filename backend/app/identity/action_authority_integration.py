"""Pure action-date authority integration; assessed inputs require a trusted adapter.

This module does not authenticate assessment documents, grant access, read a DB,
issue a permit or execute a research run. A future guarded runner must authenticate
and version the assessment evidence before supplying it. CSV labels are never
promoted to governing rules or accepted identities here.
"""
from dataclasses import dataclass, field, asdict
from datetime import date
import re

from app.identity.protected_commitment import digest
from app.identity.run_research_algorithms import json_value
from app.identity.reported_authority_actions import ActionReview
from app.identity.temporal_authority import (
    Action, ActorState, Fact, Rule, Delegation, evaluate, require,
)

POLICY = 'ACTION_DATE_AUTHORITY_INTEGRATION_V1'


def fingerprint(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value),
        'Exact evidence fingerprint required.')


@dataclass(frozen=True)
class StateAssessment:
    """State ID binds an explicit assessment to one reconstructed actor/date."""
    state_id: str = field(repr=False)
    state: ActorState = field(repr=False)

    def __post_init__(self):
        fingerprint(self.state_id)
        require(isinstance(self.state, ActorState), 'Typed dated actor state required.')


@dataclass(frozen=True)
class AuthorityAssessment:
    """Explicit inputs, not a signature or proof of assessment authenticity.

    Evidence digests inventory every cited assessment/instrument reference. The
    guarded adapter must verify those bytes and the authority of the assessor.
    This typed boundary keeps that responsibility visible rather than treating
    a JSON flag or a reported rank as sufficient real-world authority evidence.
    """
    public_payload_sha256: str = field(repr=False)
    original_action_digest: str = field(repr=False)
    destination_digest: str = field(repr=False)
    actor_uid: str = field(repr=False)
    target_scope: str = field(repr=False)
    identity: Fact
    date_semantics: Fact
    coverage: Fact
    states: tuple[StateAssessment, ...] = field(default=(), repr=False)
    rules: tuple[Rule, ...] = field(default=(), repr=False)
    delegations: tuple[Delegation, ...] = field(default=(), repr=False)
    evidence_digests: tuple[tuple[str, str], ...] = field(default=(), repr=False)

    def __post_init__(self):
        for value in (self.public_payload_sha256, self.original_action_digest, self.destination_digest):
            fingerprint(value)
        require(all(isinstance(f, Fact) and type(f.value) in (bool, type(None))
            for f in (self.identity, self.date_semantics, self.coverage)),
            'Typed boolean action and coverage assessments required.')
        require(isinstance(self.target_scope, str) and self.target_scope.strip(), 'Explicit target scope required.')
        for values, kind in ((self.states, StateAssessment), (self.rules, Rule), (self.delegations, Delegation)):
            require(isinstance(values, tuple) and all(isinstance(v, kind) for v in values),
                'Immutable typed assessment inventory required.')
        require(isinstance(self.evidence_digests, tuple), 'Immutable assessment evidence inventory required.')
        refs = set()
        for item in self.evidence_digests:
            require(isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str)
                and item[0].strip() and item[0] not in refs, 'Assessment evidence reference differs.')
            fingerprint(item[1]); refs.add(item[0])
        facts = [self.identity, self.date_semantics, self.coverage]
        for assessment in self.states:
            facts.extend(getattr(assessment.state, k) for k in ('identity', 'rank', 'role', 'active', 'scope'))
        # Even unassessed facts cannot cite absent entries in this input inventory.
        for value in (*facts, *self.rules, *self.delegations):
            require(set(value.evidence) <= refs, 'Assessment cites evidence outside inventory.')
        state_keys = [(a.state.actor_uid, a.state.on) for a in self.states]
        require(len(set(state_keys)) == len(state_keys), 'Duplicate assessed actor/date state.')
        ids = [r.rule_id for r in self.rules] + [d.delegation_id for d in self.delegations]
        require(len(set(ids)) == len(ids), 'Duplicate authority instrument.')


class ActionAuthority:
    """Connect ActionReview and ActorHistory to the existing pure evaluator."""
    def __init__(self, history):
        self.history = history

    def review(self, action, assessment=None):
        require(isinstance(action, ActionReview) and action.accepted_authority is False and
            action.status == 'CANNOT_VERIFY', 'Original unaccepted action required.')
        original_digest = digest(json_value(asdict(action)))
        base = dict(policy=POLICY, original_action_digest=original_digest,
            raw_record_id=action.raw_record_id, action_kind=action.action_kind,
            destination_digest=action.destination_digest,
            public_payload_sha256=self.history.public_sha,
            accepted_authority_claim=False, assessment_authenticity_claim=False)
        if assessment is None:
            # Existing evidence-only review remains unchanged. Preserve every
            # candidate history; do not silently choose one ambiguous candidate.
            result = self.history.review(action)
            return json_value(dict(base, mode='REPORTED_INPUTS_ONLY', status='CANNOT_VERIFY',
                reasons=result['reasons'], reported_history=result, successful_paths=(),
                actor_state_links=result['actor_state_links']))
        require(isinstance(assessment, AuthorityAssessment), 'Typed authority assessment required.')
        require(assessment.public_payload_sha256 == self.history.public_sha and
            assessment.original_action_digest == original_digest and
            assessment.destination_digest == action.destination_digest,
            'Assessment belongs to different evidence/action version.')
        require(assessment.actor_uid in action.actor_candidates and
            assessment.actor_uid in self.history.buckets, 'Assessed actor is outside candidate universe.')
        require(action.reported_date is not None, 'Assessment requires a reviewable reported action date.')
        on = date.fromisoformat(action.reported_date)
        require(on.isoformat() == action.reported_date, 'Canonical action date required.')
        assessed = {(a.state.actor_uid, a.state.on): a for a in assessment.states}
        states = {}; links = {}; instruments = {r.rule_id: r for r in assessment.rules}
        instruments.update({d.delegation_id: d for d in assessment.delegations})
        seen = set()

        def state(uid, day):
            key = (uid, day)
            if key in states or uid not in self.history.buckets:
                return
            identifier, reported = self.history.project(uid, day)
            accepted = assessed.get(key)
            if accepted is not None:
                require(accepted.state_id == identifier, 'Assessment actor/date reconstruction version differs.')
            states[key] = accepted.state if accepted else reported
            links[key] = dict(officer_uid=uid, on=day.isoformat(), state_id=identifier,
                assessment_supplied=accepted is not None)

        def visit(identifier, uid, day, depth=0):
            # Bound traversal independently of the evaluator; cycles and missing
            # parents remain unresolved there, never accepted by truncation here.
            key = (identifier, uid, day)
            if key in seen or depth >= 16:
                return
            require(len(seen) < 4096, 'Authority state expansion exceeds bound.')
            seen.add(key); state(uid, day)
            item = instruments.get(identifier)
            if isinstance(item, Delegation):
                visit(item.parent_id, item.issuer_uid, item.issued_on, depth + 1)
                visit(item.parent_id, item.issuer_uid, day, depth + 1)

        state(assessment.actor_uid, on)
        for identifier in sorted(instruments):
            item = instruments[identifier]
            if isinstance(item, Rule) or item.recipient_uid == assessment.actor_uid:
                visit(identifier, assessment.actor_uid, on)
        # Reject unrelated/unused overrides instead of hiding assessed context in
        # an output that did not actually evaluate it.
        require(set(assessed) <= set(states), 'Assessment includes unused or unanchored actor/date states.')
        request = Action(assessment.actor_uid, on, action.action_kind, assessment.target_scope,
            assessment.identity, assessment.date_semantics, (action.source_reference,))
        decision = evaluate(request, tuple(states.values()), assessment.rules,
            assessment.delegations, coverage=assessment.coverage)
        packet_digest = digest(json_value(asdict(assessment)))
        return json_value(dict(base, mode='EXPLICIT_ASSESSED_INPUTS', status=decision.status,
            reasons=decision.reasons, successful_paths=decision.successful_paths,
            decision_evidence=decision.evidence, assessment_digest=packet_digest,
            actor_state_links=[links[k] for k in sorted(links)],
            governing_instrument_ids=tuple(sorted(instruments)),
            semantics='ISSUER_AUTHORITY_AT_ISSUANCE_AND_ACTION_DATE_V1'))


def evaluate_action_inventory(actions, history, assessments=()):
    """Evaluate every supplied action and reject orphaned assessment packets.

    This pure inventory function deliberately does not decrypt a saved run or
    issue PASSED research receipts. The guarded runner must first authenticate
    the source inventory, assessments and permit, then encrypt these results.
    """
    from collections import Counter
    actions, assessments = tuple(actions), tuple(assessments)
    require(all(isinstance(a, ActionReview) for a in actions) and
        all(isinstance(p, AuthorityAssessment) for p in assessments), 'Typed action inventory required.')
    keys = [digest(json_value(asdict(a))) for a in actions]
    require(len(set(keys)) == len(keys), 'Duplicate original authority action.')
    packets = {p.original_action_digest: p for p in assessments}
    require(len(packets) == len(assessments), 'Duplicate action assessment packet.')
    require(set(packets) <= set(keys), 'Assessment references action outside supplied inventory.')
    bridge = ActionAuthority(history)
    results = tuple(bridge.review(a, packets.get(k)) for a, k in zip(actions, keys))
    counts = Counter(r['status'] for r in results)
    reasons = Counter(reason for result in results for reason in result['reasons'])
    return results, dict(policy=POLICY, mode='PURE_INVENTORY_EVALUATION',
        authority_action_records=len(actions), explicit_assessment_packets=len(assessments),
        public_payload_sha256=history.public_sha, status_counts=dict(sorted(counts.items())),
        reason_counts=dict(sorted(reasons.items())), accepted_authority_claim=False,
        assessment_authenticity_claim=False, new_research_audit_executed=False,
        findings_database_written=False, findings_anchored=False)
