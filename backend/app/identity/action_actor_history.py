"""Reported actor history at each action date; no guessed identity or authority."""
from collections import Counter
from dataclasses import asdict
from datetime import date

from app.identity.historical_reconstruction import reconstruct, require, POLICY as HISTORY
from app.identity.historical_source_claims import source_claims
from app.identity.protected_commitment import digest
from app.identity.reported_authority_actions import ActionReview
from app.identity.run_research_algorithms import json_value
from app.identity.temporal_authority import ActorState, Fact, Action, evaluate

POLICY = 'REPORTED_ACTION_ACTOR_HISTORY_V1'
GROUPS = ('candidates', 'supporting', 'review', 'future', 'expired')


def compact_projection(projection):
    """Claim IDs resolve through the encrypted claim inventory, never lost text."""
    return dict(dimension=projection.dimension, status=projection.status, reasons=projection.reasons,
        accepted_state=projection.accepted_state,
        **{g: tuple(c.claim_id for c in getattr(projection, g)) for g in GROUPS})


def actor_facts(uid, on, projections):
    """Connect real reconstructed evidence to the evaluator without upgrading it.

    The reported state algorithm accepts no state. Rank candidates can be carried
    as UNASSESSED labels; posting text cannot become a resolved geographic scope
    and service text cannot become an assessed active-service boolean.
    """
    by_dimension = {p.dimension: p for p in projections}
    def evidence(dimension):
        p = by_dimension[dimension]
        return tuple(sorted({c.claim_id for g in GROUPS for c in getattr(p, g)}))
    rank = by_dimension['rank']
    value = rank.candidates[0].value if len(rank.candidates) == 1 else None
    assessment = 'CONFLICTING' if rank.status == 'CONFLICTING_REPORTS' else 'UNASSESSED'
    return ActorState(uid, on, Fact(None, 'UNASSESSED', ('ANCHORED_CANDIDATE_MEMBERSHIP',)),
        Fact(value, assessment, evidence('rank')),
        Fact(None, 'UNASSESSED', evidence('posting')),
        Fact(None, 'UNASSESSED', evidence('service_status')),
        Fact(None, 'UNASSESSED', evidence('posting')))


class ActorHistory:
    """One claim inventory per actor; one reconstruction per actor/date pair."""
    def __init__(self, buckets, raw_bindings, captured_at, public_sha):
        self.buckets = buckets; self.bindings = raw_bindings
        self.captured_at = captured_at; self.public_sha = public_sha
        self.claims = {}; self.states = {}; self.inventory_ids = {}
        self.pending_claims = []; self.pending_states = []
        self.history_counts = Counter(); self.reason_counts = Counter()
        self.action_status_counts = Counter(); self.authority_counts = Counter()
        self.action_records = 0; self.linked_candidate_states = 0

    def project(self, uid, on):
        require(type(on) is date, 'Reported actor calendar date required.')
        key = (uid, on)
        if key in self.states:
            return self.states[key]
        require(uid in self.buckets, 'Actor is outside anchored universe.')
        if uid not in self.claims:
            claims = source_claims(uid, self.buckets[uid], self.bindings)
            self.claims[uid] = claims
            serialized = json_value([asdict(c) for c in claims])
            identifier = digest(dict(policy=POLICY, officer_uid=uid, public_payload_sha256=self.public_sha,
                claims=serialized, history_policy=HISTORY))
            self.inventory_ids[uid] = identifier
            self.pending_claims.append(dict(claim_inventory_id=identifier, officer_uid=uid,
                claims=serialized, history_policy=HISTORY))
        projections = reconstruct(uid, self.claims[uid], on=on, captured_at=self.captured_at, policy=HISTORY)
        state = actor_facts(uid, on, projections)
        identifier = digest(dict(policy=POLICY, officer_uid=uid, on=on.isoformat(),
            claim_inventory_id=self.inventory_ids[uid], history_policy=HISTORY))
        self.pending_states.append(json_value(dict(state_id=identifier, officer_uid=uid, on=on,
            claim_inventory_id=self.inventory_ids[uid], history=[compact_projection(p) for p in projections],
            authority_actor_facts=asdict(state), accepted_state_claim=False)))
        self.history_counts.update(p.dimension+':'+p.status for p in projections)
        self.reason_counts.update('history:'+r for p in projections for r in p.reasons)
        self.states[key] = (identifier, state)
        return identifier, state

    def review(self, action):
        """All candidates remain explicit; missing dates never default to query/today."""
        require(isinstance(action, ActionReview) and action.status == 'CANNOT_VERIFY' and
            action.accepted_authority is False, 'Unaccepted reported action required.')
        self.action_records += 1
        reasons = set(action.reasons)
        links = []; decisions = []
        on = date.fromisoformat(action.reported_date) if action.reported_date is not None else None
        if on is None:
            status = 'NO_REVIEWABLE_ACTION_DATE'
            reasons.add('ACTOR_HISTORY_ACTION_DATE_MISSING_OR_INVALID')
        elif not action.actor_candidates:
            status = 'ACTOR_UNRESOLVED'
            reasons.add('ACTOR_HISTORY_IDENTITY_UNRESOLVED')
        else:
            status = 'SINGLE_CANDIDATE_HISTORY' if len(action.actor_candidates) == 1 else 'AMBIGUOUS_CANDIDATE_HISTORIES'
            for uid in action.actor_candidates:
                if uid not in self.buckets:
                    links.append(dict(officer_uid=uid, state_id=None, status='OUTSIDE_ANCHORED_UNIVERSE'))
                    reasons.add('ACTOR_OUTSIDE_ANCHORED_UNIVERSE')
                    status = 'UNRESOLVED_CANDIDATE_COVERAGE'
                    continue
                state_id, state = self.project(uid, on)
                links.append(dict(officer_uid=uid, state_id=state_id, status='REPORTED_HISTORY_ONLY'))
                self.linked_candidate_states += 1
                unknown = Fact(None, 'UNASSESSED', (action.raw_record_id,))
                request = Action(uid, on, action.action_kind, 'UNRESOLVED_REPORTED_SCOPE',
                    unknown, unknown, (action.source_reference,))
                # Real actor histories are now supplied. Identity/date/rule facts
                # remain unassessed, so they cannot create a VALID authority claim.
                decision = evaluate(request, (state,), (), coverage=unknown)
                require(decision.status == 'CANNOT_VERIFY', 'Reported history cannot establish authority.')
                decisions.append(dict(officer_uid=uid, status=decision.status, reasons=decision.reasons))
                reasons.update(decision.reasons)
        self.action_status_counts.update((status,))
        self.authority_counts.update((action.action_kind+':CANNOT_VERIFY',))
        self.reason_counts.update('action:'+r for r in reasons)
        return json_value(dict(policy=POLICY, raw_record_id=action.raw_record_id, action_kind=action.action_kind,
            original_action_digest=digest(json_value(asdict(action))), source_reference_sha256=digest(action.source_reference),
            destination_digest=action.destination_digest, actor_candidates=action.actor_candidates,
            reported_date=action.reported_date, reported_date_text=action.reported_date_text,
            history_link_status=status, actor_state_links=links, candidate_decisions=decisions,
            status='CANNOT_VERIFY', reasons=tuple(sorted(reasons)), accepted_authority_claim=False))

    def drain(self):
        """The caller writes these records encrypted; caches keep only compact states."""
        claims, states = self.pending_claims, self.pending_states
        self.pending_claims = []; self.pending_states = []
        return claims, states

    def aggregate(self):
        return dict(authority_action_records=self.action_records, distinct_actors=len(self.claims),
            distinct_actor_dates=len(self.states), linked_candidate_states=self.linked_candidate_states,
            source_claims=sum(len(c) for c in self.claims.values()),
            actor_history_status_counts=dict(sorted(self.history_counts.items())),
            action_link_status_counts=dict(sorted(self.action_status_counts.items())),
            authority_action_counts=dict(sorted(self.authority_counts.items())),
            reason_counts=dict(sorted(self.reason_counts.items())))
