"""Invented assessments test the real actor-history bridge, not police law."""
from copy import deepcopy
from dataclasses import replace
from datetime import date
from uuid import uuid4

import pytest
from app.identity.action_authority_integration import ActionAuthority, AuthorityAssessment, StateAssessment
from app.identity.action_actor_history import ActorHistory
from app.identity.temporal_authority import Fact, ActorState, Rule, Delegation
from test_action_actor_history import action, history
from test_historical_reconstruction import OFFICER

DAY = date(2020, 1, 10)
ISSUED = date(2020, 1, 5)
REF = 'fixture-assessment-evidence'


def fact(value, assessment='ASSESSED'):
    return Fact(value, assessment, (REF,))


def actor(h, uid=OFFICER, on=DAY, rank='fixture-rank', active=True):
    identifier, _ = h.project(uid, on)
    state = ActorState(uid, on, fact(True), fact(rank), fact('fixture-role'), fact(active), fact('fixture-scope'))
    return StateAssessment(identifier, state)


def rule(**changes):
    value = Rule('fixture-rule', ('AUTHORIZE_PROMOTION',), ('fixture-rank',), ('fixture-role',),
        ('fixture-scope',), ('fixture-target',), date(2019, 1, 1), None, True, 'ASSESSED', (REF,))
    return replace(value, **changes)


def packet(h, a=None, **changes):
    from dataclasses import asdict
    from app.identity.protected_commitment import digest
    from app.identity.run_research_algorithms import json_value
    a = a or action()
    value = AuthorityAssessment(h.public_sha, digest(json_value(asdict(a))), a.destination_digest,
        OFFICER, 'fixture-target', fact(True), fact(True), fact(True),
        (actor(h),), (rule(),), (), ((REF, 'f'*64),))
    return replace(value, **changes)


def test_reported_only_mode_preserves_original_history_and_never_accepts_authority():
    h = history(); result = ActionAuthority(h).review(action())
    assert result['status'] == 'CANNOT_VERIFY' and result['mode'] == 'REPORTED_INPUTS_ONLY'
    assert not result['accepted_authority_claim'] and not result['assessment_authenticity_claim']
    assert result['actor_state_links'][0]['state_id']


def test_explicit_direct_authority_uses_exact_reconstructed_action_date():
    h = history(); result = ActionAuthority(h).review(action(), packet(h))
    assert result['status'] == 'VALID' and result['successful_paths'] == ['fixture-rule']
    assert result['actor_state_links'][0]['on'] == '2020-01-10'
    assert result['actor_state_links'][0]['assessment_supplied']
    assert not result['accepted_authority_claim']  # pure input evaluation, not a live audit


@pytest.mark.parametrize('field,value', [('rank', 'other-rank'), ('role', 'other-role'),
    ('scope', 'other-scope'), ('active', False)])
def test_assessed_complete_refutation_is_invalid(field, value):
    h = history(); p = packet(h); assessed = p.states[0]
    p = replace(p, states=(replace(assessed, state=replace(assessed.state, **{field: fact(value)})),))
    assert ActionAuthority(h).review(action(), p)['status'] == 'INVALID'


def test_incomplete_coverage_does_not_turn_refuted_route_into_invalid():
    h = history(); p = packet(h, coverage=fact(None, 'UNASSESSED'), states=(actor(h, active=False),))
    assert ActionAuthority(h).review(action(), p)['status'] == 'CANNOT_VERIFY'


@pytest.mark.parametrize('field', ['identity', 'date_semantics'])
def test_unassessed_action_fact_blocks_authority(field):
    h = history(); p = packet(h, **{field: fact(None, 'UNASSESSED')})
    assert ActionAuthority(h).review(action(), p)['status'] == 'CANNOT_VERIFY'


def delegated(h, *, expired_issuer=False, revoke=None, scope='fixture-target', may_delegate=True):
    issuer = str(uuid4()); h.buckets[issuer] = {}
    grant = Delegation('fixture-grant', 'fixture-rule', issuer, OFFICER,
        ('AUTHORIZE_PROMOTION',), (scope,), ISSUED, ISSUED, None, False, revoke, 'ASSESSED', (REF,))
    return packet(h, states=(actor(h, rank='recipient-rank'), actor(h, issuer, ISSUED),
        actor(h, issuer, DAY, active=not expired_issuer)),
        rules=(rule(may_delegate=may_delegate),), delegations=(grant,))


def test_delegation_reconstructs_issuer_at_issuance_and_action_date():
    h = history(); p = delegated(h); result = ActionAuthority(h).review(action(), p)
    assert result['status'] == 'VALID' and result['successful_paths'] == ['fixture-grant']
    issuer = p.delegations[0].issuer_uid
    assert {(r['officer_uid'], r['on']) for r in result['actor_state_links']} >= {
        (issuer, '2020-01-05'), (issuer, '2020-01-10'), (OFFICER, '2020-01-10')}


@pytest.mark.parametrize('change', ['issuer_inactive', 'revoked', 'scope_expansion', 'cannot_delegate'])
def test_delegated_refutations_are_not_hidden(change):
    h = history(); p = delegated(h, expired_issuer=change == 'issuer_inactive',
        revoke=DAY if change == 'revoked' else None,
        scope='ungranted-scope' if change == 'scope_expansion' else 'fixture-target',
        may_delegate=change != 'cannot_delegate')
    assert ActionAuthority(h).review(action(), p)['status'] == 'INVALID'


def test_missing_issuer_assessment_keeps_real_reported_history_unassessed():
    h = history(); p = delegated(h)
    p = replace(p, states=tuple(s for s in p.states if s.state.actor_uid == OFFICER))
    assert ActionAuthority(h).review(action(), p)['status'] == 'CANNOT_VERIFY'


def test_revocation_and_half_open_rule_boundaries():
    h = history(); p = packet(h, rules=(rule(end=DAY),))
    assert ActionAuthority(h).review(action(), p)['status'] == 'INVALID'
    p = packet(h, rules=(rule(start=DAY),))
    assert ActionAuthority(h).review(action(), p)['status'] == 'VALID'


@pytest.mark.parametrize('change', ['public', 'action', 'destination', 'state_id', 'different_actor', 'missing_date'])
def test_mixed_evidence_versions_are_rejected(change):
    h = history(); a = action(); p = packet(h)
    if change == 'public': p = replace(p, public_payload_sha256='0'*64)
    elif change == 'action': p = replace(p, original_action_digest='0'*64)
    elif change == 'destination': p = replace(p, destination_digest='0'*64)
    elif change == 'state_id': p = replace(p, states=(replace(p.states[0], state_id='0'*64),))
    elif change == 'different_actor': p = replace(p, actor_uid=str(uuid4()))
    else: a = replace(a, reported_date=None); p = packet(h, a)
    with pytest.raises(ValueError): ActionAuthority(h).review(a, p)


def test_uncited_assessment_evidence_is_rejected():
    h = history()
    with pytest.raises(ValueError, match='outside inventory'): packet(h, evidence_digests=())


def test_duplicate_instruments_and_state_assessments_are_rejected():
    h = history(); p = packet(h)
    with pytest.raises(ValueError, match='Duplicate authority'): replace(p, rules=p.rules * 2)
    with pytest.raises(ValueError, match='Duplicate assessed'): replace(p, states=p.states * 2)


def test_unused_state_overrides_are_rejected():
    h = history(); p = packet(h)
    p = replace(p, states=(*p.states, actor(h, on=date(2022, 1, 1))))
    with pytest.raises(ValueError, match='unused'): ActionAuthority(h).review(action(), p)


def test_cycle_stays_unresolved_and_traversal_is_bounded():
    h = history(); p = delegated(h); d = p.delegations[0]
    d = replace(d, parent_id=d.delegation_id, issuer_uid=OFFICER, may_delegate=True)
    p = replace(p, rules=(), delegations=(d,), states=(actor(h), actor(h, on=ISSUED)))
    result = ActionAuthority(h).review(action(), p)
    assert result['status'] == 'CANNOT_VERIFY'
    assert 'DELEGATION_CYCLE_OR_DEPTH_UNRESOLVED' in result['reasons']


def test_candidate_ambiguity_is_preserved_without_assessment():
    h = history(); other = str(uuid4()); h.buckets[other] = {}
    a = replace(action(), actor_candidates=(OFFICER, other))
    result = ActionAuthority(h).review(a)
    assert result['reported_history']['history_link_status'] == 'AMBIGUOUS_CANDIDATE_HISTORIES'
    assert len(result['actor_state_links']) == 2


def test_action_history_sources_and_packet_not_mutated_and_replay_is_deterministic():
    h = history(); a = action(); p = packet(h); before = deepcopy(h.buckets)
    first = ActionAuthority(h).review(a, p); second = ActionAuthority(h).review(a, p)
    assert first == second and h.buckets == before and a == action()


def test_inventory_covers_every_action_and_retains_unassessed_actions():
    from app.identity.action_authority_integration import evaluate_action_inventory
    h = history(); first = action(); second = replace(first, raw_record_id='b'*64)
    results, report = evaluate_action_inventory((first, second), h, (packet(h),))
    assert len(results) == report['authority_action_records'] == 2
    assert report['status_counts'] == {'CANNOT_VERIFY': 1, 'VALID': 1}
    assert report['explicit_assessment_packets'] == 1 and not report['new_research_audit_executed']


def test_inventory_rejects_orphan_or_duplicate_assessment_and_duplicate_action():
    from app.identity.action_authority_integration import evaluate_action_inventory
    h = history(); p = packet(h)
    with pytest.raises(ValueError, match='outside supplied'): evaluate_action_inventory((), h, (p,))
    with pytest.raises(ValueError, match='Duplicate action assessment'): evaluate_action_inventory((action(),), h, (p, p))
    with pytest.raises(ValueError, match='Duplicate original'): evaluate_action_inventory((action(), action()), h)


def test_inventory_empty_is_explicit_zero_coverage_not_research_completion():
    from app.identity.action_authority_integration import evaluate_action_inventory
    results, report = evaluate_action_inventory((), history())
    assert results == () and report['authority_action_records'] == 0 and report['status_counts'] == {}
    assert not report['new_research_audit_executed']


def test_successful_alternative_path_is_not_refuted_by_another_bad_rule():
    h = history(); p = packet(h, rules=(rule(), rule(rule_id='bad-rule', ranks=('other-rank',))))
    result = ActionAuthority(h).review(action(), p)
    assert result['status'] == 'VALID' and result['successful_paths'] == ['fixture-rule']


def test_unassessed_instrument_does_not_become_valid_from_rank_match():
    h = history(); p = packet(h, rules=(rule(assessment='UNASSESSED'),))
    assert ActionAuthority(h).review(action(), p)['status'] == 'CANNOT_VERIFY'
