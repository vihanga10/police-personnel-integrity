"""Runs the frozen authority cases (authority_frozen_cases.py, not edited here) and records the results.

Only invented fixtures are used. Results go to tests/authority_frozen_results.json for Chapter 5.
"""
from datetime import date
from pathlib import Path
from uuid import UUID
import json

from app.identity.temporal_authority import Fact, ActorState, Action, Rule, Delegation, evaluate
from authority_frozen_cases import CASES

RESULTS = Path(__file__).with_name('authority_frozen_results.json')
ON = date(2024, 12, 31)
ISSUED = date(2024, 1, 1)
UIDS = {n: str(UUID(int=n + 1)) for n in range(0, 40)}
A, B, C = UIDS[0], UIDS[1], UIDS[2]
NAMED = {'A': A, 'B': B, 'C': C}


def d(text):
    return date.fromisoformat(text) if isinstance(text, str) else text


def fact(spec, value=None):
    """spec 'A' assessed(value), 'U' unassessed, 'X' conflicting."""
    if spec == 'U':
        return Fact(None, 'UNASSESSED')
    if spec == 'X':
        # value None is valid for boolean and label fields alike (first run used a string, which boolean fields refuse)
        return Fact(None, 'CONFLICTING', ('fixture-proof',))
    return Fact(value, 'ASSESSED', ('fixture-proof',))


def good(value):
    return Fact(value, 'ASSESSED', ('fixture-proof',))


def state(uid, on, **facts):
    base = dict(identity=good(True), rank=good('fixture-rank'), role=good('fixture-role'), active=good(True), scope=good('fixture-origin'))
    base.update(facts)
    return ActorState(actor_uid=uid, on=on, **base)


def make_rule(**over):
    values = dict(rule_id='fixture-rule', powers=('fixture-approve',), ranks=('fixture-rank',), roles=('fixture-role',),
                  actor_scopes=('fixture-origin',), target_scopes=('fixture-target',), start=date(2020, 1, 1), end=None,
                  may_delegate=True, assessment='ASSESSED', evidence=('fixture-rule-proof',))
    for k, v in over.items():
        values[k] = d(v) if k in ('start', 'end') else v
    return Rule(**values)


def make_action(actor, **over):
    values = dict(actor_uid=actor, on=ON, power='fixture-approve', target_scope='fixture-target', identity=good(True),
                  date_semantics=good(True), evidence=('fixture-action',))
    for k, (spec, value) in over.items():
        values[k] = fact(spec, value)
    return Action(**values)


def make_delegation(did, parent, issuer, recipient_uid, **over):
    values = dict(delegation_id=did, parent_id=parent, issuer_uid=issuer, recipient_uid=recipient_uid, powers=('fixture-approve',),
                  target_scopes=('fixture-target',), issued_on=ISSUED, start=ISSUED, end=None, may_delegate=False,
                  revoked_from=None, assessment='ASSESSED', evidence=('fixture-delegation-proof',))
    for k, v in over.items():
        if k == 'recipient':
            v, k = NAMED[v], 'recipient_uid'
        values[k] = d(v) if k in ('issued_on', 'start', 'end', 'revoked_from') else v
    return Delegation(**values)


def coverage(case):
    return Fact(None, 'UNASSESSED') if case.get('coverage') == 'unassessed' else good(True)


def build_direct(case):
    state_facts = {k: fact(*v) for k, v in case.get('state_fact', {}).items()}
    on = d(case.get('state_date', ON))
    states = [] if case.get('no_states') else [state(A, on, **state_facts)]
    rules_mode = case.get('rules')
    if rules_mode == 'none':
        rules = []
    elif rules_mode == 'second_refuted':
        rules = [make_rule(), make_rule(rule_id='fixture-rule-2', ranks=('fixture-other-rank',))]
    elif rules_mode == 'both_refuted':
        rules = [make_rule(ranks=('x1',)), make_rule(rule_id='fixture-rule-2', ranks=('x2',))]
    else:
        rules = [make_rule(**case.get('rule_over', {}))]
    return make_action(A, **case.get('action', {})), states, rules, [], coverage(case)


def build_delegated(case):
    over = dict(case.get('delegation', {}))
    delegation = make_delegation('fixture-delegation', over.pop('parent_id', 'fixture-rule'), A, B, **over)
    rule = make_rule(**case.get('rule_over', {}))
    other = dict(rank=good('fixture-other-rank'))
    issuer_issue = state(A, delegation.issued_on, active=good(case.get('issuer_active_at_issue', True)))
    issuer_action = state(A, ON, active=good(case.get('issuer_active_at_action', True)))
    states = [state(B, ON, **other), issuer_action]
    if not case.get('skip_issuer_issue_state') and delegation.issued_on != ON:
        states.append(issuer_issue)
    return make_action(B), states, [rule], [delegation], coverage(case)


def build_chain(case, cycle=False):
    n = 2 if cycle else case['links']
    delegations, states = [], []
    for i in range(1, n + 1):
        parent = 'fixture-rule' if i == 1 else 'fixture-d%d' % (i - 1)
        over = dict(may_delegate=(i < n))
        if i == 1 and case.get('first_may_delegate') is False:
            over['may_delegate'] = False
        if i == 1 and case.get('first_revoked_from'):
            over['revoked_from'] = case['first_revoked_from']
        if i == 2 and case.get('second_powers'):
            over['powers'] = case['second_powers']
        if cycle:
            parent = 'fixture-d2' if i == 1 else 'fixture-d1'
        delegations.append(make_delegation('fixture-d%d' % i, parent, UIDS[i - 1], UIDS[i], **over))
    for i in range(0, n + 1):
        extra = {} if i == 0 else dict(rank=good('fixture-other-rank'))
        states.append(state(UIDS[i], ON, **extra))
        if i < n:
            states.append(state(UIDS[i], ISSUED, **extra))
    return make_action(UIDS[n]), states, [make_rule()], delegations, coverage(case)


def build_rejection(case):
    which = case['build']
    if which == 'issued_after_start':
        make_delegation('x', 'fixture-rule', A, B, issued_on='2024-02-01', start='2024-01-01')
    elif which == 'delegation_end_before_start':
        make_delegation('x', 'fixture-rule', A, B, start='2024-01-01', end='2024-01-01')
    elif which == 'rule_end_before_start':
        make_rule(start='2020-01-01', end='2020-01-01')
    elif which == 'assessed_without_evidence':
        Fact('x', 'ASSESSED', ())
    elif which == 'empty_scope':
        make_rule(ranks=())


def run_case(case):
    mode = case.get('mode', 'direct')
    try:
        if mode == 'reject':
            build_rejection(case)
            return 'ACCEPTED_INPUT'
        action, states, rules, delegations, cover = {'direct': build_direct, 'delegated': build_delegated,
                                                    'chain': build_chain, 'cycle': lambda c: build_chain(c, cycle=True)}[mode](case)
        return evaluate(action, states, rules, delegations, coverage=cover).status
    except ValueError:
        return 'REJECT'


def test_frozen_authority_cases_and_record_results():
    rows, failures = [], []
    for case in CASES:
        observed = run_case(case)
        ok = observed == case['exp']
        rows.append({'id': case['id'], 'rule': case['rule'], 'expected': case['exp'], 'observed': observed, 'passed': ok,
                     'author_reading': bool(case.get('reading'))})
        if not ok:
            failures.append(case['id'])
    RESULTS.write_text(json.dumps({'total': len(rows), 'passed': len(rows) - len(failures), 'failed': failures, 'cases': rows}, indent=1))
    assert not failures, 'Frozen authority cases that differ from the written expectation: ' + ', '.join(failures)
