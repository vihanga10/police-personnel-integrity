"""FROZEN authority-evaluation test cases (Chapter 5, algorithm 2).

Expected answers were written from docs/temporal-authority-algorithm-v1.md and
docs/action-date-authority-integration-v1.md BEFORE the evaluator was run on these cases. They must
not be edited to make a result pass; a failing case is reported and examined as a defect or a
mistaken expectation. All rules, ranks and scopes are INVENTED fixtures: these cases test the
algorithm, not Sri Lankan legal authority.

Documented definitions used
  VALID          at least one fully assessed direct or delegated route supports the action.
  INVALID        every available route is refuted AND coverage is explicitly assessed complete.
  CANNOT_VERIFY  anything unresolved, or no successful route and coverage not established complete.
  Intervals are half-open [start,end); revocation applies from its date inclusively; sub-delegation needs
  permission at every link; delegated power/scope may not exceed the parent; V1 requires issuer authority at
  issuance and at the action date; actor state must match the exact action date; cycles and chains of
  16 or more instruments stay unresolved; a refuted alternative never overturns a successful route.

Case format
  id, rule (the sentence tested), exp in {VALID, INVALID, CANNOT_VERIFY, REJECT}, and `mode`:
    'direct'     actor A acts under a rule (default)
    'delegated'  actor B acts; A holds the rule authority and delegates to B; B alone fails the rule
    'chain'      actor C acts through A -> B -> C (`links` = number of delegations in the chain)
  Optional override keys are interpreted by test_authority_frozen.py (state_fact, rule, delegation,
  action, coverage, no_states, state_date, rules).
  `reading=True` marks answers that rest on the author's reading where the documents are less explicit.
"""

C = 'complete'
U = 'unassessed'

CASES = [
    # ---------------- Direct route
    dict(id='D01', rule='a fully assessed matching route with complete coverage is VALID', exp='VALID'),
    dict(id='D02', rule='an unassessed identity never authorises', exp='CANNOT_VERIFY', state_fact={'identity': ('U', None)}),
    dict(id='D03', rule='an unassessed rank never authorises', exp='CANNOT_VERIFY', state_fact={'rank': ('U', None)}),
    dict(id='D04', rule='an unassessed role never authorises', exp='CANNOT_VERIFY', state_fact={'role': ('U', None)}),
    dict(id='D05', rule='an unassessed service status never authorises', exp='CANNOT_VERIFY', state_fact={'active': ('U', None)}),
    dict(id='D06', rule='an unassessed scope never authorises', exp='CANNOT_VERIFY', state_fact={'scope': ('U', None)}),
    dict(id='D07', rule='a conflicting identity never authorises', exp='CANNOT_VERIFY', state_fact={'identity': ('X', None)}),
    dict(id='D08', rule='a conflicting rank never authorises', exp='CANNOT_VERIFY', state_fact={'rank': ('X', None)}),
    dict(id='D09', rule='a conflicting role never authorises', exp='CANNOT_VERIFY', state_fact={'role': ('X', None)}),
    dict(id='D10', rule='a conflicting service status never authorises', exp='CANNOT_VERIFY', state_fact={'active': ('X', None)}),
    dict(id='D11', rule='a conflicting scope never authorises', exp='CANNOT_VERIFY', state_fact={'scope': ('X', None)}),
    dict(id='D12', rule='a refuted rank with complete coverage is INVALID', exp='INVALID', state_fact={'rank': ('A', 'other-rank')}),
    dict(id='D13', rule='a refuted role with complete coverage is INVALID', exp='INVALID', state_fact={'role': ('A', 'other-role')}),
    dict(id='D14', rule='a refuted scope with complete coverage is INVALID', exp='INVALID', state_fact={'scope': ('A', 'other-scope')}),
    dict(id='D15', rule='an inactive officer with complete coverage is INVALID', exp='INVALID', state_fact={'active': ('A', False)}),
    dict(id='D16', rule='a refuted rank without complete coverage is only CANNOT_VERIFY', exp='CANNOT_VERIFY', state_fact={'rank': ('A', 'other-rank')}, coverage=U),
    dict(id='D17', rule='a refuted role without complete coverage is only CANNOT_VERIFY', exp='CANNOT_VERIFY', state_fact={'role': ('A', 'other-role')}, coverage=U),
    dict(id='D18', rule='a refuted scope without complete coverage is only CANNOT_VERIFY', exp='CANNOT_VERIFY', state_fact={'scope': ('A', 'other-scope')}, coverage=U),
    dict(id='D19', rule='an inactive officer without complete coverage is only CANNOT_VERIFY', exp='CANNOT_VERIFY', state_fact={'active': ('A', False)}, coverage=U),
    dict(id='D20', rule='a refuted action identity is unresolved, not an accusation', exp='CANNOT_VERIFY', action={'identity': ('A', False)}),
    dict(id='D21', rule='a refuted action date meaning is unresolved', exp='CANNOT_VERIFY', action={'date_semantics': ('A', False)}),
    dict(id='D22', rule='an unassessed action identity is unresolved', exp='CANNOT_VERIFY', action={'identity': ('U', None)}),
    dict(id='D23', rule='an unassessed action date meaning is unresolved', exp='CANNOT_VERIFY', action={'date_semantics': ('U', None)}),
    dict(id='D24', rule='a rule starting after the action date does not apply; with complete coverage the route set is refuted',
         exp='INVALID', rule_over={'start': '2025-01-01'}, reading=True),
    dict(id='D25', rule='half-open interval: the action on the rule end date is outside the rule', exp='INVALID', rule_over={'start': '2020-01-01', 'end': '2024-12-31'}, reading=True),
    dict(id='D26', rule='half-open interval: the day before the end is inside', exp='VALID', rule_over={'end': '2025-01-01'}),
    dict(id='D27', rule='the rule start day itself is inside', exp='VALID', rule_over={'start': '2024-12-31'}),
    dict(id='D28', rule='an unassessed rule never authorises', exp='CANNOT_VERIFY', rule_over={'assessment': 'UNASSESSED'}),
    dict(id='D29', rule='a conflicting rule never authorises', exp='CANNOT_VERIFY', rule_over={'assessment': 'CONFLICTING'}),
    dict(id='D30', rule='a power the rule does not grant is refuted (complete coverage)', exp='INVALID', rule_over={'powers': ('fixture-other',)}),
    dict(id='D31', rule='the same without complete coverage is CANNOT_VERIFY', exp='CANNOT_VERIFY', rule_over={'powers': ('fixture-other',)}, coverage=U),
    dict(id='D32', rule='a target scope outside the rule is refuted (complete coverage)', exp='INVALID', rule_over={'target_scopes': ('fixture-elsewhere',)}),
    dict(id='D33', rule='the same without complete coverage is CANNOT_VERIFY', exp='CANNOT_VERIFY', rule_over={'target_scopes': ('fixture-elsewhere',)}, coverage=U),
    dict(id='D34', rule='no governing rule and no assessed coverage is CANNOT_VERIFY, never invalid', exp='CANNOT_VERIFY', rules='none', coverage=U),
    dict(id='D35', rule='actor state for a different date is not state on the action date', exp='CANNOT_VERIFY', state_date='2024-06-30'),
    dict(id='D36', rule='no actor state at all is CANNOT_VERIFY', exp='CANNOT_VERIFY', no_states=True),
    dict(id='D37', rule='a refuted alternative does not overturn a successful route', exp='VALID', rules='second_refuted'),
    dict(id='D38', rule='all routes refuted with complete coverage is INVALID', exp='INVALID', rules='both_refuted'),
    # ---------------- One delegation (A delegates to B; B alone fails the rule)
    dict(id='G01', mode='delegated', rule='a valid delegation from an authorised issuer supports the action', exp='VALID'),
    dict(id='G02', mode='delegated', rule='a delegation starting after the action date is not in force', exp='INVALID', delegation={'issued_on': '2025-01-01', 'start': '2025-01-01'}),
    dict(id='G03', mode='delegated', rule='half-open delegation interval: the end date is outside', exp='INVALID', delegation={'end': '2024-12-31'}),
    dict(id='G04', mode='delegated', rule='the day before the delegation end is inside', exp='VALID', delegation={'end': '2025-01-01'}),
    dict(id='G05', mode='delegated', rule='the delegation start day is inside', exp='VALID', delegation={'start': '2024-12-31', 'issued_on': '2024-12-31'}, issuer_dates=('2024-12-31',)),
    dict(id='G06', mode='delegated', rule='revocation is effective from its own date inclusively', exp='INVALID', delegation={'revoked_from': '2024-12-31'}),
    dict(id='G07', mode='delegated', rule='a revocation the day after the action does not affect it', exp='VALID', delegation={'revoked_from': '2025-01-01'}),
    dict(id='G08', mode='delegated', rule='an earlier revocation removes the delegation', exp='INVALID', delegation={'revoked_from': '2024-06-01'}),
    dict(id='G09', mode='delegated', rule='a delegation to someone else does not support this actor', exp='INVALID', delegation={'recipient': 'C'}),
    dict(id='G10', mode='delegated', rule='a delegation that omits the action power is refuted', exp='INVALID', delegation={'powers': ('fixture-other',)}),
    dict(id='G11', mode='delegated', rule='a delegation that omits the target scope is refuted', exp='INVALID', delegation={'target_scopes': ('fixture-elsewhere',)}),
    dict(id='G12', mode='delegated', rule='a delegation granting more than its parent rule is unsupported', exp='INVALID', delegation={'powers': ('fixture-approve', 'fixture-extra')}, reading=True),
    dict(id='G13', mode='delegated', rule='a parent rule that forbids delegation refutes the route', exp='INVALID', rule_over={'may_delegate': False}),
    dict(id='G14', mode='delegated', rule='a parent rule with unassessed delegation permission is unresolved', exp='CANNOT_VERIFY', rule_over={'may_delegate': None}),
    dict(id='G15', mode='delegated', rule='issuer inactive on the action date refutes the route (V1 convention)', exp='INVALID', issuer_active_at_action=False),
    dict(id='G16', mode='delegated', rule='issuer without authority at issuance refutes the route (V1 convention)', exp='INVALID', issuer_active_at_issue=False),
    dict(id='G17', mode='delegated', rule='missing issuer state at issuance is unresolved', exp='CANNOT_VERIFY', skip_issuer_issue_state=True),
    dict(id='G18', mode='delegated', rule='an unassessed delegation never authorises', exp='CANNOT_VERIFY', delegation={'assessment': 'UNASSESSED'}),
    dict(id='G19', mode='delegated', rule='a conflicting delegation never authorises', exp='CANNOT_VERIFY', delegation={'assessment': 'CONFLICTING'}),
    dict(id='G20', mode='delegated', rule='a delegation whose parent is missing stays unresolved', exp='CANNOT_VERIFY', delegation={'parent_id': 'fixture-missing'}),
    dict(id='G21', mode='delegated', rule='a refuted delegation without complete coverage is only CANNOT_VERIFY', exp='CANNOT_VERIFY', delegation={'revoked_from': '2024-06-01'}, coverage=U),
    # ---------------- Chains
    dict(id='H01', mode='chain', links=2, rule='a two-link chain with permission at every link is VALID', exp='VALID'),
    dict(id='H02', mode='chain', links=2, rule='a middle link that cannot sub-delegate refutes the chain', exp='INVALID', first_may_delegate=False),
    dict(id='H03', mode='chain', links=2, rule='a second link granting more than its parent is unsupported', exp='INVALID', second_powers=('fixture-approve', 'fixture-extra'), reading=True),
    dict(id='H04', mode='chain', links=2, rule='a revoked first link breaks the chain', exp='INVALID', first_revoked_from='2024-06-01'),
    dict(id='H05', mode='cycle', rule='delegations that name each other as parent form a cycle and stay unresolved', exp='CANNOT_VERIFY'),
    dict(id='H06', mode='chain', links=20, rule='a chain of 20 instruments exceeds the traversal bound and stays unresolved', exp='CANNOT_VERIFY'),
    # ---------------- Invalid input must be refused, not guessed
    dict(id='J01', mode='reject', rule='a delegation issued after it starts is refused', exp='REJECT', build='issued_after_start'),
    dict(id='J02', mode='reject', rule='a delegation ending on or before it starts is refused', exp='REJECT', build='delegation_end_before_start'),
    dict(id='J03', mode='reject', rule='a rule ending on or before it starts is refused', exp='REJECT', build='rule_end_before_start'),
    dict(id='J04', mode='reject', rule='an assessed fact without evidence is refused', exp='REJECT', build='assessed_without_evidence'),
    dict(id='J05', mode='reject', rule='a rule with an empty scope is refused', exp='REJECT', build='empty_scope'),
]
