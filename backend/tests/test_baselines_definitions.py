"""The baselines do exactly what their definitions say (checked on tiny hand-made inputs, before any evaluation run)."""
from baselines import current_only_history, rank_only_authority, value_only_contradictions, wilson, prf, confusion, CAND, AGREE


def v(vid, cid, dim, value, start, rec='2026-10-02', wd=False, mode='EVENT', end=None):
    return (vid, cid, dim, value, mode, start, end, rec, None, wd)


def test_current_only_history_ignores_both_dates_and_never_separates_future_or_expired():
    versions = [v('1', 'a', 'rank', 'Inspector', '2015-01-01'), v('2', 'b', 'rank', 'Chief', '2020-01-01'), v('3', 'c', 'rank', 'Late', '2022-01-01', rec='2026-10-30')]
    assert current_only_history(versions, ['rank']) == {'rank': {'candidates': ['Late'], 'future': [], 'expired': []}}
    assert current_only_history([v('1', 'a', 'rank', 'X', '2015-01-01'), v('2', 'a', 'rank', 'X', '2015-01-01', wd=True, rec='2026-10-05')], ['rank'])['rank']['candidates'] == []
    police = [v('1', 'p', 'police_number', 'N1', '2010-01-01', mode='INTERVAL', end='2012-01-01'), v('2', 'q', 'police_number', 'N2', '2013-01-01', mode='INTERVAL')]
    assert current_only_history(police, ['police_number'])['police_number']['candidates'] == ['N1', 'N2']


class Fact:
    def __init__(self, value): self.value = value


class State:
    def __init__(self, uid, rank): self.actor_uid, self.rank = uid, Fact(rank)


class Rule:
    def __init__(self, ranks): self.ranks = ranks


class Action:
    def __init__(self, uid): self.actor_uid = uid


def test_rank_only_authority_uses_rank_alone_and_never_answers_cannot_verify():
    a = Action('u1')
    assert rank_only_authority(a, [State('u1', 'SP')], [Rule(('SP', 'DIG'))], [], None) == 'VALID'
    assert rank_only_authority(a, [State('u1', 'SI')], [Rule(('SP',))], [], None) == 'INVALID'
    assert rank_only_authority(a, [State('u1', None)], [Rule(('SP',))], [], None) == 'INVALID'
    assert rank_only_authority(a, [], [Rule(('SP',))], [], None) == 'INVALID'
    assert rank_only_authority(a, [State('u1', 'SP')], [], [], None) == 'INVALID'
    assert rank_only_authority(a, [State('u2', 'SP')], [Rule(('SP',))], [], None) == 'INVALID'


def c(cid, dim, value, **kw):
    return dict(id=cid, dim=dim, value=value, **kw)


def test_value_only_contradictions_compare_values_only():
    claims = [c('a', 'rank', {'to_rank': 'X'}), c('b', 'rank', {'to_rank': 'Y'}), c('c', 'rank', {'to_rank': 'X'})]
    assert value_only_contradictions(claims) == [[['a', 'b'], CAND], [['a', 'c'], AGREE], [['b', 'c'], CAND]]
    # different number types or distinct restriction ids are still "different values"; dates and eligibility are ignored
    nums = [c('a', 'police_number', {'police_no': '1', 'number_type': 'police'}), c('b', 'police_number', {'police_no': '2', 'number_type': 'warrant'})]
    assert value_only_contradictions(nums) == [[['a', 'b'], CAND]]
    assert value_only_contradictions([c('a', 'rank', {'x': '1'}), c('b', 'posting', {'x': '2'})]) == []
    assert value_only_contradictions([c('a', 'rank', {'to_rank': 'X'}), c('b', 'rank', {'to_rank': 'Y'}), c('b', 'rank', {'to_rank': 'Y'}, wd=True)]) == []


def test_metric_helpers_mark_undefined_ratios_and_compute_wilson_and_macro_f1():
    assert wilson(0, 0) == (None, None)
    low, high = wilson(47, 47)
    assert 0.92 < low < 0.94 and high == 1.0
    assert prf(0, 0, 0)['precision'] is None and prf(3, 1, 1)['f1'] == 0.75
    matrix, scores = confusion([('VALID', 'VALID'), ('INVALID', 'VALID'), ('INVALID', 'INVALID'), ('CANNOT_VERIFY', 'INVALID')])
    assert matrix['INVALID']['VALID'] == 1 and matrix['CANNOT_VERIFY']['INVALID'] == 1
    assert scores['per_class_f1']['CANNOT_VERIFY'] == 0.0 and 0 < scores['macro_f1'] < 1
