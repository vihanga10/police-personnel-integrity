"""Integrated procedures versus the three simple baselines, on the SAME frozen case sets (Chapter 3, Section 3.9.2).

Writes tests/baseline_results.json. No case is removed for failing; cases that test refusal of malformed input are reported
separately because the baselines perform no validation.
"""
import json
from pathlib import Path

import baselines as B
import test_authority_frozen as A
import test_contradiction_frozen as C
import test_history_frozen as H
from authority_frozen_cases import CASES as AUTHORITY
from contradiction_frozen_cases import CASES as CONTRADICTION
from history_frozen_cases import CASES as HISTORY

RESULTS = Path(__file__).with_name('baseline_results.json')


def proportion(correct, total):
    low, high = B.wilson(correct, total)
    return {'correct': correct, 'total': total, 'percent': round(100 * correct / total, 1) if total else None, 'wilson95': [low, high]}


def paired(rows):
    """rows: (case id, integrated_correct, baseline_correct)."""
    return {'both_correct': sum(1 for _, i, b in rows if i and b), 'only_integrated_correct': [c for c, i, b in rows if i and not b],
            'only_baseline_correct': [c for c, i, b in rows if b and not i], 'neither_correct': [c for c, i, b in rows if not i and not b]}


def history():
    rows, evaluable, refusals = [], [], []
    for case in HISTORY:
        if 'reject' in case['exp']:
            refusals.append(case)
            continue
        evaluable.append(case)
        integrated = H.run_case(case) == case['exp']
        baseline = B.current_only_history(case['v'], list(case['exp'])) == case['exp']
        candidates_only = all(B.current_only_history(case['v'], [d])[d]['candidates'] == case['exp'][d]['candidates'] for d in case['exp'])
        rows.append((case['id'], integrated, baseline, candidates_only))
    return {
        'evaluable_cases': len(evaluable),
        'integrated': proportion(sum(1 for _, i, _, _ in rows if i), len(rows)),
        'current_only_exact': proportion(sum(1 for _, _, b, _ in rows if b), len(rows)),
        'current_only_candidate_values_only': proportion(sum(1 for _, _, _, c in rows if c), len(rows)),
        'paired_exact': paired([(c, i, b) for c, i, b, _ in rows]),
        'refusal_cases': {'count': len(refusals), 'integrated_refused': sum(1 for c in refusals if H.run_case(c) == {'reject': True}), 'baseline_refused': 0}}


def authority():
    rows, refusals = [], []
    for case in AUTHORITY:
        if case['exp'] == 'REJECT':
            refusals.append(case)
            continue
        mode = case.get('mode', 'direct')
        inputs = {'direct': A.build_direct, 'delegated': A.build_delegated, 'chain': A.build_chain, 'cycle': lambda c: A.build_chain(c, cycle=True)}[mode](case)
        rows.append((case['id'], case['exp'], A.run_case(case), B.rank_only_authority(*inputs)))
    labels = ('VALID', 'INVALID', 'CANNOT_VERIFY')
    out = {'evaluable_cases': len(rows), 'reference_mix': {l: sum(1 for r in rows if r[1] == l) for l in labels}}
    for name, index in (('integrated', 2), ('rank_only', 3)):
        matrix, scores = B.confusion([(r[1], r[index]) for r in rows], labels)
        out[name] = {'accuracy': proportion(sum(1 for r in rows if r[1] == r[index]), len(rows)), 'confusion_matrix_expected_by_observed': matrix, **scores}
    out['paired'] = paired([(r[0], r[1] == r[2], r[1] == r[3]) for r in rows])
    out['refusal_cases'] = {'count': len(refusals), 'integrated_refused': sum(1 for c in refusals if A.run_case(c) == 'REJECT'), 'baseline_refused': 0}
    return out


def contradictions():
    rows, refusals = [], []
    tp = {'integrated': 0, 'value_only': 0}
    fp, fn = dict(tp), dict(tp)
    for case in CONTRADICTION:
        if case['exp'] == 'REJECT':
            refusals.append(case)
            continue
        expected = C.expected(case)
        integrated, baseline = C.run_case(case), B.value_only_contradictions(case['claims'])
        rows.append((case['id'], integrated == expected, baseline == expected))
        wanted = {tuple(p) for p, s in expected if s == B.CAND}
        for name, observed in (('integrated', integrated), ('value_only', baseline)):
            seen = {tuple(p) for p, s in observed if s == B.CAND}
            tp[name] += len(wanted & seen)
            fp[name] += len(seen - wanted)
            fn[name] += len(wanted - seen)
    expected_pairs = [(tuple(p), s) for case in CONTRADICTION if case['exp'] != 'REJECT' for p, s in C.expected(case)]
    status_matches = sum(1 for case in CONTRADICTION if case['exp'] != 'REJECT' for p, s in C.expected(case)
                         if [p, s] in B.value_only_contradictions(case['claims']))
    return {'evaluable_cases': len(rows), 'expected_pairs': len(expected_pairs),
            'integrated': {'case_accuracy': proportion(sum(1 for _, i, _ in rows if i), len(rows)), 'candidate_class': B.prf(tp['integrated'], fp['integrated'], fn['integrated'])},
            'value_only': {'case_accuracy': proportion(sum(1 for _, _, b in rows if b), len(rows)), 'candidate_class': B.prf(tp['value_only'], fp['value_only'], fn['value_only']),
                           'expected_pairs_given_the_expected_status': proportion(status_matches, len(expected_pairs))},
            'paired': paired(rows),
            'refusal_cases': {'count': len(refusals), 'integrated_refused': sum(1 for c in refusals if C.run_case(c) == 'REJECT'), 'baseline_refused': 0}}


def test_comparison_runs_on_the_frozen_sets_and_records_every_number():
    report = {'history': history(), 'authority': authority(), 'contradiction': contradictions(),
              'note': 'Baselines were defined and committed before this run. The case sets are purposive boundary coverage, so the comparison shows what the added evidence conditions contribute, not general superiority.'}
    RESULTS.write_text(json.dumps(report, indent=1, sort_keys=True))
    # The integrated procedures must still reproduce their recorded frozen results (a regression guard, not a target).
    assert report['history']['integrated']['correct'] == report['history']['integrated']['total']
    assert report['authority']['integrated']['accuracy']['correct'] == report['authority']['integrated']['accuracy']['total']
    assert report['contradiction']['integrated']['case_accuracy']['correct'] == report['contradiction']['integrated']['case_accuracy']['total']
    assert report['history']['evaluable_cases'] + report['history']['refusal_cases']['count'] == 47
    assert report['authority']['evaluable_cases'] + report['authority']['refusal_cases']['count'] == 70
    assert report['contradiction']['evaluable_cases'] + report['contradiction']['refusal_cases']['count'] == 57
