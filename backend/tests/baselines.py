"""The three deliberately simple comparison procedures named in Chapter 3 (Section 3.3 / 3.9.2).

Defined and committed BEFORE they were run on the frozen case sets. They are transparent simplifications, not claims about
commercial products, and each one removes exactly the evidence conditions the integrated procedure adds:

  current_only_history   ignores the effective date, the knowledge time and coverage; returns what is current today.
  rank_only_authority    decides from the actor's rank alone: ignores dates, role, scope, service status, delegation,
                         assessment state and coverage; never answers CANNOT_VERIFY.
  value_only_contradictions  flags two claims of one dimension as a candidate when their values differ and as agreement when
                         they match; ignores knowledge time, effective dates, number types / restriction ids, uncertainty and
                         withdrawal-free eligibility; never answers NO_REPORTED_CONFLICT_AT_POINT or UNRESOLVED_COMPARISON.

None of them validates input, so they never refuse; cases that test refusal are reported separately.
"""
import json
from itertools import combinations

CAND, AGREE = 'REPORTED_CONTRADICTION_CANDIDATE', 'REPORTED_AGREEMENT'


def heads(versions):
    """Latest version of every claim (by recording time, then identifier); withdrawn claims dropped. Time of the query is ignored."""
    latest = {}
    for v in sorted(versions, key=lambda v: (v[7], v[0])):
        latest[v[1]] = v
    return [v for v in latest.values() if not v[9]]


def current_only_history(versions, wanted):
    """versions: (vid, claim, dimension, value, mode, start, end, recorded, supersedes, withdrawn). Returns {dimension: answer}."""
    result = {}
    for dimension in wanted:
        mine = [v for v in heads(versions) if v[2] == dimension]
        if dimension == 'rank' and mine:
            top = max((v[5] or '') for v in mine)
            mine = [v for v in mine if (v[5] or '') == top]
        result[dimension] = {'candidates': sorted(v[3] for v in mine), 'future': [], 'expired': []}
    return result


def rank_only_authority(action, states, rules, delegations, coverage):
    allowed = {rank for rule in rules for rank in rule.ranks}
    own = [s for s in states if s.actor_uid == action.actor_uid]
    if not own or not allowed:
        return 'INVALID'
    return 'VALID' if own[0].rank.value in allowed else 'INVALID'


def value_of(spec):
    if 'raw' in spec:
        return spec['raw']
    return json.dumps(spec['value'], sort_keys=True)


def value_only_contradictions(claims):
    """claims: contradiction-case claim dicts. Returns [[pair], status] sorted, comparing the latest non-withdrawn claim of each id."""
    latest = {}
    for number, spec in enumerate(claims):
        if spec.get('wd'):
            latest.pop(spec['id'], None)
        else:
            latest[spec['id']] = (number, spec)
    by_dimension = {}
    for _, spec in latest.values():
        by_dimension.setdefault(spec['dim'], []).append(spec)
    out = []
    for group in by_dimension.values():
        for a, b in combinations(sorted(group, key=lambda s: s['id']), 2):
            out.append([sorted([a['id'], b['id']]), CAND if value_of(a) != value_of(b) else AGREE])
    return sorted(out)


def wilson(successes, total, z=1.96):
    """Wilson score interval for a proportion; (None, None) when there are no cases."""
    if total == 0:
        return None, None
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * ((p * (1 - p) / total + z * z / (4 * total * total)) ** 0.5) / denominator
    return round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4)


def prf(tp, fp, fn):
    """Precision, recall and F1; undefined ratios are None, never 0 or 1."""
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    # F1 = 2TP / (2TP + FP + FN): zero when a class is missed but never predicted, undefined only when the class never occurs at all.
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {'tp': tp, 'fp': fp, 'fn': fn, 'precision': precision, 'recall': recall, 'f1': f1}


def confusion(pairs, labels=('VALID', 'INVALID', 'CANNOT_VERIFY')):
    """pairs: (expected, observed). Returns matrix[expected][observed] counts and macro F1 over the labels."""
    matrix = {e: {o: 0 for o in labels} for e in labels}
    for expected, observed in pairs:
        if expected in matrix and observed in matrix[expected]:
            matrix[expected][observed] += 1
    scores = []
    for label in labels:
        tp = matrix[label][label]
        fp = sum(matrix[e][label] for e in labels if e != label)
        fn = sum(matrix[label][o] for o in labels if o != label)
        scores.append(prf(tp, fp, fn)['f1'])
    defined = [s for s in scores if s is not None]
    return matrix, {'per_class_f1': dict(zip(labels, scores)), 'macro_f1': sum(defined) / len(defined) if defined else None,
                    'classes_with_undefined_f1': [l for l, s in zip(labels, scores) if s is None]}
