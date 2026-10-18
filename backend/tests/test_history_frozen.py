"""Runs the frozen history cases and an independent simple re-implementation on random histories.

The frozen cases live in history_frozen_cases.py and are not edited here. Results are written to
tests/history_frozen_results.json so Chapter 5 can quote them, failures included.
"""
from datetime import date, datetime, timezone, timedelta
import json
import os
import random
from pathlib import Path
from uuid import UUID
import pytest

from app.identity.historical_reconstruction import Claim
from app.identity.bitemporal_reconstruction import EvidenceVersion, RecordingHistory, query
from history_frozen_cases import CASES

UID = str(UUID(int=1))
COVER = (datetime(2026, 10, 1, tzinfo=timezone.utc), datetime(2026, 10, 31, tzinfo=timezone.utc))
RESULTS = Path(__file__).with_name('history_frozen_results.json')


def d(text):
    return None if text is None else date.fromisoformat(text)


def instant(text):
    value = datetime.fromisoformat(text)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def build(versions):
    out = []
    for vid, cid, dim, value, mode, start, end, rec, sup, wd in versions:
        # Builder fixes after the first run (expectations untouched): police numbers use the typed JSON value the
        # algorithm requires, and every version of one claim shares one source reference so a withdrawal can equal its predecessor.
        encoded = json.dumps(dict(police_no=value, number_type='police')) if dim == 'police_number' else value
        claim = Claim(claim_id=cid, officer_uid=UID, dimension=dim, value=encoded, source_reference='ref-' + cid,
                      destination_digest='a' * 64, mode=mode, start=d(start), end=d(end))
        out.append(EvidenceVersion(version_id=vid, claim=claim, source_key='src:' + cid, recorded_at=instant(rec),
                                   receipt_reference='receipt-' + vid, receipt_digest='b' * 64, supersedes=sup, withdrawn=wd))
    return RecordingHistory(officer_uid=UID, coverage_start=COVER[0], coverage_end=COVER[1], coverage_reference='frozen-case-coverage',
                            coverage_digest='c' * 64, versions=tuple(out))


def observed(result, dimension):
    p = next(p for p in result.projections if p.dimension == dimension)
    label = (lambda c: json.loads(c.value)['police_no']) if dimension == 'police_number' else (lambda c: c.value)
    return {'candidates': sorted(label(c) for c in p.candidates), 'future': sorted(label(c) for c in p.future),
            'expired': sorted(label(c) for c in p.expired)}


def run_case(case):
    effective, known = case['q']
    try:
        history = build(case['v'])
        result = query(history, effective_on=d(effective), known_at=instant(known))
    except ValueError:
        return {'reject': True}
    return {dim: observed(result, dim) for dim in case['exp'] if dim != 'reject' and dim != 'status'}


def test_frozen_cases_and_record_results():
    rows, failures = [], []
    for case in CASES:
        got = run_case(case)
        want = case['exp']
        ok = got == want if 'reject' in want else got == {k: v for k, v in want.items()}
        if ok and case.get('digest_stable_against_later'):
            effective, known = case['q']
            early = [v for v in case['v'] if instant(v[7]) <= instant(known)]
            a = query(build(early), effective_on=d(effective), known_at=instant(known)).query_digest
            b = query(build(case['v']), effective_on=d(effective), known_at=instant(known)).query_digest
            ok = a == b
        rows.append({'id': case['id'], 'rule': case['rule'], 'expected': want, 'observed': got, 'passed': ok})
        if not ok:
            failures.append(case['id'])
    RESULTS.write_text(json.dumps({'total': len(rows), 'passed': len(rows) - len(failures), 'failed': failures, 'cases': rows}, indent=1))
    assert not failures, 'Frozen cases that differ from the written expectation: ' + ', '.join(failures)


# ---- Independent simple oracle: a deliberately plain re-statement of the documented rules.
def oracle(versions, effective, known):
    heads = {}
    for v in sorted(versions, key=lambda v: (instant(v[7]), v[0])):
        if instant(v[7]) <= instant(known):
            heads[v[1]] = v
    live = [v for v in heads.values() if not v[9]]
    out = {}
    for dim in ('rank', 'police_number', 'restrictions'):
        c, f, e = [], [], []
        mine = [v for v in live if v[2] == dim]
        if dim == 'rank':
            dated = [v for v in mine if d(v[5]) <= d(effective)]
            top = max((d(v[5]) for v in dated), default=None)
            c = [v[3] for v in dated if d(v[5]) == top]
            f = [v[3] for v in mine if d(v[5]) > d(effective)]
        else:
            for v in mine:
                if d(v[5]) > d(effective):
                    f.append(v[3])
                elif v[6] is not None and d(v[6]) < d(effective):
                    e.append(v[3])
                else:
                    c.append(v[3])
        out[dim] = {'candidates': sorted(c), 'future': sorted(f), 'expired': sorted(e)}
    return out


def random_history(rng):
    versions, serial = [], 0
    for cid_index in range(rng.randint(0, 5)):
        dim = rng.choice(['rank', 'police_number', 'restrictions'])
        mode = 'EVENT' if dim == 'rank' else 'INTERVAL'
        start = date(2005, 1, 1) + timedelta(days=rng.randint(0, 6000))
        end = None if mode == 'EVENT' or rng.random() < 0.3 else start + timedelta(days=rng.randint(0, 3000))
        rec = datetime(2026, 10, 2, tzinfo=timezone.utc) + timedelta(days=rng.randint(0, 25), hours=rng.randint(0, 23))
        cid = 'c%d' % cid_index
        serial += 1
        prev = ('v%d' % serial, cid, dim, 'val%d' % serial, mode, start.isoformat(), end.isoformat() if end else None, rec.isoformat(), None, False)
        versions.append(prev)
        for _ in range(rng.randint(0, 2)):
            serial += 1
            rec = rec + timedelta(hours=rng.randint(1, 100))
            if rec > COVER[1]:
                break
            withdraw = rng.random() < 0.25
            new_start = prev[5] if withdraw else (date(2005, 1, 1) + timedelta(days=rng.randint(0, 6000))).isoformat()
            new_end = prev[6] if withdraw or mode == 'EVENT' else (date.fromisoformat(new_start) + timedelta(days=rng.randint(0, 3000))).isoformat()
            new = ('v%d' % serial, cid, dim, prev[3] if withdraw else 'val%d' % serial, mode, new_start, new_end, rec.isoformat(), prev[0], withdraw)
            versions.append(new)
            prev = new
            if withdraw:
                break
    return versions


def test_random_histories_agree_with_the_independent_oracle():
    rng = random.Random(20261018)
    disagreements = []
    runs = int(os.environ.get('HISTORY_RANDOM_RUNS', '3000'))
    for n in range(runs):
        versions = random_history(rng)
        # Half the queries sit exactly on, or one day either side of, a recorded start/end so boundary rules are exercised.
        edges = [x for v in versions for x in (v[5], v[6]) if x]
        if edges and rng.random() < 0.5:
            effective = (date.fromisoformat(rng.choice(edges)) + timedelta(days=rng.choice([-1, 0, 1]))).isoformat()
        else:
            effective = (date(2004, 1, 1) + timedelta(days=rng.randint(0, 8000))).isoformat()
        known = (datetime(2026, 10, 1, tzinfo=timezone.utc) + timedelta(hours=rng.randint(0, 720))).isoformat()
        try:
            result = query(build(versions), effective_on=d(effective), known_at=instant(known))
        except ValueError as error:
            disagreements.append((n, 'unexpected refusal', str(error)))
            continue
        want = oracle(versions, effective, known)
        got = {dim: observed(result, dim) for dim in want}
        if got != want:
            disagreements.append((n, versions, effective, known, got, want))
    assert not disagreements, '%d of %d random histories disagree; first: %r' % (len(disagreements), runs, disagreements[0])
