"""Runs the frozen contradiction cases (contradiction_frozen_cases.py, not edited here) and records the results.

Only invented fixtures are used. Results go to tests/contradiction_frozen_results.json for Chapter 5.
"""
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path
from uuid import UUID
import json

from app.identity.historical_reconstruction import Claim
from app.identity.bitemporal_reconstruction import EvidenceVersion, RecordingHistory
from app.identity.bitemporal_contradictions import compare_history
from contradiction_frozen_cases import CASES

UID = str(UUID(int=1))
COVER = (datetime(2026, 10, 1, tzinfo=timezone.utc), datetime(2026, 10, 31, tzinfo=timezone.utc))
RESULTS = Path(__file__).with_name('contradiction_frozen_results.json')


def d(text):
    return None if text is None else date.fromisoformat(text)


def instant(text):
    value = datetime.fromisoformat(text)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def build(claims):
    versions, count = [], Counter()
    for spec in claims:
        cid = spec['id']
        count[cid] += 1
        label = spec.get('src', 'SRC_' + cid)
        provenance = {} if label is None else {'reported_source': label}
        reference = {'provenance': provenance} if spec.get('bad_reference') else {'filename': 'fixture.csv', 'provenance': provenance}
        value = spec['raw'] if 'raw' in spec else json.dumps(spec['value'])
        claim = Claim(claim_id=cid, officer_uid=UID, dimension=spec['dim'], value=value, source_reference=json.dumps(reference),
                      destination_digest='a' * 64, mode=spec.get('mode', 'EVENT'), start=d(spec.get('start')), end=d(spec.get('end')),
                      issues=tuple(spec.get('issues', ())))
        previous = '%s#%d' % (cid, count[cid] - 1) if spec.get('sup') else None
        versions.append(EvidenceVersion(version_id='%s#%d' % (cid, count[cid]), claim=claim, source_key='src:' + cid,
                                        recorded_at=instant(spec.get('rec', '2026-10-02')), receipt_reference='receipt-%s-%d' % (cid, count[cid]),
                                        receipt_digest='b' * 64, supersedes=previous, withdrawn=bool(spec.get('wd'))))
    return RecordingHistory(officer_uid=UID, coverage_start=COVER[0], coverage_end=COVER[1], coverage_reference='frozen-case-coverage',
                            coverage_digest='c' * 64, versions=tuple(versions))


def run_case(case):
    effective, known = case['q']
    try:
        result = compare_history(build(case['claims']), effective_on=d(effective), known_at=instant(known))
    except ValueError:
        return 'REJECT'
    return sorted([list(sorted(c.claim_ids)), c.status] for c in result.comparisons)


def expected(case):
    return case['exp'] if case['exp'] == 'REJECT' else sorted([list(sorted(ids)), status] for ids, status in case['exp'])


def test_frozen_contradiction_cases_and_record_results():
    rows, failures = [], []
    for case in CASES:
        observed, want = run_case(case), expected(case)
        ok = observed == want
        if ok and case.get('digest_stable_against_later'):
            effective, known = case['q']
            early = [c for c in case['claims'] if instant(c.get('rec', '2026-10-02')) <= instant(known)]
            a = compare_history(build(early), effective_on=d(effective), known_at=instant(known)).comparison_digest
            b = compare_history(build(case['claims']), effective_on=d(effective), known_at=instant(known)).comparison_digest
            ok = a == b
        rows.append({'id': case['id'], 'rule': case['rule'], 'expected': want, 'observed': observed, 'passed': ok, 'author_reading': bool(case.get('reading'))})
        if not ok:
            failures.append(case['id'])
    RESULTS.write_text(json.dumps({'total': len(rows), 'passed': len(rows) - len(failures), 'failed': failures, 'cases': rows}, indent=1))
    assert not failures, 'Frozen contradiction cases that differ from the written expectation: ' + ', '.join(failures)
