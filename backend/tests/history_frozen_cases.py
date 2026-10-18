"""FROZEN history-reconstruction test cases (Chapter 5, algorithm 1).

Expected answers were written from the documented rules in
docs/historical-reconstruction-v1.md and docs/bitemporal-reconstruction-v1.md BEFORE the
algorithm was run on these cases. They must not be edited to make a result pass; a failing
case is reported and examined as either a defect or a mistaken expectation (see the
results table). Author: project author with AI drafting help; every expected answer is
subject to the author's review.

Case format
  v:   versions as (version_id, claim_id, dimension, value, mode, start, end, recorded, supersedes, withdrawn)
       dates are 'YYYY-MM-DD'; `recorded` is 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SS[.ffffff]' (UTC)
  q:   (effective_on, known_at)
  exp: {dimension: {'candidates': [...], 'future': [...], 'expired': [...]}} using claim values,
       or {'reject': True} when the history/query must be refused, or {'status': ...}
  rule: the documented sentence the case tests
Coverage window for all cases: 2026-10-01 to 2026-10-31 (UTC).
"""


def V(vid, cid, dim, value, start, rec='2026-10-02', mode='EVENT', end=None, sup=None, wd=False):
    return (vid, cid, dim, value, mode, start, end, rec, sup, wd)


def cand(*c, future=(), expired=()):
    return {'candidates': sorted(c), 'future': sorted(future), 'expired': sorted(expired)}


CASES = [
    # ---- Rank: latest dated reported candidate; predecessors retained; same-day ties retained
    dict(id='R01', rule='latest dated rank event on or before the date', v=[V('v1', 'r1', 'rank', 'A', '2020-01-01')],
         q=('2021-01-01', '2026-10-10'), exp={'rank': cand('A')}),
    dict(id='R02', rule='an event after the query date is not a candidate', v=[V('v1', 'r1', 'rank', 'A', '2020-01-01')],
         q=('2019-01-01', '2026-10-10'), exp={'rank': cand(future=['A'])}),
    dict(id='R03', rule='latest of two dated events', v=[V('v1', 'r1', 'rank', 'A', '2015-01-01'), V('v2', 'r2', 'rank', 'B', '2020-01-01')],
         q=('2021-01-01', '2026-10-10'), exp={'rank': cand('B')}),
    dict(id='R04', rule='an earlier query date selects the earlier event', v=[V('v1', 'r1', 'rank', 'A', '2015-01-01'), V('v2', 'r2', 'rank', 'B', '2020-01-01')],
         q=('2018-01-01', '2026-10-10'), exp={'rank': cand('A', future=['B'])}),
    dict(id='R05', rule='the event day itself counts', v=[V('v1', 'r1', 'rank', 'A', '2015-01-01'), V('v2', 'r2', 'rank', 'B', '2020-01-01')],
         q=('2020-01-01', '2026-10-10'), exp={'rank': cand('B')}),
    dict(id='R06', rule='the day before an event keeps the previous rank', v=[V('v1', 'r1', 'rank', 'A', '2015-01-01'), V('v2', 'r2', 'rank', 'B', '2020-01-01')],
         q=('2019-12-31', '2026-10-10'), exp={'rank': cand('A', future=['B'])}),
    dict(id='R07', rule='same-day ties are all retained', v=[V('v1', 'r1', 'rank', 'B', '2020-01-01'), V('v2', 'r2', 'rank', 'C', '2020-01-01')],
         q=('2021-01-01', '2026-10-10'), exp={'rank': cand('B', 'C')}),
    dict(id='R08', rule='three-step chain, middle selected', v=[V('v1', 'r1', 'rank', 'A', '2010-01-01'), V('v2', 'r2', 'rank', 'B', '2015-01-01'), V('v3', 'r3', 'rank', 'C', '2020-01-01')],
         q=('2017-06-01', '2026-10-10'), exp={'rank': cand('B', future=['C'])}),
    dict(id='R09', rule='a query before every event has no candidate', v=[V('v1', 'r1', 'rank', 'A', '2010-01-01'), V('v2', 'r2', 'rank', 'B', '2015-01-01')],
         q=('2000-01-01', '2026-10-10'), exp={'rank': cand(future=['A', 'B'])}),
    dict(id='R10', rule='no evidence gives no candidate (absence proves nothing)', v=[],
         q=('2021-01-01', '2026-10-10'), exp={'rank': cand()}),
    # ---- Bitemporal: knowledge time
    dict(id='B01', rule='a late arrival is invisible before it is recorded, despite its old effective date',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01', rec='2026-10-20')], q=('2021-01-01', '2026-10-10'), exp={'rank': cand()}),
    dict(id='B02', rule='the same late arrival is visible once recorded', v=[V('v1', 'r1', 'rank', 'A', '2020-01-01', rec='2026-10-20')],
         q=('2021-01-01', '2026-10-20'), exp={'rank': cand('A')}),
    dict(id='B03', rule='a version recorded exactly at known_at is included',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01', rec='2026-10-15T00:00:00')], q=('2021-01-01', '2026-10-15T00:00:00'), exp={'rank': cand('A')}),
    dict(id='B04', rule='one microsecond earlier it is not included',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01', rec='2026-10-15T00:00:00')], q=('2021-01-01', '2026-10-14T23:59:59.999999'), exp={'rank': cand()}),
    dict(id='B05', rule='a correction applies only from its recording time (before)',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r1', 'rank', 'B', '2020-01-01', rec='2026-10-15', sup='v1')],
         q=('2021-01-01', '2026-10-10'), exp={'rank': cand('A')}),
    dict(id='B06', rule='a correction applies from its recording time (at)',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r1', 'rank', 'B', '2020-01-01', rec='2026-10-15', sup='v1')],
         q=('2021-01-01', '2026-10-15'), exp={'rank': cand('B')}),
    dict(id='B07', rule='the corrected value stays after the correction',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r1', 'rank', 'B', '2020-01-01', rec='2026-10-15', sup='v1')],
         q=('2021-01-01', '2026-10-25'), exp={'rank': cand('B')}),
    dict(id='B08', rule='a correction changing the effective date recomputes from the replacement interval (before)',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r1', 'rank', 'A', '2022-01-01', rec='2026-10-15', sup='v1')],
         q=('2021-01-01', '2026-10-10'), exp={'rank': cand('A')}),
    dict(id='B09', rule='a correction changing the effective date recomputes from the replacement interval (after)',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r1', 'rank', 'A', '2022-01-01', rec='2026-10-15', sup='v1')],
         q=('2021-01-01', '2026-10-20'), exp={'rank': cand(future=['A'])}),
    dict(id='B10', rule='an explicit withdrawal removes the candidate (before)',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r1', 'rank', 'A', '2020-01-01', rec='2026-10-15', sup='v1', wd=True)],
         q=('2021-01-01', '2026-10-10'), exp={'rank': cand('A')}),
    dict(id='B11', rule='an explicit withdrawal removes the candidate (after)',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r1', 'rank', 'A', '2020-01-01', rec='2026-10-15', sup='v1', wd=True)],
         q=('2021-01-01', '2026-10-20'), exp={'rank': cand()}),
    dict(id='B12', rule='a later version naming the withdrawn predecessor reinstates',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r1', 'rank', 'A', '2020-01-01', rec='2026-10-15', sup='v1', wd=True),
            V('v3', 'r1', 'rank', 'A', '2020-01-01', rec='2026-10-25', sup='v2')],
         q=('2021-01-01', '2026-10-30'), exp={'rank': cand('A')}),
    dict(id='B13', rule='between withdrawal and reinstatement the candidate stays removed',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r1', 'rank', 'A', '2020-01-01', rec='2026-10-15', sup='v1', wd=True),
            V('v3', 'r1', 'rank', 'A', '2020-01-01', rec='2026-10-25', sup='v2')],
         q=('2021-01-01', '2026-10-20'), exp={'rank': cand()}),
    dict(id='B14', rule='independent source claims are both retained',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r2', 'rank', 'B', '2020-01-01')],
         q=('2021-01-01', '2026-10-10'), exp={'rank': cand('A', 'B')}),
    dict(id='B15', rule='a later arrival does not change an earlier query result',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r2', 'rank', 'B', '2020-01-01', rec='2026-10-25')],
         q=('2021-01-01', '2026-10-10'), exp={'rank': cand('A')}, digest_stable_against_later=True),
    # ---- Intervals (police numbers, restrictions): inclusive bounds
    dict(id='P01', rule='inside the reported interval', v=[V('v1', 'p1', 'police_number', 'N1', '2010-01-01', mode='INTERVAL', end='2015-12-31')],
         q=('2012-06-01', '2026-10-10'), exp={'police_number': cand('N1')}),
    dict(id='P02', rule='the end day is included as a candidate', v=[V('v1', 'p1', 'police_number', 'N1', '2010-01-01', mode='INTERVAL', end='2015-12-31')],
         q=('2015-12-31', '2026-10-10'), exp={'police_number': cand('N1')}),
    dict(id='P03', rule='the day after the end is expired', v=[V('v1', 'p1', 'police_number', 'N1', '2010-01-01', mode='INTERVAL', end='2015-12-31')],
         q=('2016-01-01', '2026-10-10'), exp={'police_number': cand(expired=['N1'])}),
    dict(id='P04', rule='before the start is future', v=[V('v1', 'p1', 'police_number', 'N1', '2010-01-01', mode='INTERVAL', end='2015-12-31')],
         q=('2009-12-31', '2026-10-10'), exp={'police_number': cand(future=['N1'])}),
    dict(id='P05', rule='the start day is included', v=[V('v1', 'p1', 'police_number', 'N1', '2010-01-01', mode='INTERVAL', end='2015-12-31')],
         q=('2010-01-01', '2026-10-10'), exp={'police_number': cand('N1')}),
    dict(id='P06', rule='an open end is a candidate but never proves continuing validity',
         v=[V('v1', 'p1', 'police_number', 'N1', '2010-01-01', mode='INTERVAL')], q=('2020-01-01', '2026-10-10'), exp={'police_number': cand('N1')}),
    dict(id='P07', rule='overlapping numbers are both retained',
         v=[V('v1', 'p1', 'police_number', 'N1', '2010-01-01', mode='INTERVAL', end='2015-12-31'), V('v2', 'p2', 'police_number', 'N2', '2012-01-01', mode='INTERVAL', end='2018-12-31')],
         q=('2013-01-01', '2026-10-10'), exp={'police_number': cand('N1', 'N2')}),
    dict(id='X01', rule='concurrent restrictions are retained as a set',
         v=[V('v1', 'x1', 'restrictions', 'RA', '2010-01-01', mode='INTERVAL', end='2015-12-31'), V('v2', 'x2', 'restrictions', 'RB', '2012-01-01', mode='INTERVAL', end='2018-12-31')],
         q=('2013-01-01', '2026-10-10'), exp={'restrictions': cand('RA', 'RB')}),
    dict(id='X02', rule='no restriction evidence never establishes unrestricted', v=[V('v1', 'r1', 'rank', 'A', '2020-01-01')],
         q=('2021-01-01', '2026-10-10'), exp={'restrictions': cand()}),
    dict(id='X03', rule='an ended restriction is expired, not current',
         v=[V('v1', 'x1', 'restrictions', 'RA', '2010-01-01', mode='INTERVAL', end='2012-12-31')], q=('2015-01-01', '2026-10-10'), exp={'restrictions': cand(expired=['RA'])}),
    # ---- Dimensions are independent
    dict(id='M01', rule='a rank claim never appears under posting',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'g1', 'posting', 'S1', '2020-01-01')],
         q=('2021-01-01', '2026-10-10'), exp={'rank': cand('A'), 'posting': cand('S1')}),
    dict(id='M02', rule='a snapshot is never backdated to an earlier date',
         v=[V('v1', 's1', 'service_status', 'ACTIVE', None, mode='SNAPSHOT')], q=('2015-01-01', '2026-10-10'), exp={'service_status': cand()}),
    # ---- Refusals
    dict(id='J01', rule='a query before coverage starts is rejected', v=[V('v1', 'r1', 'rank', 'A', '2020-01-01')], q=('2021-01-01', '2026-09-30'), exp={'reject': True}),
    dict(id='J02', rule='a query after coverage ends is rejected', v=[V('v1', 'r1', 'rank', 'A', '2020-01-01')], q=('2021-01-01', '2026-11-01'), exp={'reject': True}),
    dict(id='J03', rule='a same-time correction is rejected',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r1', 'rank', 'B', '2020-01-01', sup='v1')], q=('2021-01-01', '2026-10-10'), exp={'reject': True}),
    dict(id='J04', rule='a fork (two corrections of one version) is rejected',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r1', 'rank', 'B', '2020-01-01', rec='2026-10-10', sup='v1'), V('v3', 'r1', 'rank', 'C', '2020-01-01', rec='2026-10-12', sup='v1')],
         q=('2021-01-01', '2026-10-20'), exp={'reject': True}),
    dict(id='J05', rule='a correction with a missing predecessor is rejected',
         v=[V('v2', 'r1', 'rank', 'B', '2020-01-01', rec='2026-10-10', sup='missing')], q=('2021-01-01', '2026-10-20'), exp={'reject': True}),
    dict(id='J06', rule='a correction cannot change the dimension',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r1', 'posting', 'S1', '2020-01-01', rec='2026-10-10', sup='v1')], q=('2021-01-01', '2026-10-20'), exp={'reject': True}),
    dict(id='J07', rule='a repeated version identifier is rejected',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v1', 'r2', 'rank', 'B', '2020-01-01')], q=('2021-01-01', '2026-10-10'), exp={'reject': True}),
    dict(id='J08', rule='a baseline cannot be a withdrawal of an unseen claim',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01', wd=True)], q=('2021-01-01', '2026-10-10'), exp={'reject': True}),
    dict(id='J09', rule='a version outside the coverage window is rejected',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01', rec='2026-11-15')], q=('2021-01-01', '2026-10-10'), exp={'reject': True}),
    dict(id='J10', rule='a withdrawal must keep its predecessor claim unchanged',
         v=[V('v1', 'r1', 'rank', 'A', '2020-01-01'), V('v2', 'r1', 'rank', 'B', '2020-01-01', rec='2026-10-15', sup='v1', wd=True)], q=('2021-01-01', '2026-10-20'), exp={'reject': True}),
]
