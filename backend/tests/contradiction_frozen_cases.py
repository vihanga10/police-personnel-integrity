"""FROZEN contradiction-detection test cases (Chapter 5, algorithm 3).

Expected answers were written from docs/bitemporal-contradiction-evaluation-v2.md BEFORE the
comparison function was run on these cases. They must not be edited to make a result pass; a failing case
is reported and examined as a defect or a mistaken expectation. Cases are separate from the 20 toy
cases in contradiction_benchmark_cases.py. All values are invented fixtures.

Documented outcomes used
  CAND  REPORTED_CONTRADICTION_CANDIDATE  differing exact comparable fields for the same reported event date, or
        overlapping intervals at the requested day (same exact namespace).
  AGREE REPORTED_AGREEMENT                exact fields agree and temporal applicability permits the comparison.
  NONE  NO_REPORTED_CONFLICT_AT_POINT     distinct event dates; differing exact number types; distinct restriction ids.
  UNRES UNRESOLVED_COMPARISON             uncertain dates/modes/fields, end-day ambiguity, blank values, unapproved
        posting / service-status semantics, whitespace- or case-only differences, request after the knowledge date.
  Only the latest head of each claim known at known_at takes part; withdrawn claims, and interval or event claims that
  are future or expired at the effective date, are excluded; every pair of remaining same-dimension claims is compared.
  An empty list means no comparison is emitted.

Case format
  id, rule, claims (list of claim dicts), q = (effective_on, known_at), exp = list of (claim-id pair, status) or 'REJECT'.
  Claim dict keys: id, dim ('rank'|'police_number'|'restrictions'|'posting'|'service_status'), plus
    value (dict of reported fields), mode, start, end, src (label or None), rec (recorded date/time),
    sup (version id superseded), wd (withdrawal), issues, raw (raw value text for malformed-input cases).
  `reading=True` marks answers that rest on the author's reading where the document is less explicit.
Coverage window for all cases: 2026-10-01 to 2026-10-31 (UTC).
"""

CAND, AGREE, NONE, UNRES = ('REPORTED_CONTRADICTION_CANDIDATE', 'REPORTED_AGREEMENT', 'NO_REPORTED_CONFLICT_AT_POINT', 'UNRESOLVED_COMPARISON')
Q = ('2024-06-01', '2026-10-10')


def R(cid, rank, start='2024-01-01', **kw):
    return dict(id=cid, dim='rank', value={'to_rank': rank}, mode='EVENT', start=start, **kw)


def N(cid, number, kind='police', start='2024-01-01', end=None, **kw):
    return dict(id=cid, dim='police_number', value={'police_no': number, 'number_type': kind}, mode='INTERVAL', start=start, end=end, **kw)


def X(cid, rid, effect='prohibited', start='2024-01-01', end=None, **kw):
    return dict(id=cid, dim='restrictions', value={'restriction_id': rid, 'restriction_category': 'integrity', 'restriction_effect': effect,
                                                  'restriction_scope': 'station'}, mode='INTERVAL', start=start, end=end, **kw)


CASES = [
    # ---------------- Rank events (exact to_rank, same reported event date)
    dict(id='K01', rule='same event date, different ranks, different sources: a contradiction candidate', claims=[R('a', 'Inspector', src='HR'), R('b', 'Chief Inspector', src='PF')], q=Q, exp=[(('a', 'b'), CAND)]),
    dict(id='K02', rule='same event date, same rank: agreement', claims=[R('a', 'Inspector', src='HR'), R('b', 'Inspector', src='PF')], q=Q, exp=[(('a', 'b'), AGREE)]),
    dict(id='K03', rule='distinct event dates are not a same-event contradiction', claims=[R('a', 'Inspector', '2020-01-01'), R('b', 'Chief Inspector', '2022-01-01')], q=Q, exp=[(('a', 'b'), NONE)]),
    dict(id='K04', rule='distinct event dates with equal ranks are still not a contradiction', claims=[R('a', 'Inspector', '2020-01-01'), R('b', 'Inspector', '2022-01-01')], q=Q, exp=[(('a', 'b'), NONE)]),
    dict(id='K05', rule='a case-only difference is unresolved, never a candidate or agreement', claims=[R('a', 'Inspector'), R('b', 'inspector')], q=Q, exp=[(('a', 'b'), UNRES)]),
    dict(id='K06', rule='a whitespace-only difference is unresolved', claims=[R('a', 'Inspector'), R('b', 'Inspector ')], q=Q, exp=[(('a', 'b'), UNRES)]),
    dict(id='K07', rule='a blank value is unresolved', claims=[R('a', 'Inspector'), R('b', '')], q=Q, exp=[(('a', 'b'), UNRES)]),
    dict(id='K08', rule='three claims give three pairs: differing pairs are candidates, equal pair agrees',
         claims=[R('a', 'Inspector'), R('b', 'Chief Inspector'), R('c', 'Inspector')], q=Q, exp=[(('a', 'b'), CAND), (('a', 'c'), AGREE), (('b', 'c'), CAND)]),
    dict(id='K09', rule='a claim with no event date is unresolved', claims=[R('a', 'Inspector'), R('b', 'Chief Inspector', start=None)], q=Q, exp=[(('a', 'b'), UNRES)]),
    dict(id='K10', rule='a missing source label does not stop a candidate being found', claims=[R('a', 'Inspector', src=None), R('b', 'Chief Inspector', src='PF')], q=Q, exp=[(('a', 'b'), CAND)]),
    dict(id='K11', rule='two differing claims carrying the same source label are still a candidate', claims=[R('a', 'Inspector', src='PF'), R('b', 'Chief Inspector', src='PF')], q=Q, exp=[(('a', 'b'), CAND)]),
    dict(id='K12', rule='an event dated after the effective date is excluded, so nothing is compared', claims=[R('a', 'Inspector'), R('b', 'Chief Inspector', '2025-01-01')], q=Q, exp=[]),
    dict(id='K13', rule='a single claim yields no comparison', claims=[R('a', 'Inspector')], q=Q, exp=[]),
    dict(id='K14', rule='four mutually different claims give six candidate pairs',
         claims=[R('a', 'A1'), R('b', 'B1'), R('c', 'C1'), R('d', 'D1')], q=Q,
         exp=[(p, CAND) for p in (('a', 'b'), ('a', 'c'), ('a', 'd'), ('b', 'c'), ('b', 'd'), ('c', 'd'))]),
    dict(id='K15', rule='review-mode evidence stays unresolved', claims=[R('a', 'Inspector'), dict(R('b', 'Chief Inspector'), mode='REVIEW')], q=Q, exp=[(('a', 'b'), UNRES)]),
    dict(id='K16', rule='snapshot evidence stays unresolved', claims=[R('a', 'Inspector'), dict(R('b', 'Chief Inspector'), mode='SNAPSHOT', start=None)], q=Q, exp=[(('a', 'b'), UNRES)]),
    dict(id='K17', rule='issue-bearing evidence stays unresolved', claims=[R('a', 'Inspector'), dict(R('b', 'Chief Inspector'), issues=('DATE_UNCLEAR',))], q=Q, exp=[(('a', 'b'), UNRES)]),
    dict(id='K18', rule='a request after the knowledge date cannot establish a future state', claims=[R('a', 'Inspector'), R('b', 'Chief Inspector')], q=('2027-06-01', '2026-10-10'),
         exp=[(('a', 'b'), UNRES)], reading=True),
    # ---------------- Knowledge time
    dict(id='T01', rule='a claim recorded after known_at is invisible, so nothing is compared',
         claims=[R('a', 'Inspector'), R('b', 'Chief Inspector', rec='2026-10-20')], q=('2024-06-01', '2026-10-10'), exp=[]),
    dict(id='T02', rule='once recorded the same late claim creates the candidate',
         claims=[R('a', 'Inspector'), R('b', 'Chief Inspector', rec='2026-10-20')], q=('2024-06-01', '2026-10-20'), exp=[(('a', 'b'), CAND)]),
    dict(id='T03', rule='before a correction the disagreement stands',
         claims=[R('a', 'Inspector'), R('b', 'Chief Inspector'), dict(R('b', 'Inspector'), rec='2026-10-15', sup='b')], q=('2024-06-01', '2026-10-10'), exp=[(('a', 'b'), CAND)]),
    dict(id='T04', rule='after the correction the corrected head agrees',
         claims=[R('a', 'Inspector'), R('b', 'Chief Inspector'), dict(R('b', 'Inspector'), rec='2026-10-15', sup='b')], q=('2024-06-01', '2026-10-20'), exp=[(('a', 'b'), AGREE)]),
    dict(id='T05', rule='before a withdrawal the disagreement stands',
         claims=[R('a', 'Inspector'), R('b', 'Chief Inspector'), dict(R('b', 'Chief Inspector'), rec='2026-10-15', sup='b', wd=True)], q=('2024-06-01', '2026-10-10'), exp=[(('a', 'b'), CAND)]),
    dict(id='T06', rule='after a withdrawal the withdrawn claim no longer takes part',
         claims=[R('a', 'Inspector'), R('b', 'Chief Inspector'), dict(R('b', 'Chief Inspector'), rec='2026-10-15', sup='b', wd=True)], q=('2024-06-01', '2026-10-20'), exp=[]),
    dict(id='T07', rule='a correction that moves one claim to another date turns the pair into no-conflict',
         claims=[R('a', 'Inspector', '2024-01-01'), R('b', 'Chief Inspector', '2024-01-01'), dict(R('b', 'Chief Inspector', '2025-01-01'), rec='2026-10-15', sup='b')],
         q=('2026-06-01', '2026-10-20'), exp=[(('a', 'b'), NONE)]),
    dict(id='T08', rule='a claim recorded exactly at known_at takes part',
         claims=[R('a', 'Inspector'), R('b', 'Chief Inspector', rec='2026-10-15T00:00:00')], q=('2024-06-01', '2026-10-15T00:00:00'), exp=[(('a', 'b'), CAND)]),
    dict(id='T09', rule='one microsecond earlier it does not',
         claims=[R('a', 'Inspector'), R('b', 'Chief Inspector', rec='2026-10-15T00:00:00')], q=('2024-06-01', '2026-10-14T23:59:59.999999'), exp=[]),
    dict(id='T10', rule='a later arrival does not change an earlier comparison digest',
         claims=[R('a', 'Inspector'), R('b', 'Chief Inspector'), R('c', 'Staff Officer', rec='2026-10-25')], q=('2024-06-01', '2026-10-10'), exp=[(('a', 'b'), CAND)], digest_stable_against_later=True),
    # ---------------- Police numbers (intervals, exact type namespaces)
    dict(id='N01', rule='same type, different numbers, overlapping at the date: candidate', claims=[N('a', '100'), N('b', '200')], q=Q, exp=[(('a', 'b'), CAND)]),
    dict(id='N02', rule='same type, same number, overlapping: agreement', claims=[N('a', '100'), N('b', '100')], q=Q, exp=[(('a', 'b'), AGREE)]),
    dict(id='N03', rule='different types may coexist: no conflict', claims=[N('a', '100', 'police'), N('b', '200', 'warrant')], q=Q, exp=[(('a', 'b'), NONE)]),
    dict(id='N04', rule='different types with the same number are still no conflict', claims=[N('a', '100', 'police'), N('b', '100', 'warrant')], q=Q, exp=[(('a', 'b'), NONE)]),
    dict(id='N05', rule='an interval that ended before the effective date is excluded', claims=[N('a', '100', end='2024-01-31'), N('b', '200')], q=Q, exp=[]),
    dict(id='N06', rule='an interval starting after the effective date is excluded', claims=[N('a', '100'), N('b', '200', start='2025-01-01')], q=Q, exp=[]),
    dict(id='N07', rule='a shared end day carries end-day ambiguity: unresolved', claims=[N('a', '100', end='2024-06-01'), N('b', '200')], q=Q, exp=[(('a', 'b'), UNRES)], reading=True),
    dict(id='N08', rule='two open-ended intervals overlapping at the date remain a candidate (with stated uncertainty)', claims=[N('a', '100'), N('b', '200')], q=('2025-06-01', '2026-10-10'), exp=[(('a', 'b'), CAND)], reading=True),
    dict(id='N09', rule='a blank number type is unresolved', claims=[N('a', '100', 'police'), N('b', '200', '')], q=Q, exp=[(('a', 'b'), UNRES)]),
    dict(id='N10', rule='number types differing only by case are unresolved', claims=[N('a', '100', 'police'), N('b', '200', 'Police')], q=Q, exp=[(('a', 'b'), UNRES)], reading=True),
    dict(id='N11', rule='three same-type overlapping numbers give three candidate pairs', claims=[N('a', '1'), N('b', '2'), N('c', '3')], q=Q, exp=[(('a', 'b'), CAND), (('a', 'c'), CAND), (('b', 'c'), CAND)]),
    dict(id='N12', rule='namespaces are kept apart inside one set', claims=[N('a', '1', 'police'), N('b', '2', 'police'), N('c', '3', 'warrant')], q=Q,
         exp=[(('a', 'b'), CAND), (('a', 'c'), NONE), (('b', 'c'), NONE)]),
    # ---------------- Restrictions (four exact fields)
    dict(id='X01', rule='distinct restriction ids coexist: no conflict', claims=[X('a', 'RS/1'), X('b', 'RS/2')], q=Q, exp=[(('a', 'b'), NONE)]),
    dict(id='X02', rule='the same restriction reported identically agrees', claims=[X('a', 'RS/1'), X('b', 'RS/1')], q=Q, exp=[(('a', 'b'), AGREE)]),
    dict(id='X03', rule='the same restriction id with a different effect is a candidate', claims=[X('a', 'RS/1', 'prohibited'), X('b', 'RS/1', 'permitted')], q=Q, exp=[(('a', 'b'), CAND)]),
    dict(id='X04', rule='a whitespace-only difference in a restriction is unresolved', claims=[X('a', 'RS/1'), X('b', 'RS/1 ')], q=Q, exp=[(('a', 'b'), UNRES)]),
    dict(id='X05', rule='an ended restriction is excluded at the effective date', claims=[X('a', 'RS/1', end='2024-01-31'), X('b', 'RS/2')], q=Q, exp=[]),
    dict(id='X06', rule='three distinct restrictions give three no-conflict pairs', claims=[X('a', 'RS/1'), X('b', 'RS/2'), X('c', 'RS/3')], q=Q, exp=[(('a', 'b'), NONE), (('a', 'c'), NONE), (('b', 'c'), NONE)]),
    # ---------------- Dimensions without approved semantics, and separation
    dict(id='S01', rule='posting disagreement is unresolved (posting semantics unapproved)',
         claims=[dict(id='a', dim='posting', value={'unit': 'U1'}, mode='EVENT', start='2024-01-01'), dict(id='b', dim='posting', value={'unit': 'U2'}, mode='EVENT', start='2024-01-01')],
         q=Q, exp=[(('a', 'b'), UNRES)]),
    dict(id='S02', rule='even identical posting reports stay unresolved', reading=True,
         claims=[dict(id='a', dim='posting', value={'unit': 'U1'}, mode='EVENT', start='2024-01-01'), dict(id='b', dim='posting', value={'unit': 'U1'}, mode='EVENT', start='2024-01-01')],
         q=Q, exp=[(('a', 'b'), UNRES)]),
    dict(id='S03', rule='service status disagreement is unresolved (semantics unapproved)',
         claims=[dict(id='a', dim='service_status', value={'status': 'ACTIVE'}, mode='EVENT', start='2024-01-01'), dict(id='b', dim='service_status', value={'status': 'RETIRED'}, mode='EVENT', start='2024-01-01')],
         q=Q, exp=[(('a', 'b'), UNRES)]),
    dict(id='M01', rule='claims of different dimensions are never compared with each other',
         claims=[R('a', 'Inspector'), dict(id='b', dim='posting', value={'unit': 'U1'}, mode='EVENT', start='2024-01-01')], q=Q, exp=[]),
    dict(id='M02', rule='each dimension is compared inside its own group',
         claims=[R('a', 'Inspector'), R('b', 'Chief Inspector'), N('c', '1'), N('d', '2')], q=Q, exp=[(('a', 'b'), CAND), (('c', 'd'), CAND)]),
    # ---------------- Malformed input is refused, never guessed
    dict(id='J01', rule='a knowledge time outside coverage is refused', claims=[R('a', 'Inspector'), R('b', 'Chief Inspector')], q=('2024-06-01', '2026-11-05'), exp='REJECT'),
    dict(id='J02', rule='claim evidence that is not a JSON object is refused', claims=[R('a', 'Inspector'), dict(R('b', 'x'), raw='["not","an","object"]')], q=Q, exp='REJECT'),
    dict(id='J03', rule='a repeated field name in the evidence is refused', claims=[R('a', 'Inspector'), dict(R('b', 'x'), raw='{"to_rank":"A","to_rank":"B"}')], q=Q, exp='REJECT'),
    dict(id='J04', rule='a non-text field value is refused', claims=[R('a', 'Inspector'), dict(R('b', 'x'), raw='{"to_rank":5}')], q=Q, exp='REJECT'),
    dict(id='J05', rule='a source reference without a filename is refused', claims=[R('a', 'Inspector'), dict(R('b', 'Chief Inspector'), bad_reference=True)], q=Q, exp='REJECT'),
    dict(id='J06', rule='a correction may not change the dimension', claims=[R('a', 'Inspector'), dict(id='a', dim='posting', value={'unit': 'U1'}, mode='EVENT', start='2024-01-01', rec='2026-10-15', sup='a')], q=Q, exp='REJECT'),
]
