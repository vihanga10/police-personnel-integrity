from dataclasses import replace, FrozenInstanceError
from datetime import date, datetime, timezone, timedelta
from uuid import UUID
import itertools
import json
import pytest

from app.identity.historical_reconstruction import Claim
from app.identity.bitemporal_reconstruction import EvidenceVersion, RecordingHistory, query

UID = str(UUID(int=1))
T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
T1 = T0 + timedelta(days=1)
T2 = T1 + timedelta(days=1)
ON = date(2024, 12, 31)


def claim(key='rank-row', **changes):
    values = dict(claim_id=key, officer_uid=UID, dimension='rank', value='rank-A',
        source_reference='source-row-version-A', destination_digest='a'*64,
        start=date(2024, 1, 1))
    values.update(changes)
    return Claim(**values)


def version(key='v1', c=None, **changes):
    values = dict(version_id=key, claim=c or claim(), source_key='source-A:row-1',
        recorded_at=T0, receipt_reference='receipt-'+key, receipt_digest='b'*64)
    values.update(changes)
    return EvidenceVersion(**values)


def history(*versions, **changes):
    values = dict(officer_uid=UID, coverage_start=T0, coverage_end=T2,
        coverage_reference='complete-recording-inventory', coverage_digest='c'*64,
        versions=tuple(versions))
    values.update(changes)
    return RecordingHistory(**values)


def rank(result):
    return result.projections[0]


def test_late_arrival_is_invisible_before_receipt_despite_old_effective_date():
    h = history(version(recorded_at=T1))
    before = query(h, effective_on=ON, known_at=T0)
    after = query(h, effective_on=ON, known_at=T1)
    assert not before.visible_versions and rank(before).status == 'CANNOT_VERIFY'
    assert rank(after).candidates[0].value == 'rank-A'


def test_correction_boundary_old_query_preserved_and_inputs_unchanged():
    first = version()
    corrected = version('v2', claim(value='rank-B', destination_digest='d'*64,
        source_reference='source-row-version-B'), recorded_at=T1, supersedes='v1')
    h = history(corrected, first)
    before = query(h, effective_on=ON, known_at=T1-timedelta(microseconds=1))
    after = query(h, effective_on=ON, known_at=T1)
    assert rank(before).candidates == (first.claim,)
    assert rank(after).candidates == (corrected.claim,)
    assert after.visible_versions == (corrected,)
    assert before.query_digest != after.query_digest
    assert h.versions == (corrected, first) and first.claim.value == 'rank-A'
    with pytest.raises(FrozenInstanceError):
        first.recorded_at = T2


def test_corrected_effective_date_recomputes_candidates():
    h = history(version(), version('v2', claim(start=date(2025, 1, 1)),
        recorded_at=T1, supersedes='v1'))
    assert rank(query(h, effective_on=ON, known_at=T0)).candidates
    result = rank(query(h, effective_on=ON, known_at=T1))
    assert not result.candidates and len(result.future) == 1


def test_withdrawal_retains_provenance_and_explicit_reinstatement():
    a = version()
    w = version('v2', a.claim, withdrawn=True, supersedes='v1', recorded_at=T1)
    r = version('v3', a.claim, supersedes='v2', recorded_at=T2)
    h = history(a, w, r)
    middle = query(h, effective_on=ON, known_at=T1)
    assert not rank(middle).candidates and middle.visible_versions == (w,)
    assert rank(query(h, effective_on=ON, known_at=T0)).candidates == (a.claim,)
    assert rank(query(h, effective_on=ON, known_at=T2)).candidates == (a.claim,)


def test_independent_sources_and_same_day_conflicts_are_preserved():
    a = version()
    b = version('other', claim('other-row', value='rank-B'),
        source_key='source-B:row-1', recorded_at=T1)
    for ordering in itertools.permutations([a, b]):
        result = query(history(*ordering), effective_on=ON, known_at=T1)
        assert rank(result).status == 'CONFLICTING_REPORTS'
        assert len(rank(result).candidates) == 2
        assert result.accepted_state is None and not result.receipt_authenticity_claim


def test_future_knowledge_never_changes_past_result_fingerprint():
    a = version()
    b = version('later', claim('later-row', value='rank-B'), recorded_at=T2)
    past = query(history(a), effective_on=ON, known_at=T0)
    extended = query(history(a, b), effective_on=ON, known_at=T0)
    assert past == extended


@pytest.mark.parametrize('known', [T0-timedelta(microseconds=1), T2+timedelta(microseconds=1),
    datetime(2026,10,1), date(2026,10,1), None])
def test_unknown_coverage_and_naive_knowledge_rejected(known):
    with pytest.raises(ValueError):
        query(history(), effective_on=ON, known_at=known)


def test_timezone_equivalence_and_coverage_boundary_inclusion():
    offset = timezone(timedelta(hours=5, minutes=30))
    h = history(version(recorded_at=T0.astimezone(offset)))
    assert query(h, effective_on=ON, known_at=T0) == query(h, effective_on=ON,
        known_at=T0.astimezone(offset))
    assert query(h, effective_on=ON, known_at=T2).visible_versions


@pytest.mark.parametrize('versions', [
    (version(), version()),
    (version(supersedes='missing'),),
    (version(withdrawn=True),),
    (version(), version('v2', recorded_at=T1)),
    (version(), version('v2', recorded_at=T1, supersedes='missing')),
    (version(), version('v2', recorded_at=T1, supersedes='v1'),
        version('v3', recorded_at=T2, supersedes='v1')),
    (version(), version('v2', recorded_at=T0, supersedes='v1')),
    (version(), version('v2', recorded_at=T1, supersedes='v1', source_key='other-source')),
    (version(), version('v2', claim(dimension='posting'), recorded_at=T1, supersedes='v1')),
    (version(), version('v2', claim(value='changed'), recorded_at=T1, supersedes='v1', withdrawn=True)),
    (version(recorded_at=T0-timedelta(seconds=1)),),
    (version(recorded_at=T2+timedelta(seconds=1)),),
    (version(c=claim(officer_uid=str(UUID(int=2)))),),
])
def test_corrupt_chains_and_inventory_are_rejected(versions):
    with pytest.raises(ValueError):
        history(*versions)


@pytest.mark.parametrize('changes', [dict(receipt_reference=''), dict(receipt_digest='x'*64),
    dict(recorded_at=datetime(2026,1,1)), dict(source_key=' '), dict(withdrawn=1),
    dict(version_id=''), dict(claim='untyped')])
def test_version_provenance_required(changes):
    with pytest.raises(ValueError):
        version(**changes)


def test_empty_history_is_unverified_and_snapshots_are_not_backdated():
    empty = query(history(), effective_on=ON, known_at=T0)
    assert all(p.status == 'CANNOT_VERIFY' for p in empty.projections)
    result = query(history(version(c=claim(mode='SNAPSHOT', start=None))),
        effective_on=ON, known_at=T0)
    assert not rank(result).candidates and rank(result).review


def test_effective_future_after_known_time_cannot_establish_future_state():
    result = query(history(version()), effective_on=date(2027,1,1), known_at=T0)
    assert rank(result).status == 'CANNOT_VERIFY'
    assert 'REQUEST_AFTER_CAPTURE_CANNOT_ESTABLISH_FUTURE_STATE' in rank(result).reasons


def test_concurrent_restrictions_and_end_day_semantics_retained():
    a = claim('restriction-A', dimension='restrictions', mode='INTERVAL', end=ON)
    b = claim('restriction-B', dimension='restrictions', mode='INTERVAL', value='restriction-B')
    result = query(history(version(c=a), version('v2', b)), effective_on=ON, known_at=T0)
    restriction = result.projections[-1]
    assert len(restriction.candidates) == 2
    assert 'END_DAY_INCLUSION_IS_CANDIDATE_ONLY' in restriction.reasons
    assert restriction.accepted_state is None


def test_result_repr_does_not_disclose_values_identifiers_or_source_references():
    v = version(c=claim(value='private-value', source_reference='private-source'))
    h = history(v)
    result = query(h, effective_on=ON, known_at=T0)
    for secret in ('private-value', 'private-source', UID, v.receipt_reference, v.source_key):
        assert secret not in repr(v) + repr(h) + repr(result)


def test_bad_effective_date_and_mutable_inventory_rejected():
    with pytest.raises(ValueError):
        query(history(), effective_on=datetime(2024,12,31), known_at=T0)
    with pytest.raises(ValueError):
        history(versions=[])
    with pytest.raises(ValueError):
        history(coverage_end=T0-timedelta(seconds=1))


def number_claim(key, number, kind):
    return claim(key, dimension='police_number',
        value=json.dumps(dict(police_no=number, number_type=kind)))


def number_projection(result):
    return next(p for p in result.projections if p.dimension == 'police_number')


def test_v2_distinct_number_types_do_not_create_a_scalar_conflict():
    a = version(c=number_claim('number-A', 'fixture-1', 'type-A'))
    b = version('other', number_claim('number-B', 'fixture-2', 'type-B'),
        source_key='source-B:row-2')
    result = query(history(a, b), effective_on=ON, known_at=T0)
    p = number_projection(result)
    assert p.status == 'REPORTED_CANDIDATES' and len(p.candidates) == 2
    assert 'POLICE_NUMBER_TYPES_AND_EQUIVALENCE_UNASSESSED' in p.reasons
    assert result.reconstruction_policy == 'REPORTED_HISTORICAL_RECONSTRUCTION_V2'
    assert result.accepted_state is None


def test_v2_number_correction_resolves_same_type_conflict_only_after_receipt():
    a = version(c=number_claim('number-A', 'fixture-1', 'type-A'))
    b = version('other', number_claim('number-B', 'fixture-2', 'type-A'),
        source_key='source-B:row-2')
    fixed = version('corrected', number_claim('number-B', 'fixture-1', 'type-A'),
        source_key=b.source_key, recorded_at=T1, supersedes=b.version_id)
    h = history(a, b, fixed)
    before = query(h, effective_on=ON, known_at=T0)
    after = query(h, effective_on=ON, known_at=T1)
    assert number_projection(before).status == 'CONFLICTING_REPORTS'
    assert number_projection(after).status == 'REPORTED_CANDIDATES'
    assert before == query(history(a, b), effective_on=ON, known_at=T0)


def test_v2_missing_number_type_remains_unverifiable():
    v = version(c=number_claim('number-A', 'fixture-1', ''))
    p = number_projection(query(history(v), effective_on=ON, known_at=T0))
    assert p.status == 'CANNOT_VERIFY'
    assert 'POLICE_NUMBER_TYPE_OR_VALUE_MISSING' in p.reasons


def test_v2_malformed_late_number_is_not_parsed_before_receipt():
    v = version(c=claim('number-A', dimension='police_number', value='private-malformed'),
        recorded_at=T1)
    h = history(v)
    assert number_projection(query(h, effective_on=ON, known_at=T0)).status == 'CANNOT_VERIFY'
    with pytest.raises(ValueError, match='Police number candidate shape differs') as error:
        query(h, effective_on=ON, known_at=T1)
    assert 'private-malformed' not in str(error.value)
