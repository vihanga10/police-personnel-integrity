"""Made-up police-number claims only; no personnel, network or database access."""
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import date
import itertools
import json
import pytest
from test_historical_reconstruction import claim, result, OFFICER, ON, CAPTURE
from test_historical_explanation import archive, replay, SHA
from test_protected_commitment import identity_crypto
from app.identity.historical_reconstruction import reconstruct, POLICY, LEGACY_POLICY
from app.identity.historical_explanation import explain
from app.identity.historical_result_review import json_value
from app.identity.historical_source_claims import source_claims, HEADERS
from app.identity.evidence_bundle_v2 import seal_artifact
from app.identity.review_history_explanations import saved_payloads, PUBLIC_SHA


def number(identifier='a', kind='fixture-type-A', value='fixture-number-A', **kwargs):
    fields = dict(dimension='police_number', mode='INTERVAL',
        value=json.dumps(dict(police_no=value, number_type=kind)))
    fields.update(kwargs)
    return claim(identifier, **fields)


def projection(claims, **kwargs):
    return result(claims, 'police_number', **kwargs)


def test_different_types_no_longer_imply_conflict_and_preserve_all_evidence():
    a, b = number(), number('b', kind='fixture-type-B', value='fixture-number-B')
    for ordered in itertools.permutations((a, b)):
        p = projection(ordered)
        assert p.status == 'REPORTED_CANDIDATES' and p.candidates == (a, b)
        assert p.accepted_state is None
        assert 'POLICE_NUMBER_TYPES_AND_EQUIVALENCE_UNASSESSED' in p.reasons
        assert 'COMPETING_REPORTED_VALUES_WITHOUT_ACCEPTED_PRECEDENCE' not in p.reasons
        assert projection(ordered, policy=LEGACY_POLICY).status == 'CONFLICTING_REPORTS'


def test_same_type_overlapping_numbers_remain_conflicting():
    p = projection([number(), number('b', value='fixture-number-B')])
    assert p.status == 'CONFLICTING_REPORTS' and len(p.candidates) == 2
    assert 'COMPETING_REPORTED_VALUES_WITHOUT_ACCEPTED_PRECEDENCE' in p.reasons


def test_same_type_same_number_preserves_both_sources():
    p = projection([number(), number('b')])
    assert p.status == 'REPORTED_CANDIDATES' and len(p.candidates) == 2
    assert 'SOURCE_INDEPENDENCE_UNVERIFIED' in p.reasons


@pytest.mark.parametrize('kind,value', [('', 'X'), ('  ', 'X'), ('A', ''), ('A', '  ')])
def test_incomplete_candidate_cannot_become_unique_state(kind, value):
    p = projection([number(kind=kind, value=value)])
    assert p.status == 'CANNOT_VERIFY' and len(p.candidates) == 1
    assert 'POLICE_NUMBER_TYPE_OR_VALUE_MISSING' in p.reasons


def test_known_type_conflict_is_retained_alongside_unknown_type():
    p = projection([number(), number('b', value='B'), number('c', kind='')])
    assert p.status == 'CONFLICTING_REPORTS'
    assert 'POLICE_NUMBER_TYPE_OR_VALUE_MISSING' in p.reasons


@pytest.mark.parametrize('kind', ['fixture-type-a', ' fixture-type-A', 'fixture-type-A '])
def test_type_aliases_are_not_silently_normalized(kind):
    p = projection([number(), number('b', kind=kind, value='B')])
    assert p.status == 'REPORTED_CANDIDATES'
    assert 'POLICE_NUMBER_TYPES_AND_EQUIVALENCE_UNASSESSED' in p.reasons


def test_number_whitespace_is_preserved_as_distinct_report():
    assert projection([number(), number('b', value='fixture-number-A ')]).status == 'CONFLICTING_REPORTS'


def test_snapshot_still_blocks_answer_even_when_types_do_not_conflict():
    p = projection([number(), number('b', kind='B'), number('c', mode='SNAPSHOT')])
    assert p.status == 'CANNOT_VERIFY' and len(p.review) == 1


def test_expired_and_future_intervals_do_not_create_active_conflicts():
    p = projection([number(), number('b', value='B', end=date(2020,1,9)),
        number('c', value='C', start=date(2020,1,11))])
    assert p.status == 'REPORTED_CANDIDATES' and len(p.expired) == len(p.future) == 1


def test_closed_end_day_remains_candidate_convention_and_can_conflict():
    p = projection([number(end=ON), number('b', value='B', start=ON)])
    assert p.status == 'CONFLICTING_REPORTS'
    assert 'END_DAY_INCLUSION_IS_CANDIDATE_ONLY' in p.reasons


def test_future_query_still_cannot_establish_state():
    p = next(p for p in reconstruct(OFFICER, [number()], on=date(2027,1,1), captured_at=CAPTURE)
        if p.dimension == 'police_number')
    assert p.status == 'CANNOT_VERIFY'


@pytest.mark.parametrize('value', ['not-json', '[]', 'null', '{"police_no":1,"number_type":"A"}',
    '{"police_no":"A"}', '{"police_no":"A","number_type":"B","extra":"secret"}',
    '{"police_no":"A","number_type":"B","number_type":"C"}'])
def test_malformed_typed_candidates_stop_without_exposing_values(value):
    with pytest.raises(ValueError, match='^Police number candidate shape differs.$'):
        projection([replace(number(), value=value)])


def test_unknown_policy_rejected():
    with pytest.raises(ValueError, match='Unsupported reconstruction policy'):
        projection([], policy='unknown')


def test_new_reasons_are_explainable_without_personal_values(archive):
    p = next(p for p in archive[4] if p.dimension == 'police_number')
    # Real adapter provenance is retained; only controlled synthetic numbers change.
    c = replace(p.candidates[0], value=json.dumps(dict(police_no='secret-fixture',number_type='')))
    v = next(p for p in reconstruct(archive[0], [c], on=ON, captured_at=CAPTURE)
        if p.dimension == 'police_number')
    encoded = json.dumps(explain(v))
    assert 'POLICE_NUMBER_TYPE_OR_VALUE_MISSING' in encoded
    assert 'secret-fixture' not in encoded and archive[0] not in encoded


def test_archived_v1_result_keeps_original_conflict_after_upgrade(archive):
    a = deepcopy(archive)
    # Regenerate a v1 archive with two exact types. Replay must keep its old result.
    for row in a[2].values():
        if row['filename'] == 'officer_police_numbers.csv' and 'fixture-number-B' in row['original']['values']:
            row['original']['values'][row['original']['columns'].index('number_type')] = 'fixture-type-B'
    claims = source_claims(a[0], {k:v for k,v in a[2].items() if v['filename'] in HEADERS}, a[3]['raw_bindings'])
    from collections import Counter
    for policy, expected in [(LEGACY_POLICY, 'CONFLICTING_REPORTS'), (POLICY, 'CANNOT_VERIFY')]:
        values = reconstruct(a[0], claims, on=date(2024,12,31), captured_at=CAPTURE, policy=policy)
        a[5]['policy'] = a[6]['policy'] = policy
        a[5]['aggregate'] = dict(Counter(v.dimension+':'+v.status for v in values))
        a[6]['results'][0]['projections'] = json_value([asdict(v) for v in values])
        report = replay(a)
        assert next(d for d in report[0]['dimensions'] if d['dimension']=='police_number')['status'] == expected
    # Relabeling old results with v2 cannot pass exact replay.
    a[5]['policy'] = a[6]['policy'] = LEGACY_POLICY
    with pytest.raises(ValueError, match='Saved reconstruction differs'):
        replay(a)


@pytest.mark.parametrize('policy', [LEGACY_POLICY, POLICY])
def test_saved_encrypted_artifact_binding_uses_its_recorded_policy(tmp_path, policy):
    crypto = identity_crypto(tmp_path)
    directory = tmp_path/'saved'; directory.mkdir(mode=0o700)
    summary = dict(policy=policy, encrypted_artifacts=1, context={}, on='2024-12-31', selection_mode='SINGLE_NIC_CANDIDATE')
    binding = dict(artifact='REPORTED_HISTORY', policy=policy, context={}, public_payload_sha256=PUBLIC_SHA,
        on=summary['on'], selection_mode=summary['selection_mode'], chunk=0)
    path = directory/'history-000.encrypted.json'
    path.write_text(json.dumps(seal_artifact(crypto, crypto, {'fixture': True}, binding)));path.chmod(0o600)
    assert saved_payloads(directory, summary, crypto, crypto) == [{'fixture': True}]
    summary['policy'] = POLICY if policy == LEGACY_POLICY else LEGACY_POLICY
    with pytest.raises(Exception):
        saved_payloads(directory, summary, crypto, crypto)
