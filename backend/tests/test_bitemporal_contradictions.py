"""Dated comparisons and signed-history integration use toy evidence only."""
from dataclasses import replace, FrozenInstanceError
from datetime import timedelta
from itertools import permutations
import json
import pytest
from app.identity import bitemporal_contradictions as D
from app.identity.contradiction_evaluation import evaluate_cases, BenchmarkCase, ExpectedPair
from contradiction_benchmark_cases import claim, number, version, history, benchmark_cases, UID,T0,T1,T2,ON
from test_controlled_recording_hook import hooked, route, process
from test_committed_evidence_capture import committed
from test_recording_tip_witness import witnessed
from test_observed_recording_journal import setup
from test_protected_recording_review import verified, keys


@pytest.mark.parametrize('case',benchmark_cases(),ids=lambda c:c.case_id)
def test_explicit_annotated_scenario(case):
    result=D.compare_history(case.history,effective_on=case.effective_on,known_at=case.known_at)
    assert [(p.claim_ids,p.status) for p in result.comparisons]==[(p.claim_ids,p.status) for p in case.expected]
    for actual,gold in zip(result.comparisons,case.expected):
        assert set(gold.required_reasons)<=set(actual.reasons)
        assert not actual.accepted_contradiction and 'SOURCE_INDEPENDENCE_UNVERIFIED' in actual.reasons
    assert not result.receipt_authenticity_claim and result.accepted_state is None
    assert not result.source_change_completeness_established


def test_late_arrival_correction_and_withdrawal_preserve_earlier_results():
    a=version(claim());b=version(claim('b',{'to_rank':'fixture-B'}),recorded_at=T1)
    h=history(a,b);early=D.compare_history(h,effective_on=ON,known_at=T0)
    assert not early.comparisons
    conflict=D.compare_history(h,effective_on=ON,known_at=T1)
    assert conflict.comparisons[0].status==D.CANDIDATE
    corrected=version(claim('b'),key='b-correction',recorded_at=T2,supersedes=b.version_id)
    new=history(a,b,corrected)
    assert D.compare_history(new,effective_on=ON,known_at=T0)==early
    assert D.compare_history(new,effective_on=ON,known_at=T1)==conflict
    assert D.compare_history(new,effective_on=ON,known_at=T2).comparisons[0].status==D.AGREEMENT
    withdrawn=replace(corrected,withdrawn=True,claim=b.claim)
    result=D.compare_history(history(a,b,withdrawn),effective_on=ON,known_at=T2)
    assert not result.comparisons and ('b-correction','WITHDRAWN') in result.exclusions


def test_boundary_instant_and_version_provenance():
    a=version(claim());b=version(claim('b',{'to_rank':'fixture-B'}),recorded_at=T1)
    h=history(a,b)
    assert not D.compare_history(h,effective_on=ON,known_at=T1-timedelta(microseconds=1)).comparisons
    p=D.compare_history(h,effective_on=ON,known_at=T1).comparisons[0]
    assert p.version_ids==(a.version_id,b.version_id) and p.receipt_digests==(a.receipt_digest,b.receipt_digest)
    assert p.source_references==(a.claim.source_reference,b.claim.source_reference)
    assert p.destination_digests==(a.claim.destination_digest,b.claim.destination_digest)
    assert p.cross_reported_source is False


def test_order_independence_and_private_repr():
    versions=(version(claim()),version(claim('b',{'to_rank':'private-fixture'})))
    results=[D.compare_history(history(*items),effective_on=ON,known_at=T0) for items in permutations(versions)]
    assert results[0]==results[1]
    assert 'private-fixture' not in repr(results[0]) and 'fixture.csv' not in repr(results[0].comparisons)
    with pytest.raises(FrozenInstanceError):results[0].policy='changed'


@pytest.mark.parametrize('kind',['array','duplicate','nonstring','reference','provenance','source-type'])
def test_malformed_evidence_stops_without_disclosing_values(kind):
    c=claim('b')
    if kind=='array':c=replace(c,value='[]')
    elif kind=='duplicate':c=replace(c,value='{"to_rank":"private","to_rank":"other"}')
    elif kind=='nonstring':c=replace(c,value='{"to_rank":1}')
    elif kind=='reference':c=replace(c,source_reference='{}')
    elif kind=='provenance':c=replace(c,source_reference='{"filename":"file.csv","provenance":[]}')
    else:c=replace(c,source_reference='{"filename":"file.csv","provenance":{"reported_source":1}}')
    with pytest.raises(ValueError) as error:D.compare_history(history(version(claim()),version(c)),effective_on=ON,known_at=T0)
    assert 'private' not in str(error.value)


@pytest.mark.parametrize('known',[T0-timedelta(microseconds=1),T2+timedelta(microseconds=1),T0.replace(tzinfo=None)])
def test_uncovered_or_naive_knowledge_is_rejected(known):
    with pytest.raises(ValueError):D.compare_history(history(version(claim())),effective_on=ON,known_at=known)


def test_reported_source_labels_do_not_authenticate_independence():
    p=D.compare_history(history(version(claim()),version(claim('b',{'to_rank':'B'},source='POLICE_HR_IS'))),effective_on=ON,known_at=T0).comparisons[0]
    assert p.cross_reported_source is True and 'SOURCE_INDEPENDENCE_UNVERIFIED' in p.reasons
    p=D.compare_history(history(version(claim(source=None)),version(claim('b',{'to_rank':'B'}))),effective_on=ON,known_at=T0).comparisons[0]
    assert p.cross_reported_source is None and 'SOURCE_ATTRIBUTION_UNASSESSED' in p.reasons


def test_historical_disagreement_expired_at_query_date_is_excluded():
    a=number(end=ON-timedelta(days=1));b=number('b',number='two')
    result=D.compare_history(history(version(a),version(b)),effective_on=ON,known_at=T0)
    assert not result.comparisons and ('version-a','EXPIRED') in result.exclusions


def test_fixture_evaluation_reports_counts_and_limits():
    result=evaluate_cases(benchmark_cases())
    assert result['cases']==20 and result['annotated_pairs']==18
    assert result['candidate_detection']==dict(tp=5,fp=0,fn=0,precision=1.0,recall=1.0,f1=1.0)
    assert result['exact_status_accuracy']==result['required_reason_coverage']==1.0
    assert not result['research_accuracy_established']


def test_zero_denominators_are_unknown_not_perfect_accuracy():
    case=BenchmarkCase('empty',history(),ON,T0,())
    report=evaluate_cases((case,))
    assert report['candidate_detection']['precision'] is None and report['candidate_detection']['f1'] is None
    assert report['exact_status_accuracy'] is None


@pytest.mark.parametrize('kind',['duplicate-case','duplicate-pair','missing-annotation','wrong-status'])
def test_benchmark_annotation_integrity(kind):
    case=benchmark_cases()[0]
    if kind=='duplicate-case':cases=(case,case)
    elif kind=='duplicate-pair':cases=(replace(case,expected=case.expected*2),)
    elif kind=='missing-annotation':cases=(replace(case,expected=()),)
    else:
        with pytest.raises(ValueError):ExpectedPair(('a','b'),'ACCEPTED',())
        return
    with pytest.raises(ValueError):evaluate_cases(cases)


def test_scoring_wrong_label_counts_false_positive_and_false_negative():
    cases=benchmark_cases();wrong_positive=replace(cases[0],expected=(ExpectedPair(('a','b'),D.AGREEMENT,()),))
    wrong_negative=replace(cases[1],expected=(ExpectedPair(('a','b'),D.CANDIDATE,()),))
    report=evaluate_cases((wrong_positive,wrong_negative))
    assert report['candidate_detection']==dict(tp=0,fp=1,fn=1,precision=0.0,recall=0.0,f1=0.0)


def test_verified_witness_history_can_feed_pure_comparisons(hooked):
    h=hooked;t=h['d']['t'];baseline=t['adapter'].select()['state']['history']
    early=D.compare_history(baseline,effective_on=ON,known_at=baseline.coverage_end)
    # New independent intake, not a correction, creates two active number reports.
    process(h,route(h,supersedes=None));selected=t['adapter'].select()['state']['history']
    current=D.compare_history(selected,effective_on=ON,known_at=selected.coverage_end)
    assert current.comparisons[0].status==D.CANDIDATE
    assert current.comparisons[0].cross_reported_source is None
    assert D.compare_history(selected,effective_on=ON,known_at=baseline.coverage_end)==early
    assert not current.receipt_authenticity_claim  # authentication belongs to the caller's witnessed replay


def test_query_after_knowledge_date_stays_unresolved():
    from datetime import date
    result=D.compare_history(history(version(number()),version(number('b',number='two'))),
        effective_on=date(2030,1,1),known_at=T0)
    assert result.comparisons[0].status==D.UNRESOLVED
    assert 'REQUEST_AFTER_KNOWLEDGE_CANNOT_ESTABLISH_FUTURE_STATE' in result.comparisons[0].reasons


def test_benchmark_digest_is_order_independent():
    cases=benchmark_cases()
    assert evaluate_cases(cases)==evaluate_cases(reversed(cases))


def test_unannotated_explanations_do_not_receive_perfect_score():
    case=benchmark_cases()[0]
    case=replace(case,expected=(replace(case.expected[0],required_reasons=()),))
    result=evaluate_cases((case,))
    assert result['explanation_annotated_pairs']==0 and result['required_reason_coverage'] is None


def test_annotations_cannot_reference_nonexistent_claims():
    case=benchmark_cases()[0]
    case=replace(case,expected=(ExpectedPair(('a','missing'),D.CANDIDATE,()),))
    with pytest.raises(ValueError,match='unavailable'):evaluate_cases((case,))


@pytest.mark.parametrize('dimension,value,reason',[
    ('posting',{'to_unit_name':'unit-A'},'POSTING_DATE_AND_UNIT_IDENTITY_UNASSESSED'),
    ('service_status',{'service_status':'active'},'SERVICE_STATUS_HISTORICAL_APPLICABILITY_UNASSESSED'),
    ('restrictions',{'restriction_id':'one','effect':'A'},'RESTRICTION_FIELD_APPLICABILITY_UNKNOWN')])
def test_unapproved_field_semantics_do_not_create_conflicts(dimension,value,reason):
    a=claim(value=value,dimension=dimension,mode='INTERVAL')
    b=replace(a,claim_id='b',value=json.dumps({k:v+'-different' for k,v in value.items()}))
    p=D.compare_history(history(version(a),version(b)),effective_on=ON,known_at=T0).comparisons[0]
    assert p.status==D.UNRESOLVED and reason in p.reasons


def test_different_event_dates_do_not_hide_missing_values():
    a=claim(value={'to_rank':''})
    b=claim('b',{'to_rank':'B'},start=ON)
    result=D.compare_history(history(version(a),version(b)),effective_on=ON,known_at=T0)
    assert result.comparisons[0].status==D.UNRESOLVED
    assert 'REPORTED_VALUE_MISSING' in result.comparisons[0].reasons
