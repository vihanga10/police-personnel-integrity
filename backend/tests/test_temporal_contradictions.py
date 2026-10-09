"""Invented, provenance-bearing claim fixtures; no research values."""
from dataclasses import replace
from datetime import date
import itertools,json
import pytest
from test_historical_reconstruction import claim,OFFICER,ON
from app.identity.temporal_contradictions import compare_claims


def c(identifier='a',dimension='rank',value=None,source='PF_REGISTRY',**kw):
    value=value or {'to_rank':'fixture-A'}
    return claim(identifier,dimension=dimension,value=json.dumps(value),source_reference=json.dumps(
        dict(filename='fixture.csv',provenance=dict(reported_source=source))),**kw)


def test_same_day_conflict_retains_both_provenance_and_digests():
    a,b=c(),c('b',value={'to_rank':'fixture-B'})
    for order in itertools.permutations((a,b)):
        f=compare_claims(OFFICER,order)
        assert len(f)==1 and f[0].status=='REPORTED_CONTRADICTION_CANDIDATE'
        assert f[0].claim_ids==('a','b') and f[0].destination_digests==(a.destination_digest,b.destination_digest)
        assert not f[0].accepted_contradiction and not f[0].cross_source


def test_normal_rank_transition_and_same_value_are_not_conflicts():
    assert not compare_claims(OFFICER,[c(),c('b',value={'to_rank':'B'},start=date(2020,1,2))])
    assert not compare_claims(OFFICER,[c(),c('b')])


def number(identifier='a',kind='police',number='fixture-1',**kw):
    return c(identifier,dimension='police_number',value={'police_no':number,'number_type':kind},mode='INTERVAL',**kw)


def test_overlapping_same_type_numbers_are_candidate_conflicts():
    f=compare_claims(OFFICER,[number(),number('b',number='fixture-2')])
    assert f[0].status=='REPORTED_CONTRADICTION_CANDIDATE'


def test_distinct_number_types_are_not_merged():
    assert not compare_claims(OFFICER,[number(),number('b',kind='regimental',number='fixture-2')])


def test_nonoverlapping_intervals_and_shared_endpoint_are_distinct():
    a=number(end=date(2020,1,5))
    assert not compare_claims(OFFICER,[a,number('b',number='2',start=date(2020,1,6))])
    f=compare_claims(OFFICER,[a,number('b',number='2',start=date(2020,1,5))])
    assert f[0].status=='UNRESOLVED_COMPARISON' and 'ENDPOINT_SEMANTICS_UNASSESSED' in f[0].reasons


@pytest.mark.parametrize('updates',[{'mode':'SNAPSHOT','start':None},{'mode':'REVIEW'},
    {'start':None},{'issues':('REPORTED_DATE_INVALID',)}])
def test_uncertain_applicability_never_becomes_definite_contradiction(updates):
    f=compare_claims(OFFICER,[c(),replace(c('b',value={'to_rank':'B'}),**updates)])
    assert f[0].status=='UNRESOLVED_COMPARISON'


def test_cross_source_labels_do_not_establish_independence():
    f=compare_claims(OFFICER,[c(),c('b',value={'to_rank':'B'},source='POLICE_HR_IS')])[0]
    assert f.cross_source and 'SOURCE_INDEPENDENCE_UNVERIFIED' in f.reasons


def test_snapshot_different_field_cannot_be_backdated():
    f=compare_claims(OFFICER,[number(),c('b',dimension='police_number',value={'current_police_no':'2'},mode='SNAPSHOT',start=None)])
    assert f[0].status=='UNRESOLVED_COMPARISON'


def test_missing_type_does_not_assert_same_number_namespace():
    f=compare_claims(OFFICER,[number(),number('b',kind='',number='2')])
    assert f[0].status=='UNRESOLVED_COMPARISON'


def test_restrictions_with_different_ids_can_coexist():
    a=c(dimension='restrictions',mode='INTERVAL',value={'restriction_id':'1','effect':'A'})
    b=c('b',dimension='restrictions',mode='INTERVAL',value={'restriction_id':'2','effect':'B'})
    assert not compare_claims(OFFICER,[a,b])
    assert compare_claims(OFFICER,[a,replace(b,value=json.dumps({'restriction_id':'1','effect':'B'}))])[0].status=='REPORTED_CONTRADICTION_CANDIDATE'


def test_future_dated_claims_excluded_from_requested_cutoff():
    assert not compare_claims(OFFICER,[c(),c('b',value={'to_rank':'B'},start=date(2030,1,1))],on=ON)


@pytest.mark.parametrize('failure',['duplicate','subject','value','source','duplicate_json'])
def test_invalid_comparison_inputs_stop(failure):
    a,b=c(),c('b')
    if failure=='duplicate':b=a
    elif failure=='subject':b=replace(b,officer_uid='00000000-0000-0000-0000-000000000000')
    elif failure=='value':b=replace(b,value='[]')
    elif failure=='source':b=replace(b,source_reference='{}')
    else:b=replace(b,value='{"to_rank":"A","to_rank":"B"}')
    with pytest.raises(ValueError):compare_claims(OFFICER,[a,b])


def test_repr_does_not_expose_values_or_source_details():
    a,b=c(),c('b',value={'to_rank':'private-fixture'})
    text=repr(compare_claims(OFFICER,[a,b]))
    assert 'private-fixture' not in text and 'fixture.csv' not in text


@pytest.mark.parametrize('dimension,value',[('rank',{'to_rank':''}),
    ('police_number',{'police_no':'','number_type':'police'})])
def test_blank_values_are_missing_evidence_not_contradictions(dimension,value):
    a=c(dimension=dimension,value=value)
    b=c('b',dimension=dimension,value={'to_rank':'B'} if dimension=='rank' else {'police_no':'2','number_type':'police'})
    f=compare_claims(OFFICER,[a,b])
    assert f[0].status=='UNRESOLVED_COMPARISON' and 'REPORTED_VALUE_MISSING' in f[0].reasons
