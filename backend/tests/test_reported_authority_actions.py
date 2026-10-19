"""Exact schema controlled fixtures exercise reported actor/action adapters."""
from copy import deepcopy
from datetime import date
from uuid import uuid4
import json
import pytest
from app.identity.reported_authority_actions import review_actions,ROUTES,HEADERS

UID=str(uuid4());RAW='a'*64


def source(filename,kind_index=0,actor_link=True,**updates):
    kind,actor,dt=ROUTES[filename][kind_index]
    row={f:'' for f in HEADERS[filename]}
    if actor:row[actor]='private-fixture-actor'
    if dt:row[dt]='2020-01-01'
    row.update(updates)
    cols=sorted(row)
    item=dict(raw_record_id=RAW,filename=filename,original=dict(columns=cols,values=[row[c] for c in cols]),
        classification='UNASSESSED',delivery=dict(complete=True),assertion=dict(id='fixture-assertion'),
        provenance=dict(reported_source='SRB'),candidate_links=[dict(officer_uid=UID,role=actor,
        state='CANDIDATE_NOT_ACCEPTED')] if actor and actor_link else [])
    return {RAW:item},{RAW:[dict(row_sha256='b'*64)]}


@pytest.mark.parametrize('filename,index',[(f,i) for f,v in ROUTES.items() for i in range(len(v))])
def test_every_declared_route_preserves_unassessed_action(filename,index):
    catalog,binding=source(filename,index)
    results=review_actions(catalog,binding)
    r=next(r for r in results if r.action_kind==ROUTES[filename][index][0])
    assert r.status=='CANNOT_VERIFY' and not r.accepted_authority
    assert r.raw_record_id==RAW and r.destination_digest
    assert 'GOVERNING_RULE_UNASSESSED' in r.reasons
    assert 'private-fixture-actor' not in repr(r)


def test_free_text_authority_does_not_create_an_officer_link():
    catalog,binding=source('promotion_history.csv',actor_link=False)
    r=review_actions(catalog,binding)[0]
    assert not r.actor_candidates and 'ACTOR_IDENTITY_UNRESOLVED' in r.reasons


def test_subject_nic_cannot_become_signing_actor():
    catalog,binding=source('restriction_overrides.csv');catalog[RAW]['candidate_links'][0]['role']='officer_nic_no'
    assert not review_actions(catalog,binding)[0].actor_candidates


def test_ambiguous_actor_candidates_never_select_first():
    catalog,binding=source('restriction_overrides.csv')
    catalog[RAW]['candidate_links'].append(dict(officer_uid=str(uuid4()),role='override_authority_nic',state='CANDIDATE_NOT_ACCEPTED'))
    r=review_actions(catalog,binding)[0]
    assert len(r.actor_candidates)==2 and 'ACTOR_CANDIDATES_AMBIGUOUS' in r.reasons


@pytest.mark.parametrize('text',['','2020-02-30','01/01/2020'])
def test_missing_invalid_or_ambiguous_date_is_not_guessed(text):
    catalog,binding=source('restriction_overrides.csv',override_date=text)
    r=review_actions(catalog,binding)[0]
    assert r.reported_date is None and r.reported_date_text==text


def test_future_action_excluded_from_cutoff_without_deleting_source():
    catalog,binding=source('restriction_overrides.csv');before=deepcopy(catalog)
    assert not review_actions(catalog,binding,on=date(2019,1,1))
    assert catalog==before


def test_optional_absent_action_slots_do_not_create_missing_actions():
    catalog,binding=source('officer_restrictions.csv')
    assert len(review_actions(catalog,binding))==1


def test_delegation_reference_is_preserved_without_becoming_instrument():
    catalog,binding=source('bad_conduct_register.csv',delegation_instrument='private-ref')
    r=review_actions(catalog,binding)[0]
    assert 'REPORTED_DELEGATION_REFERENCE_NOT_AUTHENTICATED' in r.reasons
    assert 'private-ref' in r.source_reference and 'private-ref' not in repr(r)


@pytest.mark.parametrize('change',['columns','binding','state','classification','delivery','raw'])
def test_shape_and_provenance_changes_are_rejected(change):
    catalog,binding=source('restriction_overrides.csv')
    if change=='columns':catalog[RAW]['original']['columns'][0]='unknown'
    elif change=='binding':binding={}
    elif change=='state':catalog[RAW]['candidate_links'][0]['state']='ACCEPTED'
    elif change=='classification':catalog[RAW]['classification']='PUBLIC'
    elif change=='delivery':catalog[RAW]['delivery']['complete']=False
    else:catalog[RAW]['raw_record_id']='b'*64
    with pytest.raises(ValueError):review_actions(catalog,binding)


def test_malformed_candidate_uuid_is_rejected_even_when_ambiguous():
    catalog,binding=source('restriction_overrides.csv')
    catalog[RAW]['candidate_links'].append(dict(officer_uid='not-a-uuid',
        role='override_authority_nic',state='CANDIDATE_NOT_ACCEPTED'))
    with pytest.raises(ValueError):review_actions(catalog,binding)
