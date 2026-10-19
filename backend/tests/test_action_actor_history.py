"""Invented actor/date histories exercise actual source adapters and evaluator."""
from copy import deepcopy
from dataclasses import replace
from datetime import date
from uuid import uuid4
import pytest
from app.identity.action_actor_history import ActorHistory
from app.identity.reported_authority_actions import ActionReview
from test_historical_reconstruction import source, OFFICER, CAPTURE


def action(uid=OFFICER, on='2020-01-10'):
    return ActionReview('AUTHORIZE_PROMOTION', 'CANNOT_VERIFY', ('GOVERNING_RULE_UNASSESSED',),
        'a'*64, (uid,) if uid else (), on, on or '', 'private-source', 'c'*64)


def history():
    catalog,bindings=source('promotion_history.csv',dict(to_rank='fixture-rank-old', effective_date='2020-01-01'))
    later,more=source('promotion_history.csv',dict(to_rank='fixture-rank-new', effective_date='2021-01-01'))
    item=next(iter(later.values()));item['raw_record_id']='d'*64
    catalog['d'*64]=item;bindings['d'*64]=next(iter(more.values()))
    for row in catalog.values():row['provenance']['reported_source']='PF_REGISTRY'
    return ActorHistory({OFFICER:catalog},bindings,CAPTURE,'e'*64)


def test_actor_state_uses_action_date_and_retains_future_reports():
    h=history();result=h.review(action());claims,states=h.drain()
    assert len(claims)==len(states)==1 and result['status']=='CANNOT_VERIFY'
    state=states[0];rank=next(p for p in state['history'] if p['dimension']=='rank')
    assert state['on']=='2020-01-10' and len(rank['candidates'])==1 and len(rank['future'])==1
    inventory={c['claim_id']:c for c in claims[0]['claims']}
    assert 'fixture-rank-old' in inventory[rank['candidates'][0]]['value']
    assert 'fixture-rank-new' in inventory[rank['future'][0]]['value']
    assert state['authority_actor_facts']['rank']['assessment']=='UNASSESSED'
    assert not state['accepted_state_claim'] and not result['accepted_authority_claim']


def test_same_actor_date_reuses_state_without_duplicate_source_inventory():
    h=history();a=h.review(action());h.drain();b=h.review(action())
    assert h.drain()==([],[]) and a['actor_state_links']==b['actor_state_links']
    assert h.aggregate()['distinct_actor_dates']==1 and h.aggregate()['linked_candidate_states']==2


def test_different_action_date_gets_new_state_and_later_candidate():
    h=history();h.review(action());h.drain();later=h.review(action(on='2022-01-01'))
    claims,states=h.drain()
    assert not claims and len(states)==1 and h.aggregate()['distinct_actor_dates']==2
    assert 'fixture-rank-new' in states[0]['authority_actor_facts']['rank']['value']


@pytest.mark.parametrize('change',['missing_date','invalid_date','missing_actor','outside'])
def test_unresolved_actor_date_does_not_fabricate_history(change):
    h=history();a=action()
    if change=='missing_date':a=replace(a,reported_date=None,reported_date_text='')
    elif change=='invalid_date':a=replace(a,reported_date=None,reported_date_text='not-a-date')
    elif change=='missing_actor':a=replace(a,actor_candidates=())
    else:a=replace(a,actor_candidates=(str(uuid4()),))
    result=h.review(a)
    assert result['status']=='CANNOT_VERIFY' and h.aggregate()['distinct_actor_dates']==0
    assert h.drain()==([],[])


def test_ambiguous_candidates_preserve_both_histories_not_first_match():
    h=history();other=str(uuid4());h.buckets[other]={}
    result=h.review(replace(action(),actor_candidates=(OFFICER,other)))
    assert result['history_link_status']=='AMBIGUOUS_CANDIDATE_HISTORIES'
    assert {x['officer_uid'] for x in result['actor_state_links']}=={OFFICER,other}
    assert h.aggregate()['distinct_actor_dates']==2


def test_recorder_membership_never_becomes_subject_history():
    catalog,bindings=source('promotion_history.csv',dict(to_rank='private-rank',effective_date='2020-01-01'),
        role='promotion_authority')
    h=ActorHistory({OFFICER:catalog},bindings,CAPTURE,'e'*64)
    h.review(action());claims,states=h.drain()
    assert claims[0]['claims']==[]
    assert all(not p['candidates'] for p in states[0]['history'])


def test_evaluator_receives_reconstructed_actor_state(monkeypatch):
    import app.identity.action_actor_history as M
    original=M.evaluate;calls=[]
    def evaluate(request,states,rules,**kw):
        calls.append(states)
        return original(request,states,rules,**kw)
    monkeypatch.setattr(M,'evaluate',evaluate)
    h=history();h.review(action())
    assert len(calls)==1 and calls[0][0].actor_uid==OFFICER
    assert calls[0][0].on==date(2020,1,10) and calls[0][0].rank.evidence


def test_rank_candidates_never_supply_role_scope_or_active_facts():
    h=history();h.review(action());_,states=h.drain()
    facts=states[0]['authority_actor_facts']
    assert all(facts[x]['value'] is None and facts[x]['assessment']=='UNASSESSED'
        for x in ('identity','active','role','scope'))


def test_action_and_anchored_catalog_are_not_mutated():
    h=history();a=action();before=deepcopy(h.buckets);h.review(a)
    assert h.buckets==before and a==action()
