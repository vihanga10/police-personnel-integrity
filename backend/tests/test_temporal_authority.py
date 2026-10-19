"""Controlled rule fixtures test algorithms, not Sri Lanka legal authority."""
from dataclasses import replace
from datetime import date
from uuid import uuid4
import itertools
import pytest
from app.identity.temporal_authority import Fact,ActorState,Action,Rule,Delegation,evaluate

A,B,C=(str(uuid4()) for _ in range(3))
ON=date(2024,12,31);ISSUED=date(2024,1,1)


def fact(value,assessment='ASSESSED'):
    return Fact(value,assessment,('fixture-proof',))


def state(uid=A,on=ON,**updates):
    values=dict(actor_uid=uid,on=on,identity=fact(True),rank=fact('fixture-rank'),role=fact('fixture-role'),
        active=fact(True),scope=fact('fixture-origin'))
    values.update(updates);return ActorState(**values)


def action(uid=A,**updates):
    values=dict(actor_uid=uid,on=ON,power='fixture-approve',target_scope='fixture-target',
        identity=fact(True),date_semantics=fact(True),evidence=('fixture-action',))
    values.update(updates);return Action(**values)


def rule(**updates):
    values=dict(rule_id='fixture-rule',powers=('fixture-approve',),ranks=('fixture-rank',),roles=('fixture-role',),
        actor_scopes=('fixture-origin',),target_scopes=('fixture-target',),start=date(2020,1,1),end=None,
        may_delegate=True,assessment='ASSESSED',evidence=('fixture-rule-proof',))
    values.update(updates);return Rule(**values)


def delegation(**updates):
    values=dict(delegation_id='fixture-delegation',parent_id='fixture-rule',issuer_uid=A,recipient_uid=B,
        powers=('fixture-approve',),target_scopes=('fixture-target',),issued_on=ISSUED,start=ISSUED,
        end=None,may_delegate=False,revoked_from=None,assessment='ASSESSED',evidence=('fixture-delegation-proof',))
    values.update(updates);return Delegation(**values)


def run(a=None,states=None,rules=None,delegations=(),coverage=None):
    return evaluate(a or action(),[state()] if states is None else states,[rule()] if rules is None else rules,
        delegations,coverage=fact(True) if coverage is None else coverage)


def test_direct_assessed_path_supports_validity_and_preserves_provenance():
    d=run();assert d.status=='VALID' and d.successful_paths==('fixture-rule',)
    assert 'fixture-action' in d.evidence and 'fixture-rule-proof' in d.evidence


@pytest.mark.parametrize('field',['identity','rank','role','active','scope'])
@pytest.mark.parametrize('assessment',['UNASSESSED','CONFLICTING'])
def test_unassessed_or_conflicting_actor_facts_never_authorize(field,assessment):
    s=state();s=replace(s,**{field:replace(getattr(s,field),assessment=assessment)})
    assert run(states=[s]).status=='CANNOT_VERIFY'


@pytest.mark.parametrize('field,value',[('identity',False),('date_semantics',False)])
def test_refuted_action_context_is_unresolved_not_an_authority_accusation(field,value):
    assert run(a=replace(action(),**{field:fact(value)})).status=='CANNOT_VERIFY'


@pytest.mark.parametrize('field,value',[('rank','other'),('role','other'),('scope','other'),('active',False)])
def test_supported_constraint_refutes_path_only_with_complete_coverage(field,value):
    s=replace(state(),**{field:fact(value)})
    assert run(states=[s]).status=='INVALID'
    assert run(states=[s],coverage=fact(None,'UNASSESSED')).status=='CANNOT_VERIFY'


def test_identity_unassessed_cannot_use_unrelated_rank_failure_to_accuse_actor():
    assert run(states=[state(identity=fact(None,'UNASSESSED'),rank=fact('other'))]).status=='CANNOT_VERIFY'


@pytest.mark.parametrize('updates',[{'start':date(2025,1,1)},{'end':ON},{'powers':('other',)},
    {'target_scopes':('other',)}])
def test_action_date_power_and_target_scope_are_required(updates):
    assert run(rules=[rule(**updates)]).status=='INVALID'


def test_interval_start_is_inclusive_and_end_exclusive():
    assert run(rules=[rule(start=ON,end=date(2025,1,1))]).status=='VALID'
    assert run(rules=[rule(end=ON)]).status=='INVALID'


def test_missing_dated_actor_state_cannot_be_replaced_by_current_snapshot():
    assert run(states=[state(on=date(2026,1,1))]).status=='CANNOT_VERIFY'


def test_unassessed_governing_rule_cannot_establish_authority():
    assert run(rules=[rule(assessment='UNASSESSED')]).status=='CANNOT_VERIFY'


def test_absence_only_refutes_authority_when_coverage_explicitly_complete():
    assert run(rules=[],coverage=fact(None,'UNASSESSED')).status=='CANNOT_VERIFY'
    assert run(rules=[]).status=='INVALID'


def delegated_states():
    return [state(A,ISSUED),state(A),state(B,rank=fact('other'),role=fact('other'))]


def test_delegation_supports_recipient_without_assuming_direct_rank_eligibility():
    d=run(a=action(B),states=delegated_states(),delegations=[delegation()])
    assert d.status=='VALID' and d.successful_paths==('fixture-delegation',)


@pytest.mark.parametrize('updates',[{'revoked_from':ON},{'end':ON},{'start':date(2025,1,1)},
    {'powers':('fixture-approve','extra')},{'target_scopes':('fixture-target','extra')}])
def test_revoked_expired_not_yet_active_or_overbroad_delegation_refutes_route(updates):
    assert run(a=action(B),states=delegated_states(),delegations=[delegation(**updates)]).status=='INVALID'


@pytest.mark.parametrize('updates',[{'assessment':'UNASSESSED'},{'parent_id':'missing'}])
def test_missing_or_unassessed_delegation_is_not_valid_or_definitely_invalid(updates):
    assert run(a=action(B),states=delegated_states(),delegations=[delegation(**updates)]).status=='CANNOT_VERIFY'


@pytest.mark.parametrize('permission,status',[(False,'INVALID'),(None,'CANNOT_VERIFY')])
def test_explicit_parent_delegation_permission_required(permission,status):
    assert run(a=action(B),states=delegated_states(),rules=[rule(may_delegate=permission)],
        delegations=[delegation()]).status==status


def test_issuer_authority_required_at_issuance_and_at_action_date():
    states=delegated_states();states[0]=state(A,ISSUED,rank=fact('other'))
    assert run(a=action(B),states=states,delegations=[delegation()]).status=='INVALID'
    states=delegated_states();states[1]=state(A,active=fact(False))
    assert run(a=action(B),states=states,delegations=[delegation()]).status=='INVALID'
    assert run(a=action(B),states=delegated_states()[1:],delegations=[delegation()]).status=='CANNOT_VERIFY'


def test_subdelegation_requires_every_link_and_permission():
    d1=delegation(may_delegate=True)
    d2=delegation(delegation_id='fixture-sub',parent_id=d1.delegation_id,issuer_uid=B,recipient_uid=C)
    states=delegated_states()+[state(B,ISSUED,rank=fact('other')),state(C,rank=fact('other'))]
    assert run(a=action(C),states=states,delegations=[d1,d2]).status=='VALID'
    assert run(a=action(C),states=states,delegations=[replace(d1,may_delegate=False),d2]).status=='INVALID'


def test_cycle_is_unresolved_and_never_valid():
    d1=delegation(parent_id='fixture-sub',may_delegate=True)
    d2=delegation(delegation_id='fixture-sub',parent_id=d1.delegation_id,issuer_uid=B,recipient_uid=A,may_delegate=True)
    assert run(a=action(B),states=delegated_states()+[state(B,ISSUED)],rules=[],delegations=[d1,d2]).status=='CANNOT_VERIFY'


def test_alternative_valid_path_survives_unresolved_or_refuted_alternative():
    r2=rule(rule_id='unresolved',assessment='UNASSESSED')
    for order in itertools.permutations([r2,rule()]):
        d=run(rules=order);assert d.status=='VALID' and d.successful_paths==('fixture-rule',)


@pytest.mark.parametrize('kind',['state','rule','delegation'])
def test_duplicate_inputs_are_rejected(kind):
    with pytest.raises(ValueError):
        if kind=='state':run(states=[state(),state()])
        elif kind=='rule':run(rules=[rule(),rule()])
        else:run(delegations=[delegation(),delegation()])


@pytest.mark.parametrize('builder,updates',[(rule,{'end':date(2019,1,1)}),
    (rule,{'start':'2020-01-01'}),(rule,{'powers':()}),(rule,{'assessment':'VERIFIED'}),
    (rule,{'evidence':()}),(delegation,{'issued_on':date(2025,1,1)}),
    (delegation,{'recipient_uid':'invalid'}),(delegation,{'evidence':()})])
def test_invalid_instrument_shapes_fail(builder,updates):
    with pytest.raises(ValueError):builder(**updates)


def test_sensitive_ids_and_values_are_hidden_in_reprs():
    objects=[action(),state(),rule(),delegation(),run()]
    encoded=' '.join(map(repr,objects))
    assert A not in encoded and B not in encoded and 'fixture-target' not in encoded
    assert 'fixture-rule-proof' not in encoded and 'fixture-rule' not in encoded


def test_long_chain_has_a_bounded_unresolved_result():
    identities=[str(uuid4()) for _ in range(18)]
    ds=[]
    for i in range(17):
        ds.append(delegation(delegation_id='depth-'+str(i),parent_id='fixture-rule' if i==0 else 'depth-'+str(i-1),
            issuer_uid=A if i==0 else identities[i-1],recipient_uid=identities[i],may_delegate=True))
    states=[state(A),state(A,ISSUED)]+[state(u,on,rank=fact('other')) for u in identities for on in (ON,ISSUED)]
    assert run(a=action(identities[16]),states=states,delegations=ds).status=='CANNOT_VERIFY'


def test_signed_report_alone_does_not_authenticate_a_delegation():
    assert run(a=action(B),states=delegated_states(),delegations=[delegation(assessment='UNASSESSED',
        evidence=('reported-signature',))]).status=='CANNOT_VERIFY'


def test_unassessed_parent_cannot_be_used_to_refute_scope_or_to_authorize():
    assert run(a=action(B),states=delegated_states(),rules=[rule(assessment='UNASSESSED')],
        delegations=[delegation(powers=('fixture-approve','extra'))]).status=='CANNOT_VERIFY'
