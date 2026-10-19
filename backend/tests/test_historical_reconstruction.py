from dataclasses import replace
from datetime import date, datetime, timezone, timedelta
from uuid import uuid4
import itertools
import pytest
from app.identity.historical_reconstruction import Claim, reconstruct, DIMENSIONS
from app.identity.historical_source_claims import source_claims, HEADERS, reported_date

# Random fixture identifiers and made-up values never come from research personnel.
OFFICER = str(uuid4())
CAPTURE = datetime(2026, 10, 9, 4, 0, tzinfo=timezone.utc)
ON = date(2020, 1, 10)


# Shared fixture builder keeps each test focused on one temporal or provenance rule.
def claim(identifier='a', **kwargs):
    fields = dict(claim_id=identifier, officer_uid=OFFICER, dimension='rank', value='rank-A',
        source_reference='protected-reference', destination_digest='a'*64, start=date(2020, 1, 1))
    fields.update(kwargs)
    return Claim(**fields)


def result(claims, dimension='rank', **kwargs):
    return next(x for x in reconstruct(OFFICER, claims, on=ON, captured_at=CAPTURE, **kwargs) if x.dimension == dimension)


# Missing evidence must not become a verified state or an unrestricted finding.
def test_all_dimensions_and_absence_do_not_establish_state():
    values = reconstruct(OFFICER, [], on=ON, captured_at=CAPTURE)
    assert tuple(v.dimension for v in values) == DIMENSIONS
    assert all(v.status == 'CANNOT_VERIFY' and v.accepted_state is None for v in values)


def test_latest_event_projection_keeps_predecessor_and_future():
    a, b, c = claim(), claim('b', start=date(2020,1,5), value='rank-B'), claim('c', start=date(2020,2,1))
    v = result([c,a,b])
    assert v.candidates == (b,) and v.supporting == (a,b) and v.future == (c,)
    assert v.status == 'REPORTED_CANDIDATES'
    assert 'LATEST_REPORTED_EVENT_CARRY_FORWARD_HYPOTHESIS' in v.reasons


# Permuting input checks that chronology ties never introduce arbitrary precedence.
def test_same_day_conflict_never_uses_input_order_to_choose():
    a,b = claim(), claim('b', value='rank-B')
    for ordering in itertools.permutations([a,b]):
        v = result(ordering)
        assert v.status == 'CONFLICTING_REPORTS' and v.candidates == (a,b)


def test_same_value_multiple_sources_preserve_both_without_independence_claim():
    v = result([claim(),claim('b')])
    assert len(v.candidates) == 2 and v.status == 'REPORTED_CANDIDATES'
    assert 'SOURCE_INDEPENDENCE_UNVERIFIED' in v.reasons


@pytest.mark.parametrize('mode,start,issues', [('SNAPSHOT',None,()), ('REVIEW',ON,()),
    ('EVENT',None,()), ('EVENT',ON,('CANCELLED_REPORT',))])
def test_uncertain_claim_blocks_unique_answer_but_preserves_dated_candidates(mode,start,issues):
    c = claim('b',mode=mode,start=start,issues=issues)
    v = result([claim(),c])
    assert v.status == 'CANNOT_VERIFY' and v.review == (c,) and len(v.candidates) == 1


@pytest.mark.parametrize('start,end,count', [(ON,ON,1), (date(2020,1,1),None,1),
    (date(2020,1,1),date(2020,1,9),0), (date(2020,1,11),None,0)])
def test_interval_boundaries_are_only_reported_candidates(start,end,count):
    v = result([claim(mode='INTERVAL',start=start,end=end)])
    assert len(v.candidates) == count and v.accepted_state is None
    if end == ON:
        assert 'END_DAY_INCLUSION_IS_CANDIDATE_ONLY' in v.reasons


# Restrictions are a set of potentially concurrent claims rather than a scalar label.
def test_concurrent_restrictions_are_not_mutually_exclusive():
    a=claim(dimension='restrictions',mode='INTERVAL',end=None)
    b=claim('b',dimension='restrictions',mode='INTERVAL',value='another restriction')
    v=result([a,b],dimension='restrictions')
    assert v.status == 'REPORTED_CANDIDATES' and len(v.candidates) == 2
    assert 'NO_RESTRICTION_OR_OVERRIDE_EFFECT_ACCEPTED' in v.reasons


@pytest.mark.parametrize('known', [CAPTURE-timedelta(seconds=1), CAPTURE+timedelta(seconds=1), datetime(2026,1,1)])
def test_unavailable_transaction_time_and_naive_timestamps_fail(known):
    with pytest.raises(ValueError):
        result([],known_at=known)


@pytest.mark.parametrize('mutation', [dict(officer_uid=str(uuid4())), dict(start=datetime(2020,1,1)),
    dict(end=date(2019,1,1),mode='INTERVAL'), dict(mode='UNKNOWN'), dict(dimension='authority'),
    dict(destination_digest='secret'), dict(value=''), dict(issues=['not frozen'])])
def test_invalid_claim_or_wrong_subject_rejected(mutation):
    with pytest.raises(ValueError):
        result([claim(**mutation)])


def test_duplicate_claim_ids_fail_instead_of_deduplicating():
    with pytest.raises(ValueError):
        result([claim(),claim()])


def test_reprs_do_not_disclose_claim_value_officer_or_reference():
    c = claim(value='secret-promotion',source_reference='secret-source')
    assert all(x not in repr(c) + repr(result([c])) for x in ('secret-promotion','secret-source',OFFICER))


# Construct exact source-header fixtures to exercise the real catalog adapter.
def source(filename, row_updates=None, role='officer_nic_no'):
    columns=sorted(HEADERS[filename]); row={c:'' for c in columns}
    row.update(row_updates or {})
    raw='b'*64
    return {raw:dict(filename=filename,raw_record_id=raw,
        original=dict(columns=columns,values=[row[c] for c in columns]),
        candidate_links=[dict(officer_uid=OFFICER,role=role,state='CANDIDATE_NOT_ACCEPTED')],
        classification='UNASSESSED',delivery=dict(complete=True),
        provenance=dict(source_row_number=1),assertion=dict(id='assertion'))}, {raw:[dict(row_sha256='c'*64)]}


# Guard the distinction between the subject and an actor mentioned in the same row.
def test_adapter_recorder_role_cannot_become_subject_state():
    catalog,bindings=source('officer_restrictions.csv',role='restriction_recorded_officer_nic')
    assert source_claims(OFFICER,catalog,bindings) == ()


def test_adapter_promotion_dates_order_and_content_preserved():
    catalog,bindings=source('promotion_history.csv',dict(to_rank=' Inspector ',effective_date='2020-01-01'))
    claims=source_claims(OFFICER,catalog,bindings)
    rank=next(c for c in claims if c.dimension=='rank')
    assert ' Inspector ' in rank.value and rank.start == date(2020,1,1)
    assert 'source_row_number' in rank.source_reference and rank.destination_digest
    assert result(claims).status == 'REPORTED_CANDIDATES'


@pytest.mark.parametrize('flag', ['TRUE','', 'unknown'])
def test_cancelled_or_uninterpretable_transfer_never_applied(flag):
    catalog,bindings=source('transfer_history.csv',dict(to_rank='Inspector',effective_date='2020-01-01',is_cancelled=flag))
    v=result(source_claims(OFFICER,catalog,bindings))
    assert v.status == 'CANNOT_VERIFY' and not v.candidates


def test_snapshot_service_status_not_backdated_and_entry_rank_not_assumed():
    catalog,bindings=source('officer_service_information.csv',dict(service_status='Active',entry_rank='PC',date_of_enlistment='2010-01-01'))
    claims=source_claims(OFFICER,catalog,bindings)
    assert result(claims,'service_status').status == 'CANNOT_VERIFY'
    assert result(claims,'rank').status == 'CANNOT_VERIFY'


def test_demotion_floor_not_used_as_rank_and_override_not_lifting_restriction():
    for filename,fields,dimension in [('_demotions_enacted.csv',dict(floor_rank='PC',punishment_date='2020-01-01'),'rank'),
        ('restriction_overrides.csv',dict(override_id='1',restriction_id='2',override_ground='claim',override_date='2020-01-01'),'restrictions')]:
        catalog,bindings=source(filename,fields)
        v=result(source_claims(OFFICER,catalog,bindings),dimension)
        assert v.status == 'CANNOT_VERIFY' and v.review and not v.candidates


def test_inverted_interval_preserved_for_review():
    catalog,bindings=source('officer_police_numbers.csv',dict(police_no='X',number_type='reported',valid_from='2020-02-01',valid_to='2020-01-01'))
    v=result(source_claims(OFFICER,catalog,bindings),'police_number')
    assert v.status=='CANNOT_VERIFY' and '2020-02-01' in v.review[0].source_reference


@pytest.mark.parametrize('text', ['', '31/01/2020', '2020-02-30', '20200101'])
def test_missing_and_invalid_dates_never_coerced(text):
    value,issues=reported_date(text)
    assert value is None and issues


@pytest.mark.parametrize('mutation', ['missing_binding','columns','link','classification','delivery'])
def test_adapter_rejects_provenance_and_shape_failures(mutation):
    catalog,bindings=source('promotion_history.csv',dict(to_rank='Inspector',effective_date='2020-01-01'))
    item=next(iter(catalog.values()))
    if mutation=='missing_binding':bindings={}
    elif mutation=='columns':item['original']['columns'][0]='unknown'
    elif mutation=='link':item['candidate_links'][0]['state']='ACCEPTED'
    elif mutation=='classification':item['classification']='PUBLIC'
    elif mutation=='delivery':item['delivery']['complete']=False
    with pytest.raises(ValueError):source_claims(OFFICER,catalog,bindings)

# Authenticated synthetic permits only; these tests never issue a research permit.
from test_audit_gate import verified
from test_protected_commitment import identity_crypto
from app.identity.audit_gate import verify_inputs, seal_permit
from app.identity.reconstruct_history import permitted_projection, subject_index, arguments


# Exercise genuine encrypted fixture permits rather than trusting plaintext READY labels.
def test_permit_gated_projection_uses_actual_encrypted_permit(verified,tmp_path):
    p,l,f,r,context,now=verified
    crypto=identity_crypto(tmp_path)
    envelope=seal_permit(crypto,crypto,verify_inputs(p,l,f,r,context,now=now))
    values=permitted_projection(OFFICER,[claim()],on=ON,captured_at=CAPTURE,envelope=envelope,
        crypto=crypto,backup=crypto,public=p,context=context,now=now)
    assert values[0].status=='REPORTED_CANDIDATES' and values[0].accepted_state is None


@pytest.mark.parametrize('failure',['expired','context','public','ciphertext'])
# A forbidden algorithm stub proves authorization failures occur before computation.
def test_bad_permit_stops_before_algorithm(verified,tmp_path,monkeypatch,failure):
    from copy import deepcopy
    import app.identity.reconstruct_history as runner
    p,l,f,r,context,now=deepcopy(verified)
    crypto=identity_crypto(tmp_path)
    envelope=seal_permit(crypto,crypto,verify_inputs(p,l,f,r,context,now=now))
    if failure=='expired':now+=timedelta(seconds=601)
    elif failure=='context':context['code_revision']='e'*40
    elif failure=='public':p['merkle_root']='e'*64
    else:envelope['ciphertext']='broken'
    def forbidden(*args,**kwargs):
        pytest.fail('Invalid permit reached the algorithm')
    monkeypatch.setattr(runner,'reconstruct',forbidden)
    with pytest.raises(Exception):
        runner.permitted_projection(OFFICER,[claim()],on=ON,captured_at=CAPTURE,envelope=envelope,
            crypto=crypto,backup=crypto,public=p,context=context,now=now)


# Simulated expiry during computation must prevent a completed authorized projection.
def test_guard_rechecks_after_algorithm(verified,tmp_path,monkeypatch):
    import app.identity.reconstruct_history as runner
    p,l,f,r,context,now=verified
    crypto=identity_crypto(tmp_path)
    env=seal_permit(crypto,crypto,verify_inputs(p,l,f,r,context,now=now))
    original=runner.require_audit_permit
    calls=[]
    def check(*args,**kwargs):
        calls.append(True)
        if len(calls)==2:
            kwargs['now']=now+timedelta(seconds=601)
        return original(*args,**kwargs)
    monkeypatch.setattr(runner,'require_audit_permit',check)
    with pytest.raises(ValueError):
        runner.permitted_projection(OFFICER,[claim()],on=ON,captured_at=CAPTURE,envelope=env,
            crypto=crypto,backup=crypto,public=p,context=context,now=now)
    assert len(calls)==2


def test_subject_index_keeps_actor_only_edges_out():
    catalog,_=source('officer_restrictions.csv',role='restriction_recorded_officer_nic')
    assert subject_index(dict(bundles=[dict(officer_uid=OFFICER)]),catalog)=={OFFICER:{}}


def test_cli_requires_explicit_query_and_all_captured_inputs():
    with pytest.raises(SystemExit):arguments([])
    names=['key-file','backup-key-file','commitment-key-file','backup-commitment-key-file',
        'bundle-attempt','binding-attempt','commitment-attempt','audit-gate-attempt','output-root']
    argv=[part for name in names for part in ['--'+name,'/private/'+name]]
    assert arguments(argv+['--on','2020-01-10']).on==ON
    with pytest.raises(SystemExit):arguments(argv+['--on','2020-02-30'])


def test_future_query_keeps_candidate_without_future_state_claim():
    values=reconstruct(OFFICER,[claim()],on=date(2027,1,1),captured_at=CAPTURE)
    assert values[0].status=='CANNOT_VERIFY' and values[0].candidates
    assert 'REQUEST_AFTER_CAPTURE_CANNOT_ESTABLISH_FUTURE_STATE' in values[0].reasons
