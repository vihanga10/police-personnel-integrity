"""Synthetic fixtures exercise preservation, subject conflicts and encrypted binding."""
import base64
from dataclasses import replace
from datetime import date
import json
from pathlib import Path
from uuid import uuid4

from cryptography.exceptions import InvalidTag
import pytest
from app.identity.srb_plan import ROUTES, SourceReference, plan_srb, validate_srb_routing, bounded_intersection_count
from app.identity.srb_plan_crypto import seal_srb_plan, open_srb_plan
from app.security.identity_crypto import IdentityCrypto

NUMBER = 'officer_police_numbers.csv'
RESTRICTION = 'officer_restrictions.csv'
OVERRIDE = 'restriction_overrides.csv'


def sample(filename, **changes):
    row = dict.fromkeys(ROUTES[filename], '')
    row['officer_nic_no'] = 'SYNTHETIC NIC'
    if filename == NUMBER:
        row.update(police_no='00001', number_type='source type', valid_from='2020-01-01')
    elif filename == RESTRICTION:
        row.update(restriction_id='R1', restriction_start_date='2020-01-01', restriction_record_date='2020-01-02')
    else:
        row.update(override_id='O1', restriction_id='R1', transfer_id='T1', override_reference='P1',
                   override_ground='source claim', override_reason='Original reason', override_authority_nic='ACTOR NIC',
                   override_authority_rank='Assistant Superintendent of Police', override_date='2020-02-01')
    row.update(changes)
    return row


def item(plan, name):
    return next(f for f in plan.fields if f.source_column == name)


def override_plan(uid=None, **options):
    uid = uid or uuid4()
    defaults = dict(actor_candidates={'override_authority_nic': uuid4()}, reference_candidates={
        'restriction_id': (SourceReference(RESTRICTION, 'a' * 64, uid),),
        'transfer_id': (SourceReference('transfer_history.csv', 'b' * 64, uid),),
    })
    defaults.update(options)
    return plan_srb(OVERRIDE, sample(OVERRIDE), officer_uid=uid, **defaults)


@pytest.mark.parametrize('filename', [NUMBER, RESTRICTION, OVERRIDE])
def test_all_source_columns_and_exact_strings_preserved(filename):
    row = sample(filename)
    plan = plan_srb(filename, row, officer_uid=uuid4())
    assert {f.source_column: f.source_value for f in plan.fields} == row
    assert 'SYNTHETIC NIC' not in repr(plan)


def test_number_leading_zeros_and_unknown_end_are_preserved():
    plan = plan_srb(NUMBER, sample(NUMBER, police_no=' 00012 '), officer_uid=uuid4())
    assert item(plan, 'police_no').value == '00012'
    assert item(plan, 'police_no').source_value == ' 00012 '
    assert item(plan, 'valid_to').value is None
    assert 'MISSING_END_NOT_EXPLICIT_OPEN_INTERVAL' in plan.observations
    assert item(plan, 'number_type').value['code'] is None


@pytest.mark.parametrize('text', ['2023-02-29', '01/02/2020', '2020-01-01T00:00:00Z'])
def test_dates_are_not_guessed_or_corrected(text):
    plan = plan_srb(NUMBER, sample(NUMBER, valid_from=text), officer_uid=uuid4())
    assert plan.needs_review
    assert item(plan, 'valid_from').source_value == text
    assert item(plan, 'valid_from').value is None


def test_adverse_date_order_requires_review_without_rewriting():
    plan = plan_srb(NUMBER, sample(NUMBER, valid_to='2019-12-31'), officer_uid=uuid4())
    assert plan.needs_review
    assert item(plan, 'valid_to').value == date(2019, 12, 31)


def test_missing_removal_and_verifiable_flag_do_not_verify_status():
    plan = plan_srb(RESTRICTION, sample(RESTRICTION, restriction_verifiable='TRUE'), officer_uid=uuid4())
    assert item(plan, 'restriction_verifiable').value is True
    assert 'SOURCE_FLAG_NOT_VERIFICATION_RESULT' in item(plan, 'restriction_verifiable').issues
    assert 'MISSING_REMOVAL_NOT_PROOF_OF_ACTIVE_RESTRICTION' in plan.observations


def test_unmapped_boolean_and_partial_removal_preserved_for_review():
    plan = plan_srb(RESTRICTION, sample(RESTRICTION, override_recorded='yes', restriction_removal_date='2020-02-01'), officer_uid=uuid4())
    assert item(plan, 'override_recorded').status == 'REVIEW_REQUIRED'
    assert 'REMOVAL_EVIDENCE_INCOMPLETE' in plan.review_issues


def test_incomplete_and_ambiguous_station_are_not_accepted():
    for changes, candidates in [
        ({'restricted_station_code': '001'}, {}),
        ({'restricted_station_code': '001', 'restricted_station_name': 'Station'}, {'Station': ('001', '002')}),
    ]:
        plan = plan_srb(RESTRICTION, sample(RESTRICTION, **changes), officer_uid=uuid4(), station_candidates=candidates)
        assert plan.needs_review
        assert item(plan, 'restricted_station_code').value is None


def test_station_match_is_source_scoped_not_historical_scope_proof():
    plan = plan_srb(RESTRICTION, sample(RESTRICTION, restricted_station_code='001', restricted_station_name='Station'),
        officer_uid=uuid4(), station_candidates={'Station': ('001',)})
    assert not plan.needs_review
    assert 'STATION_REFERENCE_SOURCE_SCOPED_HISTORICAL_APPLICABILITY_UNKNOWN' in item(plan, 'restricted_station_code').issues


def test_same_subject_override_candidate_does_not_approve_asp_authority():
    plan = override_plan()
    assert not plan.needs_review
    assert 'OVERRIDE_CLAIM_PRESERVED_NOT_APPLIED' in plan.observations
    assert 'REPORTED_RANK_NOT_AUTHORITY_VERIFICATION' in item(plan, 'override_authority_rank').issues
    assert item(plan, 'restriction_id').value == 'a' * 64


@pytest.mark.parametrize('mode', ['missing', 'ambiguous', 'wrong_source', 'wrong_subject'])
def test_override_reference_conflicts_require_review(mode):
    uid = uuid4()
    ref = SourceReference('transfer_history.csv' if mode == 'wrong_source' else RESTRICTION,
        'a' * 64, uuid4() if mode == 'wrong_subject' else uid)
    refs = () if mode == 'missing' else (ref, ref) if mode == 'ambiguous' else (ref,)
    plan = override_plan(uid, reference_candidates={'restriction_id': refs,
        'transfer_id': (SourceReference('transfer_history.csv', 'b' * 64, uid),)})
    assert plan.needs_review
    assert item(plan, 'restriction_id').value is None


def test_unresolved_actor_is_not_guessed_from_reported_rank():
    plan = override_plan(actor_candidates={})
    assert item(plan, 'override_authority_nic').status == 'REVIEW_REQUIRED'
    assert item(plan, 'override_authority_nic').value is None


def test_contract_and_nul_guards_preserve_evidence():
    with pytest.raises(ValueError):
        plan_srb(NUMBER, dict(sample(NUMBER), extra='x'), officer_uid=uuid4())
    with pytest.raises(ValueError):
        plan_srb(NUMBER, sample(NUMBER, police_no=123), officer_uid=uuid4())
    plan = plan_srb(NUMBER, sample(NUMBER, issue_reason='line\x00two'), officer_uid=uuid4())
    assert item(plan, 'issue_reason').source_value == 'line\x00two'
    assert plan.needs_review


def test_routing_contract_and_duplicate_guard():
    contract = json.loads((Path(__file__).resolve().parents[2] / 'docs/field-routing.json').read_text())
    validate_srb_routing(contract)
    source = next(f for f in contract['files'] if f['filename'] == NUMBER)
    source['fields'][0] = dict(source['fields'][1])
    with pytest.raises(ValueError):
        validate_srb_routing(contract)


@pytest.fixture
def crypto_pair(tmp_path):
    # Ephemeral test-only keys; these never connect to a database.
    key = base64.b64encode(b'K' * 32).decode()
    keys = dict(active_encryption_key_version='test', active_lookup_key_version='test',
        encryption_keys={'test': key}, lookup_keys={'test': key})
    paths = [tmp_path / 'primary.json', tmp_path / 'backup.json']
    for path in paths:
        path.write_text(json.dumps(keys))
    return tuple(IdentityCrypto(path) for path in paths)


def test_encrypted_recovery_preserves_claims_without_state_or_authority(crypto_pair):
    crypto, backup = crypto_pair
    plan = override_plan()
    cipher, version = seal_srb_plan(crypto, plan, raw_record_id='c' * 64, reference_evidence={'fixture': True})
    binding = dict(key_version=version, filename=OVERRIDE, officer_uid=plan.officer_uid, raw_record_id='c' * 64)
    result = open_srb_plan(crypto, cipher, **binding)
    assert result == open_srb_plan(backup, cipher, **binding)
    assert result['record_classification'] == 'UNASSESSED'
    assert result['authority_assessment'] == 'NOT_RUN'
    assert all(result[k] is None for k in ('valid_from', 'valid_to', 'authority_result', 'reconstructed_state'))
    assert b'Original reason' not in cipher


def test_cipher_rebinding_and_tampering_fail(crypto_pair):
    crypto, _ = crypto_pair
    plan = override_plan()
    cipher, version = seal_srb_plan(crypto, plan, raw_record_id='c' * 64, reference_evidence={})
    binding = dict(key_version=version, filename=OVERRIDE, officer_uid=plan.officer_uid, raw_record_id='c' * 64)
    for changes in ({'filename': NUMBER}, {'officer_uid': uuid4()}, {'raw_record_id': 'd' * 64}):
        with pytest.raises(InvalidTag):
            open_srb_plan(crypto, cipher, **dict(binding, **changes))
    with pytest.raises(InvalidTag):
        open_srb_plan(crypto, cipher[:-1] + bytes([cipher[-1] ^ 1]), **binding)
    for changed in (replace(plan, fields=plan.fields[:-1]), replace(plan, officer_uid=uuid4()), replace(plan, policy_version='unapproved')):
        with pytest.raises(ValueError):
            seal_srb_plan(crypto, changed, raw_record_id='c' * 64, reference_evidence={})


def test_override_flag_consistency_does_not_apply_an_override():
    uid = uuid4()
    row = sample(RESTRICTION, override_recorded='TRUE')
    assert 'OVERRIDE_FLAG_REFERENCE_INCONSISTENT' in plan_srb(RESTRICTION, row,
        officer_uid=uid, linked_override_subjects=()).review_issues
    matched = plan_srb(RESTRICTION, row, officer_uid=uid, linked_override_subjects=(uid,))
    assert not matched.needs_review
    conflict = plan_srb(RESTRICTION, row, officer_uid=uid, linked_override_subjects=(uuid4(),))
    assert 'LINKED_OVERRIDE_SUBJECT_CONFLICT' in conflict.review_issues
    false_flag = plan_srb(RESTRICTION, sample(RESTRICTION, override_recorded='FALSE'),
        officer_uid=uid, linked_override_subjects=(uid,))
    assert 'OVERRIDE_FLAG_REFERENCE_INCONSISTENT' in false_flag.review_issues


def test_bounded_intersections_ignore_unknown_ends_and_touching_boundaries():
    first, second, third = date(2020, 1, 1), date(2020, 2, 1), date(2020, 3, 1)
    assert bounded_intersection_count([(first, second), (second, third), (first, None)]) == 0
    assert bounded_intersection_count([(first, third), (second, third), (third, first)]) == 1
