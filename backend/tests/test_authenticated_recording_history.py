"""Fixture signing only; real Ed25519 verification and bitemporal reconstruction."""
from copy import deepcopy
from datetime import datetime, date, timezone, timedelta
from uuid import UUID
import base64
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from app.identity.authenticated_recording_history import POLICY, authenticate_recording_history
from app.identity.bitemporal_reconstruction import query
from app.identity.historical_reconstruction import DIMENSIONS
from app.identity.evidence_bundle_v2 import canonical
from app.identity.protected_commitment import digest

START = datetime(2026, 10, 1, tzinfo=timezone.utc)
OFFICER = str(UUID(int=1))


def sign(key, payload, key_id='fixture-recorder'):
    message = canonical([POLICY, key_id, payload]).encode('utf-8')
    return dict(key_id=key_id, payload=deepcopy(payload),
        signature=base64.b64encode(key.sign(message)).decode())


@pytest.fixture
def fixture():
    key = Ed25519PrivateKey.generate()
    keys = {'fixture-recorder':key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)}
    scope = dict(officer_uid=OFFICER, source_keys=['PF/promotions'], dimensions=sorted(DIMENSIONS))
    context = dict(journal_id='fixture-journal', recorder_policy_sha256='a'*64,
        source_registry_sha256='b'*64)
    claim = dict(claim_id='promotion-1', officer_uid=OFFICER, dimension='rank', value='SP',
        source_reference='fixture-source-1', destination_digest='c'*64, mode='EVENT',
        start='2024-12-01', end=None, issues=[])
    events = []
    for i in range(1,4):
        version_claim = dict(claim, value='SP' if i == 1 else 'SSP')
        recorded = START+timedelta(days=i)
        events.append(dict(policy=POLICY, kind='VERSION', receipt_id=f'receipt-{i}', sequence=i,
            previous_receipt_sha256=None, context=context, scope=scope, version_id=f'v{i}',
            source_key='PF/promotions', claim=version_claim, recorded_at=recorded.isoformat(),
            issued_at=recorded.isoformat(), timestamp_semantics='RECORDER_OBSERVED_COMMITTED_VERSION',
            supersedes=None if i == 1 else f'v{i-1}', withdrawn=i == 3))
    coverage = dict(policy=POLICY, kind='COVERAGE', receipt_id='coverage-1', context=context,
        scope=scope, coverage_start=START.isoformat(),
        coverage_end=(START+timedelta(days=4)).isoformat(),
        issued_at=(START+timedelta(days=4)).isoformat(), baseline='EMPTY_AT_START',
        event_receipt_sha256=[], checkpoint_reference='independent-fixture-checkpoint',
        completeness_statement='ALL_COMMITTED_VERSION_EVENTS_IN_SCOPE')
    return dict(key=key, keys=keys, events=events, coverage=coverage, context=context, scope=scope)


def package(fixture):
    receipts = []
    for event in fixture['events']:
        event = dict(event, previous_receipt_sha256=digest(receipts[-1]) if receipts else None)
        receipts.append(sign(fixture['key'], event))
    coverage = sign(fixture['key'], dict(fixture['coverage'],
        event_receipt_sha256=[digest(r) for r in receipts]))
    return receipts, coverage


def authenticate(fixture, receipts=None, coverage=None, **overrides):
    if receipts is None: receipts, coverage = package(fixture)
    args = dict(trusted_keys=fixture['keys'], expected_context=fixture['context'],
        expected_scope=fixture['scope'], expected_coverage_digest=digest(coverage),
        now=START+timedelta(days=5))
    args.update(overrides)
    return authenticate_recording_history(receipts, coverage, **args)


def rank(result):
    return [c.value for p in result.projections if p.dimension == 'rank' for c in p.candidates]


def test_authenticated_history_preserves_old_answers_and_withdrawals(fixture):
    history = authenticate(fixture)
    old = query(history, effective_on=date(2024,12,31), known_at=START+timedelta(days=1))
    corrected = query(history, effective_on=date(2024,12,31), known_at=START+timedelta(days=2))
    withdrawn = query(history, effective_on=date(2024,12,31), known_at=START+timedelta(days=3))
    assert rank(old) == ['SP'] and rank(corrected) == ['SSP'] and rank(withdrawn) == []
    assert withdrawn.visible_versions[0].withdrawn
    assert old.accepted_state is None and not old.receipt_authenticity_claim
    assert [v.version_id for v in history.versions] == ['v1','v2','v3']
    before = query(history, effective_on=date(2024,12,31), known_at=START)
    assert rank(before) == []


@pytest.mark.parametrize('kind', ['missing','duplicate','reorder','extra','signature','untrusted',
    'key','pin','coverage_signature','context','scope'])
def test_external_authentication_and_exact_inventory_required(fixture, kind):
    receipts, coverage = package(fixture)
    pin = digest(coverage)
    overrides = {'expected_coverage_digest':pin}
    if kind == 'missing': receipts.pop()
    elif kind == 'duplicate': receipts[1] = deepcopy(receipts[0])
    elif kind == 'reorder': receipts.reverse()
    elif kind == 'extra': receipts.append(deepcopy(receipts[0]))
    elif kind == 'signature':
        receipts[0]['payload']['claim']['value'] = 'IGP'
        coverage = sign(fixture['key'], dict(coverage['payload'], event_receipt_sha256=[digest(r) for r in receipts]))
        overrides['expected_coverage_digest'] = digest(coverage)
    elif kind == 'untrusted': overrides['trusted_keys'] = {}
    elif kind == 'key': overrides['trusted_keys'] = {'fixture-recorder':b'x'*32}
    elif kind == 'pin': overrides['expected_coverage_digest'] = 'f'*64
    elif kind == 'coverage_signature': coverage['signature'] = base64.b64encode(b'x'*64).decode(); overrides['expected_coverage_digest'] = digest(coverage)
    elif kind == 'context': overrides['expected_context'] = dict(fixture['context'], journal_id='other')
    elif kind == 'scope': overrides['expected_scope'] = dict(fixture['scope'], source_keys=['other'])
    with pytest.raises(ValueError): authenticate(fixture, receipts, coverage, **overrides)


@pytest.mark.parametrize('field,value', [
    ('sequence',True), ('sequence',9), ('kind','OTHER'), ('policy','OTHER'),
    ('supersedes','missing-version'), ('source_key','other'), ('withdrawn',True),
    ('timestamp_semantics','DATABASE_REPORTED_TRANSACTION_START'),
    ('timestamp_semantics','CSV_EVENT_DATE'), ('recorded_at',None),
    ('recorded_at','2026-10-01T00:00:00+00:00'),
    ('recorded_at','2026-10-02T00:00:00'),
    ('recorded_at','2026-10-02T05:30:00+05:30'),
    ('issued_at','2026-10-01T00:00:00+00:00'),
    ('issued_at','2026-10-09T00:00:00+00:00')])
def test_even_signed_invalid_events_refused(fixture, field, value):
    fixture['events'][0][field] = value
    with pytest.raises(ValueError): authenticate(fixture)


@pytest.mark.parametrize('kind', ['fork','gap','same_time','source_change','dimension_change',
    'withdrawal_change','duplicate_version','duplicate_receipt','officer','extra_claim','extra_event'])
def test_correction_lineage_and_schema_required(fixture, kind):
    events = fixture['events']
    if kind == 'fork': events[2]['supersedes'] = 'v1'
    elif kind == 'gap': events[1]['supersedes'] = None
    elif kind == 'same_time': events[1]['recorded_at'] = events[0]['recorded_at']
    elif kind == 'source_change':
        fixture['scope']['source_keys'].append('SRB/promotions'); events[1]['source_key'] = 'SRB/promotions'
    elif kind == 'dimension_change': events[1]['claim']['dimension'] = 'posting'
    elif kind == 'withdrawal_change': events[2]['claim']['value'] = 'IGP'
    elif kind == 'duplicate_version': events[1]['version_id'] = 'v1'
    elif kind == 'duplicate_receipt': events[1]['receipt_id'] = 'receipt-1'
    elif kind == 'officer': events[0]['claim']['officer_uid'] = str(UUID(int=2))
    elif kind == 'extra_claim': events[0]['claim']['hidden'] = 'extra'
    elif kind == 'extra_event': events[0]['hidden'] = 'extra'
    with pytest.raises(ValueError): authenticate(fixture)


@pytest.mark.parametrize('field,value', [
    ('baseline','UNKNOWN'), ('baseline','DATABASE_SNAPSHOT'),
    ('completeness_statement','COUNT_MATCH_ONLY'),
    ('coverage_start','2026-10-03T00:00:00+00:00'),
    ('coverage_end','2026-10-02T00:00:00+00:00'),
    ('issued_at','2026-10-04T00:00:00+00:00'),
    ('issued_at','2026-10-09T00:00:00+00:00'), ('checkpoint_reference','')])
def test_signed_coverage_assertion_must_be_usable(fixture, field, value):
    fixture['coverage'][field] = value
    with pytest.raises(ValueError): authenticate(fixture)


def test_empty_origin_is_explicit_and_outside_coverage_queries_block(fixture):
    fixture['events'] = []
    history = authenticate(fixture)
    assert not history.versions
    for time in (START-timedelta(seconds=1), START+timedelta(days=5)):
        with pytest.raises(ValueError): query(history, effective_on=date(2024,12,31), known_at=time)


def test_valid_signatures_do_not_hide_chain_gaps(fixture):
    receipts, coverage = package(fixture)
    value = dict(receipts[1]['payload'], previous_receipt_sha256='f'*64)
    receipts[1] = sign(fixture['key'], value)
    receipts[2] = sign(fixture['key'], dict(receipts[2]['payload'], previous_receipt_sha256=digest(receipts[1])))
    coverage = sign(fixture['key'], dict(coverage['payload'], event_receipt_sha256=[digest(r) for r in receipts]))
    with pytest.raises(ValueError, match='chain'): authenticate(fixture, receipts, coverage)


def test_key_id_is_signature_bound(fixture):
    receipts, coverage = package(fixture)
    receipts[0]['key_id'] = 'another'
    fixture['keys']['another'] = fixture['keys']['fixture-recorder']
    coverage = sign(fixture['key'], dict(coverage['payload'], event_receipt_sha256=[digest(r) for r in receipts]))
    with pytest.raises(ValueError, match='signature'): authenticate(fixture, receipts, coverage)


def test_later_recorded_correction_cannot_change_old_query_digest(fixture):
    original = authenticate(fixture)
    before = query(original, effective_on=date(2024,12,31), known_at=START+timedelta(days=1))
    fixture['events'][1]['claim']['value'] = 'DIG'
    fixture['events'][2]['claim']['value'] = 'DIG'
    changed = authenticate(fixture)
    same = query(changed, effective_on=date(2024,12,31), known_at=START+timedelta(days=1))
    assert same.query_digest == before.query_digest and rank(same) == ['SP']
    assert rank(query(changed, effective_on=date(2024,12,31), known_at=START+timedelta(days=2))) == ['DIG']


def test_independent_claims_preserved_not_treated_as_corrections(fixture):
    fixture['events'] = fixture['events'][:2]
    fixture['events'][1]['claim']['claim_id'] = 'independent-promotion'
    fixture['events'][1]['supersedes'] = None
    result = query(authenticate(fixture), effective_on=date(2024,12,31),
        known_at=START+timedelta(days=2))
    projection = next(p for p in result.projections if p.dimension == 'rank')
    assert set(rank(result)) == {'SP','SSP'}
    assert len(result.visible_versions) == 2
    assert projection.accepted_state is None


def test_unsigned_and_metadata_review_envelopes_cannot_be_version_receipts(fixture):
    receipts, coverage = package(fixture)
    for envelope in (receipts[0]['payload'], dict(policy='BOUND_DATABASE_RECORDING_TIMESTAMP_V1',
        binding={}, key_version='enc', ciphertext='not-a-signed-version')):
        wrong = [envelope, *receipts[1:]]
        checkpoint = sign(fixture['key'], dict(coverage['payload'], event_receipt_sha256=[digest(r) for r in wrong]))
        with pytest.raises(ValueError): authenticate(fixture, wrong, checkpoint)
