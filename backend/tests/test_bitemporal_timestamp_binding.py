"""Complete-row binding and actual AEAD recovery; no live personnel processing."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone, timedelta
from uuid import UUID
import base64
import json
import pytest

from app.identity.destination_binding import row_binding
from app.identity.bitemporal_timestamp_binding import (
    TABLE, verify_recording_timestamp, payload, seal_recording_receipt, open_recording_receipt)
from app.security.identity_crypto import IdentityCrypto

OFFICER, ASSERTION, SOURCE, FILE = (UUID(int=i) for i in range(1, 5))
START = datetime(2026, 10, 1, tzinfo=timezone.utc)


@pytest.fixture
def source():
    row = dict(source_assertion_id=ASSERTION, officer_uid=OFFICER,
        source_system_id=SOURCE, import_file_id=FILE, raw_record_id='a'*64,
        source_file_name='officer_police_numbers.csv', source_file_sha256='b'*64,
        source_row_number=1, intake_batch_id='FIXTURE', assertion_type='POLICE_NUMBER',
        transaction_start=START, transaction_end=None, assertion_state='ACTIVE',
        asserted_value_ciphertext=b'fixture-ciphertext')
    assertion = {k: str(v) if isinstance(v, UUID) else v for k, v in row.items()
        if k not in {'officer_uid', 'transaction_start', 'transaction_end',
            'assertion_state', 'asserted_value_ciphertext'}}
    catalog = dict(raw_record_id=row['raw_record_id'], assertion=assertion,
        filename=row['source_file_name'], delivery=dict(complete=True, assertion_id=str(ASSERTION)),
        candidate_links=[dict(officer_uid=str(OFFICER), role='officer_nic_no',
            state='CANDIDATE_NOT_ACCEPTED')])
    bindings = {row['raw_record_id']: [row_binding(TABLE, ('source_assertion_id',), row)]}
    return row, catalog, bindings


@pytest.fixture
def keys(tmp_path):
    data = dict(active_encryption_key_version='enc', active_lookup_key_version='lookup',
        encryption_keys={'enc':base64.b64encode(b'E'*32).decode()},
        lookup_keys={'lookup':base64.b64encode(b'L'*32).decode()})
    paths = [tmp_path/'primary.json', tmp_path/'backup.json']
    for path in paths:
        path.write_text(json.dumps(data)); path.chmod(0o600)
    return tuple(IdentityCrypto(path) for path in paths)


@pytest.fixture
def context():
    return dict(code_revision='c'*40, bundle_attempt_id='bundle-fixture',
        binding_attempt_id='binding-fixture', commitment_attempt_id='commitment-fixture',
        binding_artifact_sha256='d'*64)


def test_timestamp_verified_without_claiming_visibility_or_complete_history(source):
    row, catalog, bindings = source
    result = verify_recording_timestamp(row, catalog, bindings)
    assert result.transaction_start == START
    assert not result.visibility_time_established and not result.complete_history_established
    assert result.timestamp_semantics == 'DATABASE_REPORTED_TRANSACTION_START'
    assert result.row_sha256 == bindings[row['raw_record_id']][0]['row_sha256']
    for secret in (str(OFFICER), str(ASSERTION), row['raw_record_id'], START.isoformat()):
        assert secret not in repr(result)


@pytest.mark.parametrize('field,value', [
    ('transaction_start', START+timedelta(seconds=1)),
    ('transaction_start', None), ('transaction_end', START+timedelta(seconds=2)),
    ('assertion_state', 'WITHDRAWN'), ('asserted_value_ciphertext', b'changed'),
    ('officer_uid', UUID(int=8)), ('source_assertion_id', UUID(int=8)),
    ('source_system_id', UUID(int=8)), ('import_file_id', UUID(int=8)),
    ('source_file_sha256', 'e'*64), ('raw_record_id', 'e'*64),
    ('source_file_name', 'changed.csv'), ('source_row_number', 2)])
def test_unbound_row_changes_rejected(source, field, value):
    row, catalog, bindings = source
    altered = dict(row, **{field:value})
    with pytest.raises(ValueError):
        verify_recording_timestamp(altered, catalog, bindings)


@pytest.mark.parametrize('failure', ['missing', 'duplicate', 'wrong_table', 'wrong_key', 'extra_column'])
def test_wrong_destination_scope_rejected(source, failure):
    row, catalog, bindings = deepcopy(source)
    entries = bindings[row['raw_record_id']]
    if failure == 'missing': entries.clear()
    elif failure == 'duplicate': entries.append(deepcopy(entries[0]))
    elif failure == 'wrong_table': entries[0]['table'] = 'identity.other'
    elif failure == 'wrong_key': entries[0]['primary_key'][0][1] = ['uuid', str(UUID(int=8))]
    else: row['extra'] = 'unbound'
    with pytest.raises(ValueError):
        verify_recording_timestamp(row, catalog, bindings)


@pytest.mark.parametrize('failure', ['complete', 'subject', 'accepted'])
def test_receipt_and_subject_required(source, failure):
    row, catalog, bindings = deepcopy(source)
    if failure == 'complete': catalog['delivery']['complete'] = False
    elif failure == 'subject': catalog['candidate_links'][0]['role'] = 'recording_officer'
    else: catalog['candidate_links'][0]['state'] = 'ACCEPTED'
    with pytest.raises(ValueError):
        verify_recording_timestamp(row, catalog, bindings)


@pytest.mark.parametrize('start,end', [
    (None, None), (datetime(2026,10,1), None), (START, START),
    (START, START-timedelta(seconds=1))])
def test_even_matching_fingerprints_do_not_make_invalid_times_usable(source, start, end):
    row, catalog, _ = source
    row.update(transaction_start=start, transaction_end=end)
    with pytest.raises(ValueError):
        bindings = {row['raw_record_id']: [row_binding(TABLE, ('source_assertion_id',), row)]}
        verify_recording_timestamp(row, catalog, bindings)


def test_timezone_normalization_and_withdrawn_metadata_preserved(source):
    row, catalog, bindings = source
    row['transaction_start'] = START.astimezone(timezone(timedelta(hours=5, minutes=30)))
    result = verify_recording_timestamp(row, catalog, bindings)
    assert result.transaction_start == START
    row.update(transaction_end=START+timedelta(days=1), assertion_state='WITHDRAWN')
    bindings[row['raw_record_id']] = [row_binding(TABLE, ('source_assertion_id',), row)]
    result = verify_recording_timestamp(row, catalog, bindings)
    assert result.assertion_state == 'WITHDRAWN' and result.transaction_end == row['transaction_end']
    assert not result.complete_history_established


def test_real_encrypted_receipt_requires_both_keys_and_expected_metadata(source, keys, context):
    record = verify_recording_timestamp(*source)
    primary, backup = keys
    envelope = seal_recording_receipt(record, primary, backup, context)
    assert open_recording_receipt(envelope, primary, backup, record, context) == record
    assert START.isoformat() not in json.dumps(envelope) and str(OFFICER) not in json.dumps(envelope)


@pytest.mark.parametrize('failure', ['ciphertext', 'context', 'expected', 'backup', 'assurance'])
def test_receipt_tampering_wrong_context_and_false_assurance_rejected(source, keys, context, tmp_path, failure):
    record = verify_recording_timestamp(*source)
    primary, backup = keys
    envelope = seal_recording_receipt(record, primary, backup, context)
    if failure == 'ciphertext': envelope['ciphertext'] = 'AAAA'+envelope['ciphertext'][4:]
    elif failure == 'context': context = dict(context, binding_attempt_id='wrong-attempt')
    elif failure == 'expected': record = replace(record, transaction_start=START+timedelta(seconds=1))
    elif failure == 'backup':
        path = tmp_path/'wrong.json'
        data = json.loads((tmp_path/'backup.json').read_text())
        data['encryption_keys']['enc'] = base64.b64encode(b'Z'*32).decode()
        path.write_text(json.dumps(data)); backup = IdentityCrypto(path)
    else: record = replace(record, complete_history_established=True)
    with pytest.raises(Exception):
        open_recording_receipt(envelope, primary, backup, record, context)
