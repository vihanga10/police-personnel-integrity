"""Synthetic envelope/credential tests; real server denials use the separate checker."""
from datetime import timedelta
import json
import os
from bson import BSON
from bson.codec_options import CodecOptions
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest
from app.storage.check_srb_mongo import fixture
from app.storage.srb_mongo_contract import COLLECTION_POLICIES, encryption_context, privileges, validator
from app.storage.srb_mongo_connection import srb_password


@pytest.mark.parametrize('collection', list(COLLECTION_POLICIES))
def test_recovery_preserves_claims_after_bson_roundtrip(collection):
    doc, key, plain = fixture(collection)
    recovered = BSON.encode(doc).decode(codec_options=CodecOptions(tz_aware=True))
    cipher = bytes(recovered['payload_ciphertext'])
    payload = AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context(collection, recovered).encode())
    assert payload == plain
    fields = json.loads(payload)['fields']
    assert fields[0]['source_value'] == '00012' and fields[0]['value'] == '00012'
    assert fields[1]['value'] is None and fields[2]['value'] is True
    assert json.loads(payload)['authority_result'] is None
    assert json.loads(payload)['override_applied'] is False
    recovered['recorded_at'] += timedelta(milliseconds=1)
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context(collection, recovered).encode())


@pytest.mark.parametrize('field,value', [('_id', '00000000-0000-0000-0000-000000000000'),
    ('officer_uid', '00000000-0000-0000-0000-000000000000'),
    ('source_assertion_uid', '00000000-0000-0000-0000-000000000000'),
    ('raw_record_id', '0'*64), ('writer_policy', 'CHANGED'), ('classification', 'ORDINARY'),
    ('schema_version', 2), ('payload_key_version', 'CHANGED')])
def test_metadata_rebinding_rejected(field, value):
    doc, key, _ = fixture('police_number_intervals')
    cipher = bytes(doc['payload_ciphertext'])
    doc[field] = value
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context('police_number_intervals', doc).encode())


def test_copy_to_other_collection_and_ciphertext_tampering_rejected():
    doc, key, _ = fixture('police_number_intervals')
    cipher = bytes(doc['payload_ciphertext'])
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context('restriction_records', doc).encode())
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:-1]+bytes([cipher[-1]^1]), encryption_context('police_number_intervals', doc).encode())


def test_contract_has_only_opaque_metadata_and_separate_writer_policies():
    for name, policy in COLLECTION_POLICIES.items():
        contract = validator(name)['$and'][0]['$jsonSchema']
        assert contract['additionalProperties'] is False
        assert contract['properties']['writer_policy'] == {'enum': [policy]}
        assert contract['properties']['classification'] == {'enum': ['UNASSESSED']}
        assert contract['properties']['payload_ciphertext'] == {'bsonType': 'binData'}
        assert 'name' not in contract['properties'] and 'nic' not in contract['properties']
    # Mutating a returned validator cannot alter the next caller's contract.
    contract['properties']['writer_policy']['enum'].append('BAD')
    assert validator('restriction_records')['$and'][0]['$jsonSchema']['properties']['writer_policy']['enum'] == ['SRB_RESTRICTION_EVIDENCE_V1']
    assert {p['resource']['collection'] for p in privileges()} == set(COLLECTION_POLICIES)
    assert all(p['actions'] == ['find', 'insert'] for p in privileges())


def test_credentials_created_once_and_private(tmp_path):
    path = tmp_path / 'history'
    first = srb_password(path, create=True)
    assert srb_password(path, create=True) == first
    assert path.stat().st_mode & 0o077 == 0
    assert (path / 'credentials.json').stat().st_mode & 0o077 == 0
    assert len(first) >= 32


@pytest.mark.parametrize('target', ['directory', 'file'])
def test_permissive_credentials_rejected(tmp_path, target):
    path = tmp_path / 'history'
    srb_password(path, create=True)
    (path if target == 'directory' else path / 'credentials.json').chmod(0o755 if target == 'directory' else 0o644)
    with pytest.raises(ValueError):
        srb_password(path)


def test_symlinked_credentials_rejected(tmp_path):
    path = tmp_path / 'history'
    srb_password(path, create=True)
    (path / 'credentials.json').rename(path / 'original')
    os.symlink(path / 'original', path / 'credentials.json')
    with pytest.raises(ValueError):
        srb_password(path)


def test_srb_collection_scope_is_exact_and_unrecognized_destinations_fail():
    assert set(COLLECTION_POLICIES) == {'police_number_intervals', 'restriction_records', 'restriction_overrides'}
    for name in ('service_status_events', 'transfer_events', 'promotion_events', 'unknown'):
        with pytest.raises(ValueError):
            validator(name)


def test_credential_directories_cannot_be_shared(tmp_path):
    from app.storage.setup_srb_mongo import separate_directories
    with pytest.raises(ValueError):
        separate_directories(tmp_path / 'bootstrap', tmp_path / 'history', tmp_path / 'history')
    separate_directories(tmp_path / 'bootstrap', tmp_path / 'history', tmp_path / 'srb')
