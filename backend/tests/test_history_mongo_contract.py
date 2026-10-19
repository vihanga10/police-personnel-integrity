"""Synthetic envelope/credential tests; real server denials use the separate checker."""
from datetime import timedelta
import json
import os
from bson import BSON
from bson.codec_options import CodecOptions
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest
from app.storage.check_history_mongo import fixture
from app.storage.history_mongo_contract import COLLECTION_POLICIES, encryption_context, privileges, validator
from app.storage.history_mongo_connection import history_password


@pytest.mark.parametrize('collection', list(COLLECTION_POLICIES))
def test_recovery_preserves_review_and_cancellation_after_bson_roundtrip(collection):
    doc, key, plain = fixture(collection)
    recovered = BSON.encode(doc).decode(codec_options=CodecOptions(tz_aware=True))
    cipher = bytes(recovered['payload_ciphertext'])
    payload = AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context(collection, recovered).encode())
    assert payload == plain
    fields = json.loads(payload)['fields']
    assert fields[0]['source_value'] == '-12' and fields[0]['status'] == 'REVIEW_REQUIRED'
    assert fields[0]['value'] is None and fields[1]['value'] is True
    recovered['recorded_at'] += timedelta(milliseconds=1)
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context(collection, recovered).encode())


@pytest.mark.parametrize('field,value', [('_id', '00000000-0000-0000-0000-000000000000'),
    ('officer_uid', '00000000-0000-0000-0000-000000000000'),
    ('source_assertion_uid', '00000000-0000-0000-0000-000000000000'),
    ('raw_record_id', '0'*64), ('writer_policy', 'CHANGED'), ('classification', 'ORDINARY'),
    ('schema_version', 2), ('payload_key_version', 'CHANGED')])
def test_metadata_rebinding_rejected(field, value):
    doc, key, _ = fixture('transfer_events')
    cipher = bytes(doc['payload_ciphertext'])
    doc[field] = value
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context('transfer_events', doc).encode())


def test_copy_to_other_collection_and_ciphertext_tampering_rejected():
    doc, key, _ = fixture('transfer_events')
    cipher = bytes(doc['payload_ciphertext'])
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context('promotion_events', doc).encode())
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:-1]+bytes([cipher[-1]^1]), encryption_context('transfer_events', doc).encode())


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
    assert validator('promotion_events')['$and'][0]['$jsonSchema']['properties']['writer_policy']['enum'] == ['PF_PROMOTION_EVIDENCE_V1']
    assert {p['resource']['collection'] for p in privileges()} == set(COLLECTION_POLICIES)
    assert all(p['actions'] == ['find', 'insert'] for p in privileges())


def test_credentials_created_once_and_private(tmp_path):
    path = tmp_path / 'history'
    first = history_password(path, create=True)
    assert history_password(path, create=True) == first
    assert path.stat().st_mode & 0o077 == 0
    assert (path / 'credentials.json').stat().st_mode & 0o077 == 0
    assert len(first) >= 32


@pytest.mark.parametrize('target', ['directory', 'file'])
def test_permissive_credentials_rejected(tmp_path, target):
    path = tmp_path / 'history'
    history_password(path, create=True)
    (path if target == 'directory' else path / 'credentials.json').chmod(0o755 if target == 'directory' else 0o644)
    with pytest.raises(ValueError):
        history_password(path)


def test_symlinked_credentials_rejected(tmp_path):
    path = tmp_path / 'history'
    history_password(path, create=True)
    (path / 'credentials.json').rename(path / 'original')
    os.symlink(path / 'original', path / 'credentials.json')
    with pytest.raises(ValueError):
        history_password(path)
