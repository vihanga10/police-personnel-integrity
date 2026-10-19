"""Synthetic envelope/credential tests; real server denials use the separate checker."""
from datetime import timedelta
import json
import os
from bson import BSON
from bson.codec_options import CodecOptions
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest
from app.storage.check_remaining_mongo import fixture
from app.storage.remaining_mongo_contract import COLLECTION_POLICIES, encryption_context, privileges, validator
from app.storage.remaining_mongo_connection import remaining_password


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
    assert json.loads(payload)['reconstructed_state'] is None
    assert json.loads(payload)['competency_result'] is None
    assert json.loads(payload)['legal_effect'] is None
    recovered['recorded_at'] += timedelta(milliseconds=1)
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context(collection, recovered).encode())


@pytest.mark.parametrize('field,value', [('_id', '00000000-0000-0000-0000-000000000000'),
    ('officer_uid', '00000000-0000-0000-0000-000000000000'),
    ('source_assertion_uid', '00000000-0000-0000-0000-000000000000'),
    ('raw_record_id', '0'*64), ('writer_policy', 'CHANGED'), ('classification', 'ORDINARY'),
    ('schema_version', 2), ('payload_key_version', 'CHANGED')])
def test_metadata_rebinding_rejected(field, value):
    doc, key, _ = fixture('education_records')
    cipher = bytes(doc['payload_ciphertext'])
    doc[field] = value
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context('education_records', doc).encode())


def test_copy_to_other_collection_and_ciphertext_tampering_rejected():
    doc, key, _ = fixture('education_records')
    cipher = bytes(doc['payload_ciphertext'])
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context('operation_records', doc).encode())
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:-1]+bytes([cipher[-1]^1]), encryption_context('education_records', doc).encode())


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
    assert validator('operation_records')['$and'][0]['$jsonSchema']['properties']['writer_policy']['enum'] == ['PF_OPERATION_EVIDENCE_V1']
    assert {p['resource']['collection'] for p in privileges()} == set(COLLECTION_POLICIES)
    assert all(p['actions'] == ['find', 'insert'] for p in privileges())


def test_credentials_created_once_and_private(tmp_path):
    path = tmp_path / 'history'
    first = remaining_password(path, create=True)
    assert remaining_password(path, create=True) == first
    assert path.stat().st_mode & 0o077 == 0
    assert (path / 'credentials.json').stat().st_mode & 0o077 == 0
    assert len(first) >= 32


@pytest.mark.parametrize('target', ['directory', 'file'])
def test_permissive_credentials_rejected(tmp_path, target):
    path = tmp_path / 'history'
    remaining_password(path, create=True)
    (path if target == 'directory' else path / 'credentials.json').chmod(0o755 if target == 'directory' else 0o644)
    with pytest.raises(ValueError):
        remaining_password(path)


def test_symlinked_credentials_rejected(tmp_path):
    path = tmp_path / 'history'
    remaining_password(path, create=True)
    (path / 'credentials.json').rename(path / 'original')
    os.symlink(path / 'original', path / 'credentials.json')
    with pytest.raises(ValueError):
        remaining_password(path)


def test_srb_collection_scope_is_exact_and_unrecognized_destinations_fail():
    assert set(COLLECTION_POLICIES) == {'education_records', 'operation_records', 'court_records', 'complaint_records', 'demotion_events'}
    for name in ('service_status_events', 'transfer_events', 'promotion_events', 'unknown'):
        with pytest.raises(ValueError):
            validator(name)


def test_credential_directories_cannot_be_shared(tmp_path):
    from app.storage.setup_remaining_mongo import separate_directories
    with pytest.raises(ValueError):
        separate_directories(tmp_path / 'bootstrap', tmp_path / 'history', tmp_path / 'history')
    separate_directories(tmp_path / 'bootstrap', tmp_path / 'history', tmp_path / 'srb', tmp_path / 'remaining')


@pytest.mark.parametrize("change", [None, "broader_remaining", "broader_srb", "inherited_role", "extra_user"])
def test_exact_account_roles_do_not_widen_existing_access(change):
    from copy import deepcopy
    from app.storage import setup_remaining_mongo as setup
    definitions = {
        setup.SERVICE_ROLE: setup.service_privileges(), setup.HISTORY_ROLE: setup.history_privileges(),
        setup.SRB_ROLE: setup.srb_privileges(), setup.ACTIVITY_ROLE: setup.activity_privileges(), setup.ROLE: setup.privileges(),
    }
    roles = {name: dict(role=name, roles=[], privileges=deepcopy(actions)) for name, actions in definitions.items()}
    users = [dict(user=user, roles=[dict(role=role, db=setup.DATABASE)]) for user, role in (
        (setup.SERVICE_USER, setup.SERVICE_ROLE), (setup.HISTORY_USER, setup.HISTORY_ROLE),
        (setup.SRB_USER, setup.SRB_ROLE), (setup.ACTIVITY_USER, setup.ACTIVITY_ROLE), (setup.APP_USER, setup.ROLE))]
    if change in {"broader_remaining", "broader_srb"}:
        roles[setup.ROLE if change == "broader_remaining" else setup.SRB_ROLE]["privileges"][0]["actions"].append("update")
    elif change == "inherited_role":
        roles[setup.ROLE]["roles"] = [dict(role="readWrite", db=setup.DATABASE)]
    elif change == "extra_user":
        users.append(dict(user="unexpected", roles=[]))
    class Database:
        def command(self, kind, name, **kwargs):
            if kind == "usersInfo": return {"users": users}
            assert kind == "rolesInfo"
            return {"roles": list(roles.values()) if name == 1 else [roles[name]]}
    if change is None:
        assert setup.verify_accounts(Database(), require_remaining=True) == (True, True)
    else:
        with pytest.raises(RuntimeError):
            setup.verify_accounts(Database(), require_remaining=True)


@pytest.mark.parametrize("extra", [None, "expireAfterSeconds", "partialFilterExpression", "sparse", "hidden", "collation"])
def test_collection_index_contract_rejects_retention_and_filter_changes(extra):
    from app.storage.setup_remaining_mongo import verify_remaining_collection
    name = "education_records"
    indexes = [dict(name="_id_", key={"_id": 1}),
        dict(name="uq_source_policy", key={"raw_record_id": 1, "writer_policy": 1}, unique=True),
        dict(name="officer_evidence", key={"officer_uid": 1, "recorded_at": 1})]
    if extra: indexes[2][extra] = 1
    class Database:
        def list_collections(self, **kwargs):
            return [dict(type="collection", options=dict(validator=validator(name), validationLevel="strict", validationAction="error"))]
        def __getitem__(self, name): return self
        def list_indexes(self): return indexes
    if extra:
        with pytest.raises(RuntimeError): verify_remaining_collection(Database(), name)
    else:
        verify_remaining_collection(Database(), name)


@pytest.mark.parametrize('collection', list(COLLECTION_POLICIES))
def test_single_subject_metadata_matches_collection_semantics(collection):
    contract=validator(collection)['$and'][0]['$jsonSchema']['properties']['officer_uid']
    doc, _, _ = fixture(collection)
    if collection in {'operation_records','court_records'}:
        assert contract=={'bsonType':'null'} and doc['officer_uid'] is None
    else:
        assert contract['bsonType']=='string' and isinstance(doc['officer_uid'],str)


def test_remaining_writer_cannot_access_existing_collections():
    from app.storage.setup_remaining_mongo import EXISTING_COUNTS
    assert not set(EXISTING_COUNTS) & set(COLLECTION_POLICIES)
    assert len(EXISTING_COUNTS)==10
    assert all(p['actions']==['find','insert'] for p in privileges())
