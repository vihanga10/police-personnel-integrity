"""Real-driver reference protections, using only isolated disposable test evidence."""
import argparse
from datetime import datetime, timezone
import json
import os
import secrets
import uuid
from bson import Binary
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pymongo import MongoClient
from app.storage.check_mongo import expect_code
from app.storage.reference_mongo_connection import reference_password, reference_client
from app.storage.reference_mongo_contract import COLLECTION_POLICIES, DATABASE, ROLE, encryption_context, privileges
from app.storage.mongo_connection import client, load_credentials
from app.storage.setup_reference_mongo import create_reference_collection, verify_reference_collection, verify_accounts, verify_existing, EXISTING_COUNTS, arguments, credentials, existing_readers
from app.storage.history_mongo_connection import history_password, history_client
from app.storage.srb_mongo_connection import srb_password, srb_client
from app.storage.activity_mongo_connection import activity_password, activity_client


def fixture(collection):
    doc = dict(_id=str(uuid.uuid4()), source_assertion_uid=str(uuid.uuid4()), raw_record_id=secrets.token_hex(32),
        writer_policy=COLLECTION_POLICIES[collection], schema_version=1, classification='UNASSESSED',
        recorded_at=datetime.now(timezone.utc), payload_key_version='EPHEMERAL_TEST_ONLY')
    # Disposable fixtures contain no research station or personnel values.
    payload = dict(synthetic=True, valid_from=None, valid_to=None, accepted_station_uid=None,
        linkage_accepted=False, authority_result=None, fields=[
        dict(source_column='station_code', source_value='00012', value='00012', status='PRESERVED'),
        dict(source_column='Province ', source_value='  EXAMPLE  ', value='  EXAMPLE  ', status='PRESERVED'),
        dict(source_column='Latitude', source_value='', value='', status='MISSING')])
    plain = json.dumps(payload, sort_keys=True).encode()
    key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
    doc['payload_ciphertext'] = Binary(nonce + AESGCM(key).encrypt(nonce, plain, encryption_context(collection, doc).encode()))
    return doc, key, plain


def denied_mutations(database, name, *, disposable=False):
    collection = database[name]
    # A nonmatching filter cannot change research evidence, even if a denial fails.
    expect_code(lambda: collection.update_one({'_id': 'SYNTHETIC-NONMATCH'}, {'$set': {'classification': 'ORDINARY'}}), 13)
    expect_code(lambda: collection.delete_one({'_id': 'SYNTHETIC-NONMATCH'}), 13)
    if disposable:
        # Schema and bypass denials are exercised only on disposable fixtures.
        expect_code(lambda: database.command('collMod', name, validationAction='warn'), 13)
        expect_code(lambda: collection.insert_one({'_id': 'SYNTHETIC-BYPASS'}, bypass_document_validation=True), 13)


def counts(database):
    return {name: database[name].count_documents({})
            for name in (*EXISTING_COUNTS, *COLLECTION_POLICIES)}


def main():
    args = arguments(argparse.ArgumentParser(description=__doc__))
    root, service_password, history_secret, srb_secret, activity_secret, remaining_secret, password = credentials(args)
    sandbox = 'police_ref_smoke_' + uuid.uuid4().hex
    smoke_password = secrets.token_urlsafe(48)
    with client(root, bootstrap=True) as bootstrap:
        database = bootstrap[DATABASE]
        verify_existing(database)
        verify_accounts(database, require_reference=True)
        for name in COLLECTION_POLICIES:
            verify_reference_collection(database, name)
        before = counts(database)
        if before != dict(EXISTING_COUNTS, **{name: 0 for name in COLLECTION_POLICIES}):
            raise RuntimeError('Counts differ from the reference foundation checkpoint.')
        with reference_client(password) as srb:
            for name in COLLECTION_POLICIES:
                if srb[DATABASE][name].count_documents({}) != 0:
                    raise RuntimeError('Reference account count differs.')
                denied_mutations(srb[DATABASE], name)
            for name in EXISTING_COUNTS:
                expect_code(lambda name=name: srb[DATABASE][name].find_one({}), 13)
        with client(service_password) as service:
            for name in COLLECTION_POLICIES:
                expect_code(lambda name=name: service[DATABASE][name].find_one({}), 13)
        with history_client(history_secret) as history_reader:
            for name in COLLECTION_POLICIES:
                expect_code(lambda name=name: history_reader[DATABASE][name].find_one({}), 13)
        with srb_client(srb_secret) as old_srb:
            for name in COLLECTION_POLICIES:
                expect_code(lambda name=name: old_srb[DATABASE][name].find_one({}), 13)
        with activity_client(activity_secret) as old_activity:
            for name in COLLECTION_POLICIES:
                expect_code(lambda name=name: old_activity[DATABASE][name].find_one({}), 13)
        from app.storage.remaining_mongo_connection import remaining_client
        with remaining_client(remaining_secret) as old_remaining:
            for name in COLLECTION_POLICIES:
                expect_code(lambda name=name: old_remaining[DATABASE][name].find_one({}), 13)
        test_database = bootstrap[sandbox]
        try:
            for name in COLLECTION_POLICIES:
                create_reference_collection(test_database, name)
                verify_reference_collection(test_database, name)
            test_database.command('createRole', ROLE, privileges=privileges(sandbox), roles=[])
            test_database.command('createUser', 'smoke_reference_app', pwd=smoke_password, roles=[{'role': ROLE, 'db': sandbox}])
            with MongoClient('127.0.0.1', 27018, username='smoke_reference_app', password=smoke_password,
                             authSource=sandbox, serverSelectionTimeoutMS=5000, socketTimeoutMS=10000,
                             tz_aware=True, retryWrites=False) as smoke:
                for name in COLLECTION_POLICIES:
                    doc, key, plain = fixture(name)
                    collection = smoke[sandbox][name]
                    collection.insert_one(doc)
                    recovered = collection.find_one({'_id': doc['_id']})
                    cipher = bytes(recovered['payload_ciphertext'])
                    if AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context(name, recovered).encode()) != plain:
                        raise RuntimeError('Reference encryption recovery differs.')
                    # Extra plaintext, wrong classifications/policies and malformed ciphertext are rejected.
                    for changes in ({'name': 'SYNTHETIC'}, {'classification': 'ORDINARY'},
                                    {'writer_policy': 'HR_SERVICE_EVIDENCE_V1'},
                                    {'payload_ciphertext': Binary(b'short')}, {'payload_ciphertext': 'plaintext'}):
                        bad = {**doc, '_id': str(uuid.uuid4()), 'raw_record_id': secrets.token_hex(32), 'source_assertion_uid': str(uuid.uuid4()), **changes}
                        expect_code(lambda bad=bad: collection.insert_one(bad), 121)
                    # A station reference must never acquire officer metadata or plaintext codes.
                    for changes in ({'officer_uid': str(uuid.uuid4())}, {'station_code': '00012'},
                                    {'source_assertion_uid': 'invalid'}, {'raw_record_id': 'invalid'},
                                    {'schema_version': 2}, {'payload_key_version': ''}):
                        bad = {**doc, '_id': str(uuid.uuid4()), 'raw_record_id': secrets.token_hex(32), 'source_assertion_uid': str(uuid.uuid4()), **changes}
                        expect_code(lambda bad=bad: collection.insert_one(bad), 121)
                    # Test raw-row/policy and assertion uniqueness independently.
                    expect_code(lambda: collection.insert_one(dict(doc, _id=str(uuid.uuid4()), source_assertion_uid=str(uuid.uuid4()))), 11000)
                    expect_code(lambda: collection.insert_one(dict(doc, _id=str(uuid.uuid4()), raw_record_id=secrets.token_hex(32))), 11000)
                    denied_mutations(smoke[sandbox], name, disposable=True)
                    # Destructive/schema operations are tested ONLY on disposable fixtures.
                    expect_code(lambda: collection.drop(), 13)
                    expect_code(lambda: collection.create_index('station_code'), 13)
                    if collection.count_documents({}) != 1:
                        raise RuntimeError('Synthetic fixture count changed.')
        finally:
            # Never remove research collections, users, evidence or Docker volumes.
            if sandbox.startswith('police_ref_smoke_') and sandbox != DATABASE:
                test_database.command('dropAllUsersFromDatabase', 1)
                test_database.command('dropAllRolesFromDatabase', 1)
                bootstrap.drop_database(sandbox)
        if counts(database) != before:
            raise RuntimeError('Research counts changed during the storage check.')
        verify_existing(database)
        verify_accounts(database, require_reference=True)
        for name in COLLECTION_POLICIES:
            verify_reference_collection(database, name)
    print('Reference Mongo storage checks: PASSED')
    print('Both collections: encrypted recovery, strict validation and duplicate rejection verified.')
    print('Reference update/delete, validation bypass and schema changes denied.')
    print('Service/history/SRB/activity/remaining/reference account separation verified; isolated test database removed.')
    print('Research counts unchanged:', json.dumps(before, sort_keys=True))
    print('No reference import, personnel values or production encryption keys used.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('Reference storage check stopped: ' + type(error).__name__ + '. Do not import reference evidence.') from None
