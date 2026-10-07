"""Real-driver SRB protections, using only isolated disposable test evidence."""
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
from app.storage.activity_mongo_connection import activity_password, activity_client
from app.storage.activity_mongo_contract import COLLECTION_POLICIES, DATABASE, ROLE, encryption_context, privileges
from app.storage.mongo_connection import client, load_credentials
from app.storage.setup_activity_mongo import create_activity_collection, verify_activity_collection, verify_accounts, verify_existing, EXISTING_COUNTS, separate_directories
from app.storage.history_mongo_connection import history_password, history_client
from app.storage.srb_mongo_connection import srb_password, srb_client


def fixture(collection):
    doc = dict(_id=str(uuid.uuid4()), officer_uid=str(uuid.uuid4()),
               source_assertion_uid=str(uuid.uuid4()), raw_record_id=secrets.token_hex(32),
               writer_policy=COLLECTION_POLICIES[collection], schema_version=1,
               classification='UNASSESSED', recorded_at=datetime.now(timezone.utc),
               payload_key_version='EPHEMERAL_TEST_ONLY')
    # Synthetic claims model source IDs, missing H2 and unverified conduct flags.
    # This fixture uses ephemeral keys and contains no research officer values.
    payload = dict(synthetic=True, valid_from=None, valid_to=None, authority_result=None,
        reconstructed_state=None, competency_result=None, legal_effect=None, fields=[
        dict(source_column='period_id', source_value='00012', value='00012', status='PARSED'),
        dict(source_column='h2_total_points', source_value='', value=None, status='MISSING'),
        dict(source_column='accused_arrested', source_value='TRUE', value=True, status='PARSED')])
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap-credential-directory', required=True)
    parser.add_argument('--history-credential-directory', required=True)
    parser.add_argument('--srb-credential-directory', required=True)
    parser.add_argument('--activity-credential-directory', required=True)
    args = parser.parse_args()
    separate_directories(args.bootstrap_credential_directory, args.history_credential_directory, args.srb_credential_directory, args.activity_credential_directory)
    root, service_password = load_credentials(args.bootstrap_credential_directory)
    history_secret = history_password(args.history_credential_directory)
    srb_secret = srb_password(args.srb_credential_directory)
    password = activity_password(args.activity_credential_directory)
    sandbox = 'police_activity_smoke_' + uuid.uuid4().hex
    smoke_password = secrets.token_urlsafe(48)
    with client(root, bootstrap=True) as bootstrap:
        database = bootstrap[DATABASE]
        verify_existing(database)
        verify_accounts(database, require_activity=True)
        for name in COLLECTION_POLICIES:
            verify_activity_collection(database, name)
        before = counts(database)
        if before != dict(EXISTING_COUNTS, **{name: 0 for name in COLLECTION_POLICIES}):
            raise RuntimeError('Counts differ from the activity foundation checkpoint.')
        with activity_client(password) as srb:
            for name in COLLECTION_POLICIES:
                if srb[DATABASE][name].count_documents({}) != 0:
                    raise RuntimeError('SRB account count differs.')
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
        test_database = bootstrap[sandbox]
        try:
            for name in COLLECTION_POLICIES:
                create_activity_collection(test_database, name)
                verify_activity_collection(test_database, name)
            test_database.command('createRole', ROLE, privileges=privileges(sandbox), roles=[])
            test_database.command('createUser', 'smoke_activity_app', pwd=smoke_password, roles=[{'role': ROLE, 'db': sandbox}])
            with MongoClient('127.0.0.1', 27018, username='smoke_activity_app', password=smoke_password,
                             authSource=sandbox, serverSelectionTimeoutMS=5000, socketTimeoutMS=10000,
                             tz_aware=True, retryWrites=False) as smoke:
                for name in COLLECTION_POLICIES:
                    doc, key, plain = fixture(name)
                    collection = smoke[sandbox][name]
                    collection.insert_one(doc)
                    recovered = collection.find_one({'_id': doc['_id']})
                    cipher = bytes(recovered['payload_ciphertext'])
                    if AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context(name, recovered).encode()) != plain:
                        raise RuntimeError('Activity encryption recovery differs.')
                    # Extra plaintext, wrong classifications/policies and malformed ciphertext are rejected.
                    for changes in ({'name': 'SYNTHETIC'}, {'classification': 'ORDINARY'},
                                    {'writer_policy': 'HR_SERVICE_EVIDENCE_V1'},
                                    {'payload_ciphertext': Binary(b'short')}, {'payload_ciphertext': 'plaintext'}):
                        bad = dict(doc, _id=str(uuid.uuid4()), raw_record_id=secrets.token_hex(32), **changes)
                        expect_code(lambda bad=bad: collection.insert_one(bad), 121)
                    expect_code(lambda: collection.insert_one(dict(doc, _id=str(uuid.uuid4()))), 11000)
                    denied_mutations(smoke[sandbox], name, disposable=True)
                    # Destructive/schema operations are tested ONLY on disposable fixtures.
                    expect_code(lambda: collection.drop(), 13)
                    expect_code(lambda: collection.create_index('officer_uid'), 13)
                    if collection.count_documents({}) != 1:
                        raise RuntimeError('Synthetic fixture count changed.')
        finally:
            # Never remove research collections, users, evidence or Docker volumes.
            if sandbox.startswith('police_activity_smoke_') and sandbox != DATABASE:
                test_database.command('dropAllUsersFromDatabase', 1)
                test_database.command('dropAllRolesFromDatabase', 1)
                bootstrap.drop_database(sandbox)
        if counts(database) != before:
            raise RuntimeError('Research counts changed during the storage check.')
    print('Activity Mongo storage checks: PASSED')
    print('All four collections: encrypted recovery, strict validation and duplicate rejection verified.')
    print('Activity update/delete, validation bypass and schema changes denied.')
    print('Service/history/SRB/activity account separation verified; isolated test database removed.')
    print('Research counts unchanged:', json.dumps(before, sort_keys=True))
    print('No activity import, personnel values or production encryption keys used.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('Activity storage check stopped: ' + type(error).__name__ + '. Do not import activity evidence.') from None
