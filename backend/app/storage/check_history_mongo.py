"""Real-driver history protections, using only isolated disposable test evidence."""
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
from app.storage.history_mongo_connection import history_password, history_client
from app.storage.history_mongo_contract import COLLECTION_POLICIES, DATABASE, ROLE, encryption_context, privileges
from app.storage.mongo_connection import client, load_credentials
from app.storage.setup_history_mongo import create_history_collection, verify_history_collection, verify_accounts
from app.storage.setup_mongo import verify_collection as verify_service_collection


def fixture(collection):
    doc = dict(_id=str(uuid.uuid4()), officer_uid=str(uuid.uuid4()),
               source_assertion_uid=str(uuid.uuid4()), raw_record_id=secrets.token_hex(32),
               writer_policy=COLLECTION_POLICIES[collection], schema_version=1,
               classification='UNASSESSED', recorded_at=datetime.now(timezone.utc),
               payload_key_version='EPHEMERAL_TEST_ONLY')
    # Negative duration and cancellation claims stay encrypted with their review flags.
    # This fixture contains no research officer values and uses no production key.
    payload = dict(synthetic=True, valid_from=None, valid_to=None, fields=[
        dict(source_column='days_in_previous_posting', source_value='-12', value=None, status='REVIEW_REQUIRED'),
        dict(source_column='is_cancelled', source_value='TRUE', value=True, status='PARSED')])
    plain = json.dumps(payload, sort_keys=True).encode()
    key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
    doc['payload_ciphertext'] = Binary(nonce + AESGCM(key).encrypt(nonce, plain, encryption_context(collection, doc).encode()))
    return doc, key, plain


def denied_mutations(database, name):
    collection = database[name]
    # A nonmatching filter cannot change research evidence, even if a denial fails.
    expect_code(lambda: collection.update_one({'_id': 'SYNTHETIC-NONMATCH'}, {'$set': {'classification': 'ORDINARY'}}), 13)
    expect_code(lambda: collection.delete_one({'_id': 'SYNTHETIC-NONMATCH'}), 13)
    expect_code(lambda: database.command('collMod', name, validationAction='warn'), 13)
    # The invalid envelope cannot enter a strict collection even if bypass is denied incorrectly.
    expect_code(lambda: collection.insert_one({'_id': 'SYNTHETIC-BYPASS'}, bypass_document_validation=True), 13)


def counts(database):
    return {name: database[name].count_documents({})
            for name in ('service_status_events', *COLLECTION_POLICIES)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap-credential-directory', required=True)
    parser.add_argument('--history-credential-directory', required=True)
    args = parser.parse_args()
    from pathlib import Path
    if Path(args.bootstrap_credential_directory).expanduser().resolve() == Path(args.history_credential_directory).expanduser().resolve():
        raise ValueError('Use a separate private history credential directory.')
    root, service_password = load_credentials(args.bootstrap_credential_directory)
    password = history_password(args.history_credential_directory)
    sandbox = 'police_history_smoke_' + uuid.uuid4().hex
    smoke_password = secrets.token_urlsafe(48)
    with client(root, bootstrap=True) as bootstrap:
        database = bootstrap[DATABASE]
        verify_service_collection(database)
        verify_accounts(database, require_history=True)
        for name in COLLECTION_POLICIES:
            verify_history_collection(database, name)
        before = counts(database)
        if before != {'service_status_events': 6596, 'transfer_events': 0, 'promotion_events': 0}:
            raise RuntimeError('Counts differ from the history foundation checkpoint.')
        with history_client(password) as history:
            for name in COLLECTION_POLICIES:
                if history[DATABASE][name].count_documents({}) != 0:
                    raise RuntimeError('History account count differs.')
                denied_mutations(history[DATABASE], name)
            expect_code(lambda: history[DATABASE].service_status_events.find_one({}), 13)
        with client(service_password) as service:
            for name in COLLECTION_POLICIES:
                expect_code(lambda name=name: service[DATABASE][name].find_one({}), 13)
        test_database = bootstrap[sandbox]
        try:
            for name in COLLECTION_POLICIES:
                create_history_collection(test_database, name)
                verify_history_collection(test_database, name)
            test_database.command('createRole', ROLE, privileges=privileges(sandbox), roles=[])
            test_database.command('createUser', 'smoke_history_app', pwd=smoke_password, roles=[{'role': ROLE, 'db': sandbox}])
            with MongoClient('127.0.0.1', 27018, username='smoke_history_app', password=smoke_password,
                             authSource=sandbox, serverSelectionTimeoutMS=5000, socketTimeoutMS=10000,
                             tz_aware=True, retryWrites=False) as smoke:
                for name in COLLECTION_POLICIES:
                    doc, key, plain = fixture(name)
                    collection = smoke[sandbox][name]
                    collection.insert_one(doc)
                    recovered = collection.find_one({'_id': doc['_id']})
                    cipher = bytes(recovered['payload_ciphertext'])
                    if AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context(name, recovered).encode()) != plain:
                        raise RuntimeError('Historical encryption recovery differs.')
                    # Extra plaintext, wrong classifications/policies and malformed ciphertext are rejected.
                    for changes in ({'name': 'SYNTHETIC'}, {'classification': 'ORDINARY'},
                                    {'writer_policy': 'HR_SERVICE_EVIDENCE_V1'},
                                    {'payload_ciphertext': Binary(b'short')}, {'payload_ciphertext': 'plaintext'}):
                        bad = dict(doc, _id=str(uuid.uuid4()), raw_record_id=secrets.token_hex(32), **changes)
                        expect_code(lambda bad=bad: collection.insert_one(bad), 121)
                    expect_code(lambda: collection.insert_one(dict(doc, _id=str(uuid.uuid4()))), 11000)
                    denied_mutations(smoke[sandbox], name)
                    # Destructive/schema operations are tested ONLY on disposable fixtures.
                    expect_code(lambda: collection.drop(), 13)
                    expect_code(lambda: collection.create_index('officer_uid'), 13)
                    if collection.count_documents({}) != 1:
                        raise RuntimeError('Synthetic fixture count changed.')
        finally:
            # Never remove research collections, users, evidence or Docker volumes.
            if sandbox.startswith('police_history_smoke_') and sandbox != DATABASE:
                test_database.command('dropAllUsersFromDatabase', 1)
                test_database.command('dropAllRolesFromDatabase', 1)
                bootstrap.drop_database(sandbox)
        if counts(database) != before:
            raise RuntimeError('Research counts changed during the storage check.')
    print('Historical Mongo storage checks: PASSED')
    print('Both collections: encrypted recovery, strict validation and duplicate rejection verified.')
    print('History update/delete, validation bypass and schema changes denied.')
    print('Service/history account separation verified; isolated test database removed.')
    print('Research counts unchanged:', json.dumps(before, sort_keys=True))
    print('No historical import, personnel values or production encryption keys used.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('History storage check stopped: ' + type(error).__name__ + '. Do not import historical evidence.') from None
