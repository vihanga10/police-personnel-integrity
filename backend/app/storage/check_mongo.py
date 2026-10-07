"""Check real account restrictions and an isolated synthetic encryption fixture."""
import argparse
from datetime import datetime, timezone
import os
import secrets
import uuid
from bson import Binary
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pymongo import MongoClient
from pymongo.errors import OperationFailure
from app.storage.mongo_connection import client, load_credentials
from app.storage.mongo_contract import APP_USER, COLLECTION, DATABASE, ROLE, encryption_context, privileges, validator
from app.storage.setup_mongo import verify_collection, verify_role


def expect_code(action, code):
    """Require the specific server denial, not a connection/client-side error."""
    try:
        action()
    except OperationFailure as error:
        if error.code == code:
            return
        raise RuntimeError("Unexpected server failure code.") from None
    raise RuntimeError("Server accepted a prohibited action.")


def fixture():
    doc = {"_id": str(uuid.uuid4()), "officer_uid": str(uuid.uuid4()),
           "source_assertion_uid": str(uuid.uuid4()), "raw_record_id": secrets.token_hex(32),
           "writer_policy": "HR_SERVICE_EVIDENCE_V1", "schema_version": 1,
           "classification": "UNASSESSED", "recorded_at": datetime.now(timezone.utc),
           "payload_key_version": "EPHEMERAL_TEST_ONLY"}
    key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
    # No personnel values or production keys enter this synthetic test.
    doc["payload_ciphertext"] = Binary(nonce + AESGCM(key).encrypt(
        nonce, b'{"synthetic":true}', encryption_context(doc).encode()))
    return doc, key


def denied_mutations(database):
    # Match no research records. Authorization must still reject each command.
    collection = database[COLLECTION]
    expect_code(lambda: collection.update_one({"_id": "SYNTHETIC-NONMATCH"}, {"$set": {"classification": "ORDINARY"}}), 13)
    expect_code(lambda: collection.delete_one({"_id": "SYNTHETIC-NONMATCH"}), 13)
    expect_code(lambda: database.command("collMod", COLLECTION, validationAction="warn"), 13)
    expect_code(lambda: collection.insert_one({"_id": "SYNTHETIC-BYPASS"}, bypass_document_validation=True), 13)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credential-directory", required=True)
    args = parser.parse_args()
    root, app = load_credentials(args.credential_directory)
    # Unique disposable namespace is unrelated to research data and contains no PII.
    sandbox = "police_storage_smoke_" + uuid.uuid4().hex
    smoke_password = secrets.token_urlsafe(48)
    with client(root, bootstrap=True) as bootstrap:
        database = bootstrap[DATABASE]
        verify_collection(database)
        verify_role(database, ROLE, privileges())
        account = database.command("usersInfo", APP_USER)["users"]
        if len(account) != 1 or account[0]["roles"] != [{"role": ROLE, "db": DATABASE}]:
            raise RuntimeError("Unexpected application permissions.")
        with client(app) as application:
            before = application[DATABASE][COLLECTION].count_documents({})
            denied_mutations(application[DATABASE])
        test_database = bootstrap[sandbox]
        try:
            test_database.create_collection(COLLECTION, validator=validator(), validationLevel="strict", validationAction="error")
            test_database[COLLECTION].create_index([("raw_record_id", 1), ("writer_policy", 1)], unique=True, name="uq_source_policy")
            test_database.command("createRole", ROLE, privileges=privileges(sandbox), roles=[])
            test_database.command("createUser", "smoke_app", pwd=smoke_password, roles=[{"role": ROLE, "db": sandbox}])
            with MongoClient("127.0.0.1", 27018, username="smoke_app", password=smoke_password,
                             authSource=sandbox, serverSelectionTimeoutMS=5000, socketTimeoutMS=10000,
                             tz_aware=True, retryWrites=False) as smoke:
                doc, key = fixture()
                collection = smoke[sandbox][COLLECTION]
                collection.insert_one(doc)
                recovered = collection.find_one({"_id": doc["_id"]})
                cipher = bytes(recovered["payload_ciphertext"])
                if AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context(recovered).encode()) != b'{"synthetic":true}':
                    raise RuntimeError("Encryption recovery failed.")
                # Unknown plaintext fields and undersized ciphertext must be rejected.
                for changes in ({"name": "SYNTHETIC"}, {"payload_ciphertext": Binary(b"short")}, {"payload_ciphertext": "plaintext"}):
                    bad = dict(doc, _id=str(uuid.uuid4()), raw_record_id=secrets.token_hex(32), **changes)
                    expect_code(lambda bad=bad: collection.insert_one(bad), 121)
                duplicate = dict(doc, _id=str(uuid.uuid4()))
                expect_code(lambda: collection.insert_one(duplicate), 11000)
                denied_mutations(smoke[sandbox])
                expect_code(lambda: collection.drop(), 13)
                expect_code(lambda: collection.create_index("officer_uid"), 13)
                if collection.count_documents({}) != 1:
                    raise RuntimeError("Synthetic evidence changed unexpectedly.")
        finally:
            # Cleanup is restricted to this freshly generated synthetic database.
            # Personnel evidence, research users, roles and volumes are never removed.
            if sandbox.startswith("police_storage_smoke_") and sandbox != DATABASE:
                test_database.command("dropAllUsersFromDatabase", 1)
                test_database.command("dropAllRolesFromDatabase", 1)
                bootstrap.drop_database(sandbox)
        with client(app) as application:
            if application[DATABASE][COLLECTION].count_documents({}) != before:
                raise RuntimeError("Research count changed during smoke check.")
    print("Mongo storage smoke checks: PASSED")
    print("Authenticated read/insert, encryption recovery, strict validation and duplicate rejection verified.")
    print("Application update/delete, schema changes and validation bypass denied.")
    print("Isolated synthetic fixtures removed; research document count unchanged:", before)
    print("No personnel values displayed; no production encryption keys used.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        reason = str(error) if type(error) is RuntimeError else type(error).__name__
        raise SystemExit("Mongo storage check stopped: " + reason + " Do not import personnel evidence.") from None
