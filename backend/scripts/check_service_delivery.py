"""Real driver recovery checks with rollback-only SQL and isolated synthetic Mongo.

SQL savepoints exercise transaction bodies, not independent durable commits.
The batch importer separately verifies actual SQL commits via fresh connections.
No research Mongo writes, personnel decryption or production encryption keys.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from sqlalchemy import URL, create_engine, func, select, text
from sqlalchemy.pool import NullPool
from pymongo import MongoClient
from pymongo.errors import AutoReconnect
from uuid import UUID, uuid4
from app.identity.service_delivery import deliver, reconcile
from app.identity.service_sql_ledger import DONE, PREP, completion_on_connection, prepare_on_connection
from app.identity.registration_service import REGISTRATION_LOCK
from app.security.identity_crypto import IdentityCrypto
from app.storage.mongo_connection import client, load_credentials
from app.storage.mongo_contract import APP_USER, COLLECTION, DATABASE, ROLE, privileges, validator
from app.storage.setup_mongo import verify_collection, verify_role
from migration_settings import MigrationSettings
from scripts.check_service_storage import counts, fixture, require


def delivery_counts(connection):
    return tuple(connection.execute(select(func.count()).select_from(table)).scalar_one() for table in (PREP, DONE))


class RollbackLedger:
    """Checker-only adapter: SQL remains inside the outer rollback transaction."""
    def __init__(self, connection, kwargs, failure):
        self.connection, self.kwargs, self.failure = connection, kwargs, failure

    def interrupt(self, point):
        if self.failure == point:
            self.failure = None
            raise AutoReconnect("Injected lost acknowledgment")

    def prepare_once(self, proposed):
        with self.connection.begin_nested():
            saved = prepare_on_connection(self.connection, proposed, **self.kwargs)
        self.interrupt("after_prepare")
        return saved

    def completion_digest(self, event_id):
        return self.connection.execute(select(DONE.c.document_sha256).where(DONE.c.delivery_id == UUID(event_id))).scalar_one_or_none()

    def complete_once(self, prepared):
        self.interrupt("before_receipt")
        with self.connection.begin_nested():
            digest = completion_on_connection(self.connection, prepared)
        self.interrupt("after_receipt")
        return digest


class InterruptedMongo:
    """Delegate to the real Mongo collection, injecting transport failures only."""
    def __init__(self, collection, failure):
        self.collection, self.failure = collection, failure

    def find_one(self, query):
        return self.collection.find_one(query)

    def insert_one(self, document):
        if self.failure == "before_mongo":
            self.failure = None
            raise AutoReconnect("Injected transport failure")
        result = self.collection.insert_one(document)
        if self.failure == "after_mongo":
            self.failure = None
            raise AutoReconnect("Injected lost Mongo acknowledgment")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mongo-credential-directory", required=True)
    args = parser.parse_args()
    settings = MigrationSettings()
    require((settings.host, settings.port, settings.user, settings.name) == ("127.0.0.1", 5432, "police_identity_migrator", "police_identity"), "Unexpected SQL target.")
    engine = create_engine(URL.create("postgresql+psycopg", username=settings.user, password=settings.password.get_secret_value(),
        host=settings.host, port=settings.port, database=settings.name), poolclass=NullPool, hide_parameters=True,
        connect_args={"connect_timeout": 5})
    try:
        root, app = load_credentials(args.mongo_credential_directory)
        with client(app) as research:
            mongo_before = research[DATABASE][COLLECTION].count_documents({})
        # Only bootstrap can create and remove isolated test namespaces/accounts.
        sandbox = "police_delivery_smoke_" + uuid4().hex
        password = secrets.token_urlsafe(48)
        baseline = None
        cases = 0
        with client(root, bootstrap=True) as bootstrap:
            verify_collection(bootstrap[DATABASE])
            verify_role(bootstrap[DATABASE], ROLE, privileges())
            accounts = bootstrap[DATABASE].command("usersInfo", APP_USER)["users"]
            require(len(accounts) == 1 and accounts[0]["roles"] == [{"role": ROLE, "db": DATABASE}], "Unexpected research Mongo account assignment.")
            test = bootstrap[sandbox]
            try:
                test.create_collection(COLLECTION, validator=validator(), validationLevel="strict", validationAction="error")
                test[COLLECTION].create_index([("raw_record_id", 1), ("writer_policy", 1)], unique=True, name="uq_source_policy")
                test[COLLECTION].create_index([("officer_uid", 1), ("recorded_at", 1)], name="officer_evidence")
                verify_collection(test)
                test.command("createRole", ROLE, privileges=privileges(sandbox), roles=[])
                test.command("createUser", "delivery_smoke_app", pwd=password, roles=[{"role": ROLE, "db": sandbox}])
                with tempfile.TemporaryDirectory() as directory:
                    key = base64.b64encode(os.urandom(32)).decode()
                    material = dict(active_encryption_key_version="EPHEMERAL", active_lookup_key_version="EPHEMERAL",
                                    encryption_keys={"EPHEMERAL": key}, lookup_keys={"EPHEMERAL": key})
                    paths = [Path(directory) / p for p in ("primary.json", "backup.json")]
                    for path in paths:
                        path.write_text(json.dumps(material)); path.chmod(0o600)
                    crypto, backup = (IdentityCrypto(p) for p in paths)
                    with MongoClient("127.0.0.1", 27018, username="delivery_smoke_app", password=password, authSource=sandbox,
                                     tz_aware=True, retryWrites=False, serverSelectionTimeoutMS=5000, socketTimeoutMS=10000) as smoke:
                        with engine.connect() as connection:
                            outer = connection.begin()
                            try:
                                connection.execute(text("SET LOCAL lock_timeout = '5s'"))
                                connection.execute(text("SET LOCAL statement_timeout = '30s'"))
                                connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": REGISTRATION_LOCK})
                                require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalars().all() == ["f73a0c94de21"], "Unexpected applied service revision.")
                                baseline = counts(connection)
                                delivery_baseline = delivery_counts(connection)
                                for failure in ("after_prepare", "before_mongo", "after_mongo", "before_receipt", "after_receipt"):
                                    case = connection.begin_nested()
                                    try:
                                        binding, payload, candidate = fixture(connection, crypto, backup)
                                        kwargs = dict(crypto=crypto, backup=backup, binding=binding, expected_payload=payload)
                                        ledger = RollbackLedger(connection, kwargs, failure)
                                        collection = InterruptedMongo(smoke[sandbox][COLLECTION], failure)
                                        delivery_args = dict(crypto=crypto, backup=backup, expected_payload=payload)
                                        try:
                                            deliver(ledger, collection, candidate(), **delivery_args)
                                        except AutoReconnect:
                                            pass
                                        else:
                                            raise RuntimeError("Failure injection did not interrupt delivery.")
                                        deliver(ledger, collection, candidate(), **delivery_args)
                                        saved = prepare_on_connection(connection, candidate(), **kwargs)
                                        require(reconcile(ledger, collection, saved, **delivery_args) == "VERIFIED_EXISTING", "Real driver reconciliation differs.")
                                        require(deliver(ledger, collection, candidate(), **delivery_args) == "VERIFIED_EXISTING", "Real driver replay differs.")
                                        require(smoke[sandbox][COLLECTION].count_documents({"raw_record_id": binding.raw_record_id}) == 1, "Mongo fixture duplicated.")
                                        require(connection.execute(select(DONE.c.delivery_id).where(DONE.c.delivery_id == UUID(saved.document()["_id"]))).scalar_one() is not None, "SQL completion is missing.")
                                        cases += 1
                                    finally:
                                        case.rollback()
                                    require(counts(connection) == baseline, "Case rollback retained SQL fixture rows.")
                                    require(delivery_counts(connection) == delivery_baseline, "Case rollback retained SQL delivery evidence.")
                            finally:
                                outer.rollback()
                        with engine.connect() as connection:
                            require(counts(connection) == baseline, "Final rollback did not preserve research counts.")
                            require(delivery_counts(connection) == delivery_baseline, "Final rollback retained SQL preparation/receipt fixtures.")
                            require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalars().all() == ["f73a0c94de21"], "Applied revision changed.")
            finally:
                # This freshly generated database contains synthetic fixtures only.
                # No research users, roles, documents, tables or volumes are deleted.
                if sandbox.startswith("police_delivery_smoke_") and sandbox != DATABASE:
                    test.command("dropAllUsersFromDatabase", 1)
                    test.command("dropAllRolesFromDatabase", 1)
                    bootstrap.drop_database(sandbox)
        with client(app) as research:
            require(research[DATABASE][COLLECTION].count_documents({}) == mongo_before, "Research Mongo count changed.")
        print("Service driver recovery checks: PASSED | interruption cases=", cases)
        print("Exact encrypted replay and SQL/Mongo reconciliation verified using real drivers.")
        print("SQL test transactions rolled back; isolated synthetic Mongo database removed.")
        print("Research counts and applied revision unchanged; no production encryption keys used.")
        print("Independent durable SQL commits remain verified by fresh connections during the actual importer workflow.")
        return 0
    except Exception as error:
        print("Service driver recovery check stopped:", type(error).__name__)
        if type(error) is RuntimeError:
            print(str(error))
        print("Stop before officer import; inspect failure without sharing credentials or personnel data.")
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
