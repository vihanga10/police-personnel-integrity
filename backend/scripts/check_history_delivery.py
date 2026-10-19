"""Real driver recovery checks with rollback-only SQL and isolated synthetic Mongo.

SQL savepoints exercise transaction bodies, not independent durable commits.
SqlHistoryLedger independently verifies actual SQL commits via fresh connections;
those production commit paths are exercised during the forthcoming importer workflow.
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
from app.identity.history_delivery import deliver, reconcile
from app.identity.history_sql_ledger import DONE, PREP, completion_on_connection, prepare_on_connection
from app.identity.registration_service import REGISTRATION_LOCK
from app.security.identity_crypto import IdentityCrypto
from app.storage.mongo_connection import client, load_credentials
from app.storage.history_mongo_contract import APP_USER, COLLECTION_POLICIES, DATABASE, ROLE, privileges
from app.storage.history_mongo_connection import history_password, history_client
from app.storage.setup_history_mongo import create_history_collection, verify_history_collection, verify_accounts
from app.identity.history_delivery import collection_for, make_delivery
from app.identity.history_sql_ledger import HistorySourceBinding
from app.identity.history_plan import ROUTES
from app.models import OfficerIdentifierVersion
from migration_settings import MigrationSettings
from scripts.check_history_storage import counts, require
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from bson import BSON, Binary
from sqlalchemy import insert
from app.models import Officer, SourceAssertion, SourceSystem
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.identity.history_plan import plan_history
from app.identity.history_plan_crypto import seal_history_plan, open_history_plan
from app.identity.normalization import NORMALIZATION_PROFILE, normalize_identifier
from app.identity.registration_service import evidence_context
from app.intake.staging_rows import seal_row
from app.storage.history_mongo_contract import encryption_context



def storage_fixture(connection, crypto, backup, filename):
    """Create unrelated source/NIC/officer fixtures entirely inside the rollback."""
    officer, nic_assertion, identifier, file_id, assertion_id, delivery_id = (uuid4() for _ in range(6))
    batch = 'HISTORY-SMOKE-' + uuid4().hex
    row = dict.fromkeys(ROUTES[filename], '')
    row.update(officer_nic_no='ROLLBACK-NIC-' + uuid4().hex, to_rank='Inspector of Police',
               effective_date='2020-01-01', is_same_unit='FALSE')
    collection = 'transfer_events' if filename == 'transfer_history.csv' else 'promotion_events'
    if collection == 'transfer_events':
        row.update(transfer_id='ROLLBACK-TRANSFER', is_cancelled='TRUE', cancellation_ref='ROLLBACK-CANCEL',
                   cancellation_date='2020-02-01', days_in_previous_posting='-12',
                   to_station_code='001', to_station_name='ROLLBACK-STATION')
    else:
        row.update(promotion_id='ROLLBACK-PROMOTION', from_rank='Sub Inspector of Police')
    sealed = seal_row(crypto, batch_id=batch, archive_path=filename, source_file_sha256='b'*64,
                      source_row_number=1, columns=list(row), values=list(row.values()))
    connection.execute(insert(IntakeBatch.__table__).values(batch_id=batch, archive_sha256='a'*64, archive_size_bytes=1,
        expected_file_count=2 if collection == 'transfer_events' else 1, registration_receipt_id=uuid4(), registration_receipt_sha256='d'*64, schema_version='1.0'))
    connection.execute(insert(IntakeFile.__table__).values(import_file_id=file_id, batch_id=batch, archive_path=filename,
        source_file_sha256='b'*64, size_bytes=1, expected_row_count=1, column_count=len(row), columns=list(row),
        declared_encoding='UTF-8', delimiter=','))
    connection.execute(insert(RawRecord.__table__).values(**asdict(sealed), import_file_id=file_id))
    station_refs = {}
    if collection == 'transfer_events':
        # A complete separate station source in this same synthetic batch exercises
        # encrypted code/name verification in the real PostgreSQL adapter.
        station_file = uuid4()
        station_row = seal_row(crypto, batch_id=batch, archive_path='station_master.csv', source_file_sha256='e'*64,
            source_row_number=1, columns=['station_code', 'station_name'], values=['001', 'ROLLBACK-STATION'])
        connection.execute(insert(IntakeFile.__table__).values(import_file_id=station_file, batch_id=batch,
            archive_path='station_master.csv', source_file_sha256='e'*64, size_bytes=1, expected_row_count=1,
            column_count=2, columns=['station_code', 'station_name'], declared_encoding='UTF-8', delimiter=','))
        connection.execute(insert(RawRecord.__table__).values(**asdict(station_row), import_file_id=station_file))
        station_refs = dict(station_source=dict(batch_id=batch, import_file_id=str(station_file),
            archive_path='station_master.csv', source_file_sha256='e'*64, match_policy='STATION_EXACT_TRIM_V1',
            historical_applicability='UNKNOWN', code_scope='REGISTERED_SOURCE_SNAPSHOT'), station_matches=dict(
            to_station_code=dict(station_code='001', raw_record_id=station_row.raw_record_id, historical_applicability='UNKNOWN')))
    connection.execute(insert(Officer.__table__).values(officer_uid=officer, registry_state='REGISTERED'))
    source_id = connection.execute(select(SourceSystem.source_system_id).where(SourceSystem.source_system_code == 'PF_REGISTRY')).scalar_one()
    nic = normalize_identifier(row['officer_nic_no'], identifier_type='NIC')
    claim = dict(schema_version='1.0', source_column='officer_nic_no', reported_value=row['officer_nic_no'],
                 normalized_value=nic.value, identifier_type='NIC', normalization_profile=NORMALIZATION_PROFILE,
                 raw_record_id=sealed.raw_record_id, source_confirmation_sha256='c'*64)
    cipher, version = crypto.encrypt_assertion(claim, context=evidence_context('ASSERTION', nic_assertion))
    provenance = dict(officer_uid=officer, source_system_id=source_id, intake_batch_id=batch, import_file_id=str(file_id),
        raw_record_id=sealed.raw_record_id, source_file_name=filename, source_file_sha256='b'*64,
        source_row_number=1, assertion_state='ACTIVE', independence_status='UNVERIFIED')
    connection.execute(insert(SourceAssertion.__table__).values(**provenance, source_assertion_id=nic_assertion,
        assertion_type='IDENTIFIER_NIC', asserted_value_ciphertext=cipher, encryption_key_version=version))
    cipher, version = crypto.encrypt(nic.value.encode(), context=evidence_context('IDENTIFIER', identifier))
    digest, lookup = crypto.lookup_hmac(nic.value, identifier_type='NIC')
    connection.execute(insert(OfficerIdentifierVersion.__table__).values(identifier_version_id=identifier,
        identifier_chain_uid=uuid4(), officer_uid=officer, source_assertion_id=nic_assertion, identifier_type='NIC',
        identifier_value_ciphertext=cipher, identifier_lookup_hmac=digest, normalization_profile=NORMALIZATION_PROFILE,
        encryption_key_version=version, lookup_key_version=lookup, version_number=1, record_state='ASSERTED'))
    plan = plan_history(filename, row, officer_uid=officer, station_candidates={'ROLLBACK-STATION': ('001',)})
    cipher, version = seal_history_plan(crypto, plan, raw_record_id=sealed.raw_record_id, reference_evidence={'synthetic': True})
    payload = open_history_plan(crypto, cipher, key_version=version, filename=filename, officer_uid=officer, raw_record_id=sealed.raw_record_id)
    recorded = datetime.now(timezone.utc)
    recorded = recorded.replace(microsecond=recorded.microsecond // 1000 * 1000)
    doc = dict(_id=str(delivery_id), officer_uid=str(officer), source_assertion_uid=str(assertion_id),
        raw_record_id=sealed.raw_record_id, writer_policy=COLLECTION_POLICIES[collection], schema_version=1,
        classification='UNASSESSED', recorded_at=recorded, payload_key_version=crypto.active_encryption_version)
    cipher, version = crypto.encrypt_assertion(payload, context=encryption_context(collection, doc))
    doc['payload_ciphertext'] = Binary(cipher)
    encoded = bytes(BSON.encode(doc))
    assertion = dict(provenance, source_assertion_id=assertion_id,
        assertion_type='PF_TRANSFER_EVIDENCE' if collection == 'transfer_events' else 'PF_PROMOTION_EVIDENCE',
        asserted_value_ciphertext=cipher, encryption_key_version=version, transaction_start=recorded)
    reviews = sum(f.status == 'REVIEW_REQUIRED' for f in plan.fields)
    preparation = dict(delivery_id=delivery_id, raw_record_id=sealed.raw_record_id, officer_uid=officer,
        source_assertion_id=assertion_id, identifier_version_id=identifier, confirmation_sha256='c'*64,
        code_revision='0'*40, source_file_name=filename, mongo_collection=collection, field_review_count=reviews,
        review_state='FIELD_REVIEW_REQUIRED' if reviews else 'NO_FIELD_REVIEW', writer_policy=doc['writer_policy'],
        linkage_method='EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH', historical_eligibility='UNASSESSED',
        document_bson=encoded, document_sha256=hashlib.sha256(encoded).hexdigest(), recorded_at=recorded)
    return assertion, preparation, payload, station_refs

def fixture(connection, crypto, backup, filename):
    # Reuse only the isolated source/NIC fixture creator, not its proposed outbox.
    assertion, seed, payload, station_refs = storage_fixture(connection, crypto, backup, filename)
    nic_assertion = connection.execute(select(OfficerIdentifierVersion.source_assertion_id).where(
        OfficerIdentifierVersion.identifier_version_id == seed["identifier_version_id"])).scalar_one()
    payload["reference_evidence"] = dict(history_source=dict(batch_id=assertion["intake_batch_id"],
        raw_record_id=seed["raw_record_id"], import_file_id=assertion["import_file_id"], source_file_sha256=assertion["source_file_sha256"],
        source_row_number=assertion["source_row_number"], reported_source_system_code="PF_REGISTRY", confirmation_sha256=seed["confirmation_sha256"]),
        identifier_evidence=[dict(identifier_version_id=str(seed["identifier_version_id"]), source_assertion_id=str(nic_assertion),
            linkage_method="EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH", historical_eligibility="UNASSESSED")], station_matches={})
    payload["reference_evidence"].update(station_refs)
    binding = HistorySourceBinding(seed["raw_record_id"], seed["identifier_version_id"], seed["confirmation_sha256"], seed["code_revision"])
    def candidate():
        from datetime import datetime, timezone
        return make_delivery(crypto, backup, payload, event_id=uuid4(), assertion_id=uuid4(), recorded_at=datetime.now(timezone.utc))
    return binding, payload, candidate


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
        self.name = collection.name

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
    parser.add_argument("--history-credential-directory", required=True)
    args = parser.parse_args()
    settings = MigrationSettings()
    require((settings.host, settings.port, settings.user, settings.name) == ("127.0.0.1", 5432, "police_identity_migrator", "police_identity"), "Unexpected SQL target.")
    engine = create_engine(URL.create("postgresql+psycopg", username=settings.user, password=settings.password.get_secret_value(),
        host=settings.host, port=settings.port, database=settings.name), poolclass=NullPool, hide_parameters=True,
        connect_args={"connect_timeout": 5})
    try:
        root, app = load_credentials(args.mongo_credential_directory)
        password_history = history_password(args.history_credential_directory)
        with client(app) as research:
            service_before = research[DATABASE].service_status_events.count_documents({})
        with history_client(password_history) as research:
            mongo_before = {name: research[DATABASE][name].count_documents({}) for name in COLLECTION_POLICIES}
        require(service_before == 6596 and all(n == 0 for n in mongo_before.values()), "Unexpected research Mongo baseline.")
        # Only bootstrap can create and remove isolated test namespaces/accounts.
        sandbox = "police_history_delivery_smoke_" + uuid4().hex
        password = secrets.token_urlsafe(48)
        baseline = None
        cases = 0
        with client(root, bootstrap=True) as bootstrap:
            verify_accounts(bootstrap[DATABASE], require_history=True)
            for name in COLLECTION_POLICIES:
                verify_history_collection(bootstrap[DATABASE], name)
            test = bootstrap[sandbox]
            try:
                for name in COLLECTION_POLICIES:
                    create_history_collection(test, name)
                    verify_history_collection(test, name)
                test.command("createRole", ROLE, privileges=privileges(sandbox), roles=[])
                test.command("createUser", "delivery_smoke_app", pwd=password, roles=[{"role": ROLE, "db": sandbox}])
                with tempfile.TemporaryDirectory() as directory:
                    key = base64.b64encode(os.urandom(32)).decode()
                    material = dict(active_encryption_key_version="EPHEMERAL", active_lookup_key_version="EPHEMERAL",
                                    encryption_keys={"EPHEMERAL": key}, lookup_keys={"EPHEMERAL": key})
                    paths = [Path(directory) / p for p in ("primary.json", "backup.json")]
                    for path in paths:
                        path.write_text(json.dumps(material))
                        path.chmod(0o600)
                    crypto, backup = (IdentityCrypto(p) for p in paths)
                    with MongoClient("127.0.0.1", 27018, username="delivery_smoke_app", password=password, authSource=sandbox,
                                     tz_aware=True, retryWrites=False, serverSelectionTimeoutMS=5000, socketTimeoutMS=10000) as smoke:
                        with engine.connect() as connection:
                            outer = connection.begin()
                            try:
                                connection.execute(text("SET LOCAL lock_timeout = '5s'"))
                                connection.execute(text("SET LOCAL statement_timeout = '30s'"))
                                connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": REGISTRATION_LOCK})
                                require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalars().all() == ["b84d2f06ac39"], "Unexpected applied historical revision.")
                                baseline = counts(connection)
                                delivery_baseline = delivery_counts(connection)
                                for filename in ROUTES:
                                    for failure in ("after_prepare", "before_mongo", "after_mongo", "before_receipt", "after_receipt"):
                                        case = connection.begin_nested()
                                        try:
                                            binding, payload, candidate = fixture(connection, crypto, backup, filename)
                                            kwargs = dict(crypto=crypto, backup=backup, binding=binding, expected_payload=payload)
                                            ledger = RollbackLedger(connection, kwargs, failure)
                                            collection = InterruptedMongo(smoke[sandbox][collection_for(payload)], failure)
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
                                            require(smoke[sandbox][collection_for(payload)].count_documents({"raw_record_id": binding.raw_record_id}) == 1, "Mongo fixture duplicated.")
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
                            require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalars().all() == ["b84d2f06ac39"], "Applied revision changed.")
            finally:
                # This freshly generated database contains synthetic fixtures only.
                # No research users, roles, documents, tables or volumes are deleted.
                if sandbox.startswith("police_history_delivery_smoke_") and sandbox != DATABASE:
                    test.command("dropAllUsersFromDatabase", 1)
                    test.command("dropAllRolesFromDatabase", 1)
                    bootstrap.drop_database(sandbox)
        with client(app) as research:
            require(research[DATABASE].service_status_events.count_documents({}) == service_before, "Research service count changed.")
        with history_client(password_history) as research:
            require({name: research[DATABASE][name].count_documents({}) for name in COLLECTION_POLICIES} == mongo_before, "Research historical counts changed.")
        print("Historical driver recovery checks: PASSED | interruption cases=", cases)
        print("Exact encrypted replay and SQL/Mongo reconciliation verified using real drivers.")
        print("SQL test transactions rolled back; isolated synthetic Mongo database removed.")
        print("Research counts and applied revision unchanged; no production encryption keys used.")
        print("Production adapter uses fresh-connection commit recovery; actual imports remain pending.")
        return 0
    except Exception as error:
        print("Historical driver recovery check stopped:", type(error).__name__)
        if type(error) in (RuntimeError, ValueError):
            print(str(error))
        print("Stop before officer import; inspect failure without sharing credentials or personnel data.")
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
