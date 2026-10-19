"""Real driver recovery checks with rollback-only SQL and isolated synthetic Mongo.

SQL savepoints exercise transaction bodies, not independent durable commits.
SqlRemainingLedger independently verifies actual SQL commits via fresh connections;
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
from app.identity.remaining_delivery import deliver, reconcile
from app.identity.remaining_sql_ledger import ASSERTION, DONE, PREP, completion_on_connection, prepare_on_connection
from app.identity.registration_service import REGISTRATION_LOCK
from app.security.identity_crypto import IdentityCrypto
from app.storage.mongo_connection import client, load_credentials
from app.storage.remaining_mongo_contract import APP_USER, COLLECTION_POLICIES, DATABASE, ROLE, privileges
from app.storage.srb_mongo_connection import srb_password, srb_client
from app.storage.remaining_mongo_connection import remaining_password, remaining_client
from app.storage.activity_mongo_connection import activity_password, activity_client
from app.storage.history_mongo_connection import history_password, history_client
from app.storage.setup_remaining_mongo import create_remaining_collection, verify_remaining_collection, verify_accounts, verify_existing, separate_directories
from app.identity.remaining_delivery import collection_for, make_delivery
from app.identity.remaining_sql_ledger import RemainingSourceBinding
from app.identity.remaining_delivery import ROUTES, identity_fields
from app.models import OfficerIdentifierVersion
from migration_settings import MigrationSettings
from scripts.check_remaining_storage import counts, require
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from bson import BSON, Binary
from sqlalchemy import insert
from app.models import Officer, SourceAssertion, SourceSystem
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.identity.remaining_plan import plan_remaining
from app.identity.remaining_plan_crypto import seal_remaining_plan, open_remaining_plan
from app.identity.normalization import NORMALIZATION_PROFILE, normalize_identifier
from app.identity.registration_service import evidence_context
from app.intake.staging_rows import seal_row
from app.storage.remaining_mongo_contract import encryption_context
from app.identity.inspect_service_plans import CONFIRMATION



def fixture(connection, crypto, backup, filename):
    """Create unrelated source/NIC/officer fixtures entirely inside the rollback."""
    officer, nic_assertion, identifier, file_id, assertion_id, delivery_id = (uuid4() for _ in range(6))
    batch = 'HISTORY-SMOKE-' + uuid4().hex
    row = dict.fromkeys(ROUTES[filename], '')
    if 'officer_nic_no' in row:
        row['officer_nic_no'] = 'ROLLBACK-NIC-' + uuid4().hex
    collection = collection_for({'filename': filename})
    source_keys = {'officer_education.csv': 'ol_index', 'operations.csv': 'operation_no',
        'court_details.csv': 'court_no', 'public_complaints.csv': 'complaint_id', '_demotions_enacted.csv': 'punishment_id'}
    row[source_keys[filename]] = '00012'
    if filename == 'court_details.csv': row['outcome_date'] = 'not a date'
    if filename == 'public_complaints.csv': row['officer_nic_as_recorded'] = 'UNKNOWN-REPORTED-NIC'
    source_code = 'POLICE_HR_IS' if filename == 'officer_education.csv' else 'PF_REGISTRY'
    sealed = seal_row(crypto, batch_id=batch, archive_path=filename, source_file_sha256='b'*64,
                      source_row_number=1, columns=list(row), values=list(row.values()))
    connection.execute(insert(IntakeBatch.__table__).values(batch_id=batch, archive_sha256='a'*64, archive_size_bytes=1,
        expected_file_count=1, registration_receipt_id=uuid4(), registration_receipt_sha256='d'*64, schema_version='1.0'))
    connection.execute(insert(IntakeFile.__table__).values(import_file_id=file_id, batch_id=batch, archive_path=filename,
        source_file_sha256='b'*64, size_bytes=1, expected_row_count=1, column_count=len(row), columns=list(row),
        declared_encoding='UTF-8', delimiter=','))
    connection.execute(insert(RawRecord.__table__).values(**asdict(sealed), import_file_id=file_id))
    connection.execute(insert(Officer.__table__).values(officer_uid=officer, registry_state='REGISTERED'))
    source_id = connection.execute(select(SourceSystem.source_system_id).where(SourceSystem.source_system_code == source_code)).scalar_one_or_none()
    if source_id is None:
        # Test-only source registration rolls back with every fixture and DDL change.
        source_id = uuid4()
        connection.execute(insert(SourceSystem.__table__).values(source_system_id=source_id,
            source_system_code=source_code, source_name='Rollback-only remaining fixture', is_active=True))
    nic = normalize_identifier(row.get('officer_nic_no', 'ROLLBACK-NIC-' + uuid4().hex), identifier_type='NIC')
    claim = dict(schema_version='1.0', source_column='officer_nic_no', reported_value=row.get('officer_nic_no', nic.value),
                 normalized_value=nic.value, identifier_type='NIC', normalization_profile=NORMALIZATION_PROFILE,
                 raw_record_id=sealed.raw_record_id, source_confirmation_sha256=CONFIRMATION)
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
    subject = officer if 'officer_nic_no' in row else None
    candidate_refs = {}
    identities = {}
    for name in identity_fields(filename):
        value = row[name].strip()
        state = 'EXACT_EVIDENCE_CANDIDATE' if name == 'officer_nic_no' else 'NO_CANDIDATE_FOUND' if value else 'UNUSABLE_NIC'
        uid = subject if name == 'officer_nic_no' else None
        candidate_refs[name] = dict(candidate_state=state, officer_uid=str(uid) if uid else None)
        identities[name] = uid
    evidence = dict(batch_id=batch,archive_sha256='a'*64,confirmation_sha256=CONFIRMATION,
        source_system_code=source_code,raw_record_id=sealed.raw_record_id,import_file_id=str(file_id),
        source_file_sha256='b'*64,source_row_number=1,identity_candidates=candidate_refs,
        historical_eligibility='UNASSESSED',reference_linkage='UNASSESSED',identifier_evidence=[])
    if subject is not None:
        evidence['identifier_evidence'] = [dict(identifier_version_id=str(identifier),source_assertion_id=str(nic_assertion),
            linkage_method='EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH',historical_eligibility='UNASSESSED')]
    plan = plan_remaining(filename,row,officer_uid=subject,identity_candidates=identities)
    cipher, version = seal_remaining_plan(crypto,plan,raw_record_id=sealed.raw_record_id,reference_evidence=evidence)
    payload = open_remaining_plan(crypto,cipher,key_version=version,filename=filename,raw_record_id=sealed.raw_record_id)
    binding = RemainingSourceBinding(sealed.raw_record_id,identifier if subject else None,CONFIRMATION,'0'*40)
    def candidate():
        return make_delivery(crypto,backup,payload,event_id=uuid4(),assertion_id=uuid4(),recorded_at=datetime.now(timezone.utc))
    return binding,payload,candidate


def delivery_counts(connection):
    return tuple(connection.execute(select(func.count()).select_from(table)).scalar_one() for table in (PREP, DONE, ASSERTION))


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
    parser.add_argument("--srb-credential-directory", required=True)
    parser.add_argument("--remaining-credential-directory", required=True)
    parser.add_argument("--activity-credential-directory", required=True)
    args = parser.parse_args()
    separate_directories(args.mongo_credential_directory, args.history_credential_directory, args.srb_credential_directory,args.activity_credential_directory, args.remaining_credential_directory)
    settings = MigrationSettings()
    require((settings.host, settings.port, settings.user, settings.name) == ("127.0.0.1", 5432, "police_identity_migrator", "police_identity"), "Unexpected SQL target.")
    engine = create_engine(URL.create("postgresql+psycopg", username=settings.user, password=settings.password.get_secret_value(),
        host=settings.host, port=settings.port, database=settings.name), poolclass=NullPool, hide_parameters=True,
        connect_args={"connect_timeout": 5})
    try:
        root, app = load_credentials(args.mongo_credential_directory)
        password_history = history_password(args.history_credential_directory)
        password_srb = srb_password(args.srb_credential_directory)
        with client(app) as research:
            service_before = research[DATABASE].service_status_events.count_documents({})
        with history_client(password_history) as research:
            history_before = {name: research[DATABASE][name].count_documents({}) for name in ('transfer_events', 'promotion_events')}
        password_activity = activity_password(args.activity_credential_directory)
        with activity_client(password_activity) as research:
            activity_before = {name:research[DATABASE][name].count_documents({}) for name in ("duty_periods","firearms_assessments","good_conduct_records","bad_conduct_records")}
        password_remaining = remaining_password(args.remaining_credential_directory)
        with srb_client(password_srb) as research:
            srb_before = {name: research[DATABASE][name].count_documents({}) for name in
                ('police_number_intervals', 'restriction_records', 'restriction_overrides')}
        with remaining_client(password_remaining) as research:
            mongo_before = {name: research[DATABASE][name].count_documents({}) for name in COLLECTION_POLICIES}
        require(service_before == 6596 and history_before == {"transfer_events": 33316, "promotion_events": 13974} and srb_before == {"police_number_intervals": 15123, "restriction_records": 10971, "restriction_overrides": 150} and activity_before == {"duty_periods":3138,"firearms_assessments":30348,"good_conduct_records":2779,"bad_conduct_records":370} and all(n == 0 for n in mongo_before.values()), "Unexpected research Mongo baseline.")
        # Only bootstrap can create and remove isolated test namespaces/accounts.
        sandbox = "police_rem_delivery_smoke_" + uuid4().hex
        require(0 < len(sandbox.encode("utf-8")) < 64 and sandbox != DATABASE, "Unsafe synthetic database name.")
        password = secrets.token_urlsafe(48)
        baseline = None
        cases = 0
        with client(root, bootstrap=True) as bootstrap:
            verify_existing(bootstrap[DATABASE])
            verify_accounts(bootstrap[DATABASE], require_remaining=True)
            for name in COLLECTION_POLICIES:
                verify_remaining_collection(bootstrap[DATABASE], name)
            test = bootstrap[sandbox]
            try:
                for name in COLLECTION_POLICIES:
                    create_remaining_collection(test, name)
                    verify_remaining_collection(test, name)
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
                                require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalars().all() == ["e17a5c39df62"], "Unexpected applied remaining revision.")
                                baseline = counts(connection)
                                require(baseline[:14] == (6596,23966,147327,3,6596,6596,6596,0,47290,47290,26244,26244,36635,36635), "Unexpected reconciled SQL baseline.")
                                delivery_baseline = delivery_counts(connection)
                                require(delivery_baseline == (0, 0, 0), "Remaining driver check requires empty research delivery tables.")
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
                            require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalars().all() == ["e17a5c39df62"], "Applied revision changed.")
            finally:
                # This freshly generated database contains synthetic fixtures only.
                # No research users, roles, documents, tables or volumes are deleted.
                if sandbox.startswith("police_rem_delivery_smoke_") and sandbox != DATABASE:
                    test.command("dropAllUsersFromDatabase", 1)
                    test.command("dropAllRolesFromDatabase", 1)
                    bootstrap.drop_database(sandbox)
        with client(app) as research:
            require(research[DATABASE].service_status_events.count_documents({}) == service_before, "Research service count changed.")
        with history_client(password_history) as research:
            require({name: research[DATABASE][name].count_documents({}) for name in ('transfer_events', 'promotion_events')} == history_before, "Research historical counts changed.")
        with srb_client(password_srb) as research:
            require({name: research[DATABASE][name].count_documents({}) for name in srb_before} == srb_before, "Research SRB counts changed.")
        with remaining_client(password_remaining) as research:
            require({name: research[DATABASE][name].count_documents({}) for name in COLLECTION_POLICIES} == mongo_before, "Research remaining counts changed.")
        with activity_client(password_activity) as research:
            require({name:research[DATABASE][name].count_documents({}) for name in activity_before} == activity_before,"Research activity counts changed.")
        print("Remaining HR/PF driver recovery checks: PASSED | interruption cases=", cases)
        print("Exact encrypted replay and SQL/Mongo reconciliation verified using real drivers.")
        print("SQL test transactions rolled back; isolated synthetic Mongo database removed.")
        print("Research counts and applied revision unchanged; no production encryption keys used.")
        print("Production adapter uses fresh-connection commit recovery; actual imports remain pending.")
        return 0
    except Exception as error:
        print("remaining HR/PF driver recovery check stopped:", type(error).__name__)
        if type(error) in (RuntimeError, ValueError):
            print(str(error))
        print("Stop before officer import; inspect failure without sharing credentials or personnel data.")
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
