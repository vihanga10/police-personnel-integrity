"""Real driver recovery checks with rollback-only SQL and isolated synthetic Mongo.

SQL savepoints exercise transaction bodies, not independent durable commits.
SqlActivityLedger independently verifies actual SQL commits via fresh connections;
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
from app.identity.activity_delivery import deliver, reconcile
from app.identity.activity_sql_ledger import DONE, PREP, completion_on_connection, prepare_on_connection
from app.identity.registration_service import REGISTRATION_LOCK
from app.security.identity_crypto import IdentityCrypto
from app.storage.mongo_connection import client, load_credentials
from app.storage.activity_mongo_contract import APP_USER, COLLECTION_POLICIES, DATABASE, ROLE, privileges
from app.storage.srb_mongo_connection import srb_password, srb_client
from app.storage.activity_mongo_connection import activity_password, activity_client
from app.storage.history_mongo_connection import history_password, history_client
from app.storage.setup_activity_mongo import create_activity_collection, verify_activity_collection, verify_accounts, verify_existing, separate_directories
from app.identity.activity_delivery import collection_for, make_delivery
from app.identity.activity_sql_ledger import ActivitySourceBinding
from app.identity.srb_activity_plan import ROUTES
from app.models import OfficerIdentifierVersion
from migration_settings import MigrationSettings
from scripts.check_activity_storage import counts, require
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from bson import BSON, Binary
from sqlalchemy import insert
from app.models import Officer, SourceAssertion, SourceSystem
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.identity.srb_activity_plan import plan_activity
from app.identity.srb_activity_plan_crypto import seal_activity_plan, open_activity_plan
from app.identity.normalization import NORMALIZATION_PROFILE, normalize_identifier
from app.identity.registration_service import evidence_context
from app.intake.staging_rows import seal_row
from app.storage.activity_mongo_contract import encryption_context
from app.identity.inspect_service_plans import CONFIRMATION



def fixture(connection, crypto, backup, filename):
    """Stage a complete small test batch; every SQL row stays inside rollback."""
    officer, nic_assertion, identifier = (uuid4() for _ in range(3))
    batch = 'SRB-DELIVERY-SMOKE-' + uuid4().hex
    nic_text = 'ROLLBACK-NIC-' + uuid4().hex
    row = dict.fromkeys(ROUTES[filename], '')
    row['officer_nic_no'] = nic_text
    actors, station_refs = {}, {}
    rows = []
    source_keys = {'officer_duty_periods.csv': 'period_id',
        'officer_firearms_expertise.csv': 'gun_record_id',
        'good_conduct_register.csv': 'good_conduct_id',
        'bad_conduct_register.csv': 'punishment_id'}
    row[source_keys[filename]] = '00012'
    if filename == 'officer_duty_periods.csv':
        row.update(period_from='2020-01-01', period_recorded_by_authority_nic=nic_text,
            period_recorded_by_authority_rank='CI', period_station_code='001', period_station_name='ROLLBACK-STATION',
            current_station_code='001')
        actors = {'period_recorded_by_authority_nic': dict(candidate_state='EXACT_EVIDENCE_CANDIDATE', officer_uid=str(officer))}
    elif filename == 'officer_firearms_expertise.csv':
        # H2 stays entirely missing. A reported score match does not establish competency.
        row.update(gun_performance_year='2020', gun_performance_station_code='001',
            gun_performance_station_name='ROLLBACK-STATION', current_station_code='001',
            h1_supervisor_nic=nic_text, h1_supervisor_police_rank='IP',
            h1_total_points='12', year_total_points='12', record_status='Original unresolved status')
        actors = {'h1_supervisor_nic': dict(candidate_state='EXACT_EVIDENCE_CANDIDATE', officer_uid=str(officer))}
    elif filename == 'good_conduct_register.csv':
        row.update(accused_arrested='TRUE', accused_convicted='FALSE', recommending_asp_nic=nic_text)
        actors = {'recommending_asp_nic': dict(candidate_state='EXACT_EVIDENCE_CANDIDATE', officer_uid=str(officer))}
    if filename in {'officer_duty_periods.csv', 'officer_firearms_expertise.csv'}:
        rows.append(('station_master.csv', {'station_code': '001', 'station_name': 'ROLLBACK-STATION'}))
    rows.insert(0, (filename, row))
    connection.execute(insert(IntakeBatch.__table__).values(batch_id=batch, archive_sha256='a'*64, archive_size_bytes=1,
        expected_file_count=len(rows), registration_receipt_id=uuid4(), registration_receipt_sha256='d'*64, schema_version='1.0'))
    staged = {}
    for source_filename, values in rows:
        file_id = uuid4()
        digest = hashlib.sha256(source_filename.encode()).hexdigest()
        sealed = seal_row(crypto, batch_id=batch, archive_path=source_filename, source_file_sha256=digest,
            source_row_number=1, columns=list(values), values=list(values.values()))
        connection.execute(insert(IntakeFile.__table__).values(import_file_id=file_id, batch_id=batch, archive_path=source_filename,
            source_file_sha256=digest, size_bytes=1, expected_row_count=1, column_count=len(values), columns=list(values),
            declared_encoding='UTF-8', delimiter=','))
        connection.execute(insert(RawRecord.__table__).values(**asdict(sealed), import_file_id=file_id))
        staged[source_filename] = (sealed, file_id, digest)
    raw, file_id, digest = staged[filename]
    connection.execute(insert(Officer.__table__).values(officer_uid=officer, registry_state='REGISTERED'))
    # NIC proof uses the existing PF source; the adapter registers SRB atomically.
    source_id = connection.execute(select(SourceSystem.source_system_id).where(SourceSystem.source_system_code == 'PF_REGISTRY')).scalar_one()
    nic = normalize_identifier(nic_text, identifier_type='NIC')
    claim = dict(schema_version='1.0', source_column='officer_nic_no', reported_value=nic_text,
        normalized_value=nic.value, identifier_type='NIC', normalization_profile=NORMALIZATION_PROFILE,
        raw_record_id=raw.raw_record_id, source_confirmation_sha256=CONFIRMATION)
    cipher, version = crypto.encrypt_assertion(claim, context=evidence_context('ASSERTION', nic_assertion))
    connection.execute(insert(SourceAssertion.__table__).values(source_assertion_id=nic_assertion, officer_uid=officer,
        source_system_id=source_id, intake_batch_id=batch, import_file_id=str(file_id), raw_record_id=raw.raw_record_id,
        source_file_name=filename, source_file_sha256=digest, source_row_number=1, assertion_state='ACTIVE',
        independence_status='UNVERIFIED', assertion_type='IDENTIFIER_NIC', asserted_value_ciphertext=cipher, encryption_key_version=version))
    cipher, version = crypto.encrypt(nic.value.encode(), context=evidence_context('IDENTIFIER', identifier))
    lookup_digest, lookup_version = crypto.lookup_hmac(nic.value, identifier_type='NIC')
    connection.execute(insert(OfficerIdentifierVersion.__table__).values(identifier_version_id=identifier,
        identifier_chain_uid=uuid4(), officer_uid=officer, source_assertion_id=nic_assertion, identifier_type='NIC',
        identifier_value_ciphertext=cipher, identifier_lookup_hmac=lookup_digest, normalization_profile=NORMALIZATION_PROFILE,
        encryption_key_version=version, lookup_key_version=lookup_version, version_number=1, record_state='ASSERTED'))
    if 'station_master.csv' in staged:
        station, station_file, station_digest = staged['station_master.csv']
        station_refs = dict(station_source=dict(batch_id=batch, import_file_id=str(station_file), archive_path='station_master.csv',
            source_file_sha256=station_digest, match_policy='STATION_EXACT_TRIM_V1', historical_applicability='UNKNOWN', code_scope='REGISTERED_SOURCE_SNAPSHOT'),
            station_matches={name: dict(station_code='001', raw_record_id=station.raw_record_id, historical_applicability='UNKNOWN')
                for name in ('period_station_code', 'gun_performance_station_code', 'current_station_code') if name in row and row[name]})
    evidence = dict(activity_source=dict(batch_id=batch, raw_record_id=raw.raw_record_id, import_file_id=str(file_id), source_file_sha256=digest,
        source_row_number=1, reported_source_system_code='SRB', confirmation_sha256=CONFIRMATION),
        identifier_evidence=[dict(identifier_version_id=str(identifier), source_assertion_id=str(nic_assertion),
            linkage_method='EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH', historical_eligibility='UNASSESSED')],
        actor_candidates=actors, station_matches={})
    evidence.update(station_refs)
    plan = plan_activity(filename, row, officer_uid=officer, station_candidates={'ROLLBACK-STATION': ('001',)},
        actor_candidates={name: UUID(ref['officer_uid']) for name, ref in actors.items()})
    cipher, version = seal_activity_plan(crypto, plan, raw_record_id=raw.raw_record_id, reference_evidence=evidence)
    payload = open_activity_plan(crypto, cipher, key_version=version, filename=filename, officer_uid=officer, raw_record_id=raw.raw_record_id)
    binding = ActivitySourceBinding(raw.raw_record_id, identifier, CONFIRMATION, '0'*40)
    def candidate():
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
    parser.add_argument("--srb-credential-directory", required=True)
    parser.add_argument("--activity-credential-directory", required=True)
    args = parser.parse_args()
    separate_directories(args.mongo_credential_directory, args.history_credential_directory, args.srb_credential_directory, args.activity_credential_directory)
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
        with srb_client(password_srb) as research:
            srb_before = {name: research[DATABASE][name].count_documents({}) for name in
                ('police_number_intervals', 'restriction_records', 'restriction_overrides')}
        with activity_client(password_activity) as research:
            mongo_before = {name: research[DATABASE][name].count_documents({}) for name in COLLECTION_POLICIES}
        require(service_before == 6596 and history_before == {"transfer_events": 33316, "promotion_events": 13974} and srb_before == {"police_number_intervals": 15123, "restriction_records": 10971, "restriction_overrides": 150} and all(n == 0 for n in mongo_before.values()), "Unexpected research Mongo baseline.")
        # Only bootstrap can create and remove isolated test namespaces/accounts.
        sandbox = "police_activity_delivery_smoke_" + uuid4().hex
        password = secrets.token_urlsafe(48)
        baseline = None
        cases = 0
        with client(root, bootstrap=True) as bootstrap:
            verify_existing(bootstrap[DATABASE])
            verify_accounts(bootstrap[DATABASE], require_activity=True)
            for name in COLLECTION_POLICIES:
                verify_activity_collection(bootstrap[DATABASE], name)
            test = bootstrap[sandbox]
            try:
                for name in COLLECTION_POLICIES:
                    create_activity_collection(test, name)
                    verify_activity_collection(test, name)
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
                                require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalars().all() == ["d06f4b28ce51"], "Unexpected applied activity revision.")
                                baseline = counts(connection)
                                require(baseline[:12] == (6596, 23966, 110692, 3, 6596, 6596, 6596, 0, 47290, 47290, 26244, 26244), "Unexpected reconciled SQL baseline.")
                                delivery_baseline = delivery_counts(connection)
                                require(delivery_baseline == (0, 0), "Activity driver check requires empty research delivery tables.")
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
                            require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalars().all() == ["d06f4b28ce51"], "Applied revision changed.")
            finally:
                # This freshly generated database contains synthetic fixtures only.
                # No research users, roles, documents, tables or volumes are deleted.
                if sandbox.startswith("police_activity_delivery_smoke_") and sandbox != DATABASE:
                    test.command("dropAllUsersFromDatabase", 1)
                    test.command("dropAllRolesFromDatabase", 1)
                    bootstrap.drop_database(sandbox)
        with client(app) as research:
            require(research[DATABASE].service_status_events.count_documents({}) == service_before, "Research service count changed.")
        with history_client(password_history) as research:
            require({name: research[DATABASE][name].count_documents({}) for name in ('transfer_events', 'promotion_events')} == history_before, "Research historical counts changed.")
        with srb_client(password_srb) as research:
            require({name: research[DATABASE][name].count_documents({}) for name in srb_before} == srb_before, "Research SRB counts changed.")
        with activity_client(password_activity) as research:
            require({name: research[DATABASE][name].count_documents({}) for name in COLLECTION_POLICIES} == mongo_before, "Research activity counts changed.")
        print("SRB activity driver recovery checks: PASSED | interruption cases=", cases)
        print("Exact encrypted replay and SQL/Mongo reconciliation verified using real drivers.")
        print("SQL test transactions rolled back; isolated synthetic Mongo database removed.")
        print("Research counts and applied revision unchanged; no production encryption keys used.")
        print("Production adapter uses fresh-connection commit recovery; actual imports remain pending.")
        return 0
    except Exception as error:
        print("SRB activity driver recovery check stopped:", type(error).__name__)
        if type(error) in (RuntimeError, ValueError):
            print(str(error))
        print("Stop before officer import; inspect failure without sharing credentials or personnel data.")
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
