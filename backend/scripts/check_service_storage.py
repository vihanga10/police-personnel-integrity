"""Apply and exercise service storage in a SQL transaction, then ALWAYS rollback.

No Mongo connection, production encryption keys or personnel-value reads.
Use before applying revision f73a0c94de21. Fixtures are synthetic and transient.
"""
import base64
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import URL, create_engine, func, insert, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool
from app.db.base import Base
from app.db.staging_base import StagingBase
from app.models import Officer, OfficerIdentifierVersion, ProfileTransformReceipt, SourceAssertion, SourceSystem
from app.models.service_delivery_storage import ServiceDeliveryCompletion, ServiceDeliveryPreparation
from app.staging.identity_decision import IdentityRegistrationDecision  # register predecessor metadata
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.identity.normalization import NORMALIZATION_PROFILE, normalize_identifier
from app.identity.registration_service import REGISTRATION_LOCK, evidence_context
from app.identity.service_delivery import make_delivery
from app.identity.service_plan import ROUTES, plan_service
from app.identity.service_plan_crypto import open_service_plan, seal_service_plan
from app.identity.service_sql_ledger import ServiceSourceBinding, completion_on_connection, prepare_on_connection
from app.intake.staging_rows import seal_row
from app.security.identity_crypto import IdentityCrypto
from migration_settings import MigrationSettings

REVISION = "e62c9a01bd47"
TABLES = ("staging.service_delivery_preparation", "staging.service_delivery_completion")
BASELINE_MODELS = (Officer, OfficerIdentifierVersion, SourceAssertion, SourceSystem, ProfileTransformReceipt, RawRecord)


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def fixture(connection, crypto, backup):
    """Create one wholly separate source row/officer/NIC fixture, inside rollback."""
    officer, assertion, identifier, file_id = (uuid4() for _ in range(4))
    batch = "SERVICE-SMOKE-" + uuid4().hex
    confirmation = "c" * 64
    row = {name: "" for name in ROUTES}
    row.update(service_id="ROLLBACK-TEST", officer_nic_no="ROLLBACK-NIC-" + uuid4().hex,
               current_rank="Police Constable Class 1", current_rank_category="Non-Gazetted",
               current_unit_type="CID", service_status="Active")
    sealed = seal_row(crypto, batch_id=batch, archive_path="officer_service_information.csv",
                      source_file_sha256="b" * 64, source_row_number=1, columns=list(row), values=list(row.values()))
    connection.execute(insert(IntakeBatch.__table__).values(batch_id=batch, archive_sha256="a" * 64, archive_size_bytes=1,
        expected_file_count=1, registration_receipt_id=uuid4(), registration_receipt_sha256="d" * 64, schema_version="1.0"))
    connection.execute(insert(IntakeFile.__table__).values(import_file_id=file_id, batch_id=batch,
        archive_path=sealed.archive_path, source_file_sha256=sealed.source_file_sha256, size_bytes=1, expected_row_count=1,
        column_count=len(row), columns=list(row), declared_encoding="UTF-8", delimiter=","))
    connection.execute(insert(RawRecord.__table__).values(**asdict(sealed), import_file_id=file_id))
    connection.execute(insert(Officer.__table__).values(officer_uid=officer, registry_state="REGISTERED"))
    source_id = connection.execute(select(SourceSystem.source_system_id).where(SourceSystem.source_system_code == "PF_REGISTRY")).scalar_one()
    nic = normalize_identifier(row["officer_nic_no"], identifier_type="NIC")
    claim = dict(schema_version="1.0", source_column="officer_nic_no", reported_value=row["officer_nic_no"],
                 normalized_value=nic.value, identifier_type="NIC", normalization_profile=NORMALIZATION_PROFILE,
                 raw_record_id=sealed.raw_record_id, source_confirmation_sha256=confirmation)
    cipher, version = crypto.encrypt_assertion(claim, context=evidence_context("ASSERTION", assertion))
    connection.execute(insert(SourceAssertion.__table__).values(source_assertion_id=assertion, officer_uid=officer,
        source_system_id=source_id, assertion_type="IDENTIFIER_NIC", asserted_value_ciphertext=cipher,
        encryption_key_version=version, intake_batch_id=batch, import_file_id=str(file_id), raw_record_id=sealed.raw_record_id,
        source_file_name=sealed.archive_path, source_file_sha256=sealed.source_file_sha256, source_row_number=1,
        assertion_state="ACTIVE", independence_status="UNVERIFIED"))
    cipher, version = crypto.encrypt(nic.value.encode(), context=evidence_context("IDENTIFIER", identifier))
    digest, lookup_version = crypto.lookup_hmac(nic.value, identifier_type="NIC")
    connection.execute(insert(OfficerIdentifierVersion.__table__).values(identifier_version_id=identifier,
        identifier_chain_uid=uuid4(), officer_uid=officer, source_assertion_id=assertion, identifier_type="NIC",
        identifier_value_ciphertext=cipher, identifier_lookup_hmac=digest, normalization_profile=NORMALIZATION_PROFILE,
        encryption_key_version=version, lookup_key_version=lookup_version, version_number=1, record_state="ASSERTED"))
    references = dict(service_source=dict(batch_id=batch, raw_record_id=sealed.raw_record_id, import_file_id=str(file_id),
        source_file_sha256=sealed.source_file_sha256, source_row_number=1, reported_source_system_code="POLICE_HR_IS",
        confirmation_sha256=confirmation), identifier_evidence=[dict(identifier_version_id=str(identifier),
        source_assertion_id=str(assertion), linkage_method="EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH", historical_eligibility="UNASSESSED")])
    plan = plan_service(row, officer_uid=officer, station_candidates={})
    cipher, version = seal_service_plan(crypto, plan, officer_uid=officer, raw_record_id=sealed.raw_record_id, reference_evidence=references)
    payload = open_service_plan(crypto, cipher, key_version=version, officer_uid=officer, raw_record_id=sealed.raw_record_id)
    binding = ServiceSourceBinding(sealed.raw_record_id, identifier, confirmation, "0" * 40)
    def candidate():
        return make_delivery(crypto, backup, payload, event_id=uuid4(), assertion_id=uuid4(), recorded_at=datetime.now(timezone.utc))
    return binding, payload, candidate


def counts(connection):
    return tuple(connection.execute(select(func.count()).select_from(m.__table__)).scalar_one() for m in BASELINE_MODELS)


def main():
    settings = MigrationSettings()
    require((settings.host, settings.port, settings.user, settings.name) == ("127.0.0.1", 5432, "police_identity_migrator", "police_identity"),
            "Unexpected migration target.")
    engine = create_engine(URL.create("postgresql+psycopg", username=settings.user, password=settings.password.get_secret_value(),
        host=settings.host, port=settings.port, database=settings.name), poolclass=NullPool, hide_parameters=True,
        connect_args={"connect_timeout": 5})
    path = BACKEND / "migrations/versions/f73a0c94de21_add_service_delivery_storage.py"
    spec = importlib.util.spec_from_file_location("service_storage_check_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    checks = 0
    baseline = None
    try:
        with tempfile.TemporaryDirectory() as directory:
            key = base64.b64encode(os.urandom(32)).decode()
            material = dict(active_encryption_key_version="EPHEMERAL", active_lookup_key_version="EPHEMERAL",
                            encryption_keys={"EPHEMERAL": key}, lookup_keys={"EPHEMERAL": key})
            paths = [Path(directory) / name for name in ("primary.json", "backup.json")]
            for key_path in paths:
                key_path.write_text(json.dumps(material)); key_path.chmod(0o600)
            crypto, backup = (IdentityCrypto(p) for p in paths)
            with engine.connect() as connection:
                outer = connection.begin()
                try:
                    connection.execute(text("SET LOCAL lock_timeout = '5s'"))
                    connection.execute(text("SET LOCAL statement_timeout = '30s'"))
                    connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": REGISTRATION_LOCK})
                    require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalars().all() == [REVISION], "Unexpected applied revision.")
                    for table in TABLES:
                        require(connection.execute(text("SELECT to_regclass(:table)"), {"table": table}).scalar_one() is None, "Run this check before upgrading service storage.")
                    baseline = counts(connection)
                    require(baseline[:5] == (6596, 23966, 30562, 1, 6596), "Unexpected identity/profile/source baseline.")
                    with Operations.context(MigrationContext.configure(connection)):
                        migration.upgrade()
                    checks += 1
                    context = MigrationContext.configure(connection, opts={"include_schemas": True, "compare_type": True,
                        "version_table": "alembic_version", "version_table_schema": "identity",
                        "include_object": lambda obj, name, kind, reflected, other: kind != "table" or obj.schema in {"identity", "staging"}})
                    require(not compare_metadata(context, [Base.metadata, StagingBase.metadata]), "Schema/model differences detected.")
                    checks += 1
                    for table in TABLES:
                        for privilege, allowed in (("SELECT", True), ("INSERT", True), ("UPDATE", False), ("DELETE", False), ("TRUNCATE", False), ("REFERENCES", False), ("TRIGGER", False)):
                            actual = connection.execute(text("SELECT has_table_privilege('police_identity_app', :table, :privilege)"), {"table": table, "privilege": privilege}).scalar_one()
                            require(actual is allowed, "Unexpected application service-storage permissions.")
                            checks += 1
                    binding, payload, candidate = fixture(connection, crypto, backup)
                    kwargs = dict(crypto=crypto, backup=backup, binding=binding, expected_payload=payload)
                    before = counts(connection)

                    def rejected(action, state):
                        nonlocal checks
                        savepoint = connection.begin_nested()
                        try:
                            action()
                        except DBAPIError as error:
                            require(getattr(error.orig, "sqlstate", None) == state, "Unexpected SQL rejection type.")
                            checks += 1
                        else:
                            raise RuntimeError("Prohibited SQL operation was accepted.")
                        finally:
                            savepoint.rollback()

                    def fail_after_assertion_insert():
                        # Inject an outbox failure only within this savepoint;
                        # rollback must remove its newly inserted source assertion.
                        connection.execute(text("""CREATE FUNCTION staging.smoke_reject_service_insert() RETURNS trigger
                            LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Injected preparation failure'; RETURN NULL; END; $$"""))
                        connection.execute(text("""CREATE TRIGGER zz_smoke_preparation_failure BEFORE INSERT ON staging.service_delivery_preparation
                            FOR EACH ROW EXECUTE FUNCTION staging.smoke_reject_service_insert()"""))
                        prepare_on_connection(connection, candidate(), **kwargs)
                    rejected(fail_after_assertion_insert, "P0001")
                    require(counts(connection) == before, "Failed preparation retained its assertion or source registration.")
                    require(connection.execute(select(func.count()).select_from(ServiceDeliveryPreparation.__table__)).scalar_one() == 0, "Failed preparation retained an outbox record.")
                    checks += 2
                    proposed = candidate()
                    saved = prepare_on_connection(connection, proposed, **kwargs)
                    require(saved == proposed, "Initial preparation differs.")
                    require(prepare_on_connection(connection, candidate(), **kwargs) == saved, "Replay did not reuse exact prepared BSON.")
                    require(connection.execute(select(func.count()).select_from(ServiceDeliveryCompletion.__table__)).scalar_one() == 0, "Pending preparation already has a completion.")
                    checks += 3
                    prep_table = ServiceDeliveryPreparation.__table__
                    receipt_table = ServiceDeliveryCompletion.__table__
                    prepared_row = dict(connection.execute(select(prep_table)).mappings().one())
                    changed = dict(prepared_row, delivery_id=uuid4(), officer_uid=uuid4())
                    rejected(lambda: connection.execute(insert(prep_table).values(**changed)), "P0001")
                    changed = dict(prepared_row, delivery_id=uuid4(), document_bson=prepared_row["document_bson"] + b"x")
                    rejected(lambda: connection.execute(insert(prep_table).values(**changed)), "23514")
                    changed = dict(prepared_row, delivery_id=uuid4())
                    rejected(lambda: connection.execute(insert(prep_table).values(**changed)), "23505")
                    for digest in ("0" * 64,):
                        rejected(lambda: connection.execute(insert(receipt_table).values(delivery_id=prepared_row["delivery_id"], document_sha256=digest)), "P0001")
                    rejected(lambda: connection.execute(insert(receipt_table).values(delivery_id=uuid4(), document_sha256=saved.document_sha256)), "P0001")
                    rejected(lambda: connection.execute(insert(receipt_table).values(delivery_id=prepared_row["delivery_id"], document_sha256=saved.document_sha256,
                        recorded_at=prepared_row["recorded_at"] - timedelta(days=1))), "P0001")
                    require(completion_on_connection(connection, saved) == saved.document_sha256, "Completion recovery differs.")
                    require(completion_on_connection(connection, saved) == saved.document_sha256, "Completion replay differs.")
                    require(connection.execute(select(func.count()).select_from(receipt_table)).scalar_one() == 1, "Completion was duplicated.")
                    checks += 3
                    for table in TABLES:
                        for statement in (f"UPDATE {table} SET recorded_at=recorded_at", f"DELETE FROM {table}"):
                            rejected(lambda statement=statement: connection.execute(text(statement)), "P0001")
                    # Include both FK-related tables so PostgreSQL reaches the
                    # truncate guard instead of stopping at FK dependency checks.
                    rejected(lambda: connection.execute(text("TRUNCATE staging.service_delivery_preparation, staging.service_delivery_completion")), "P0001")
                    rejected(lambda: connection.execute(text("TRUNCATE staging.service_delivery_completion")), "P0001")
                    print("Transactional service storage checks: PASSED | checks=", checks)
                finally:
                    outer.rollback()
            with engine.connect() as connection:
                require(counts(connection) == baseline, "Research counts changed after rollback.")
                require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalars().all() == [REVISION], "Applied revision changed.")
                for table in TABLES:
                    require(connection.execute(text("SELECT to_regclass(:table)"), {"table": table}).scalar_one() is None, "Service table survived rollback.")
                require(connection.execute(text("SELECT to_regprocedure('staging.smoke_reject_service_insert()')")).scalar_one() is None, "Test failure function survived rollback.")
                print("Rollback verified: new service tables and all test rows were not retained.")
                print("Applied revision remains:", REVISION)
                print("No Mongo connection; no personnel values displayed; only ephemeral test keys used.")
        return 0
    except Exception as error:
        print("Service storage check stopped:", type(error).__name__)
        if isinstance(error, RuntimeError):
            print(str(error))
        if isinstance(error, DBAPIError):
            print("SQL state:", getattr(error.orig, "sqlstate", None))
            print("Constraint:", getattr(getattr(error.orig, "diag", None), "constraint_name", None))
        print("No commit requested. Stop before upgrading or importing service evidence.")
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
