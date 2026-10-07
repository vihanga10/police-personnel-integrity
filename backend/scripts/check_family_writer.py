"""Rollback-only receipt migration and atomic writer checks using synthetic fixtures.

Run at f28b6d40ea73 before applying a39c7e51fb84. No Mongo connection, production
keys, personnel decryption or persistent test rows. Fixtures use the migrator;
application privileges are inspected, not exercised through role impersonation.
"""
import base64
from dataclasses import asdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback
from unittest.mock import patch
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import URL, create_engine, inspect, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool
from app.db.base import Base
from app.db.staging_base import StagingBase
from app.models import Officer, OfficerIdentifierVersion, SourceAssertion, SourceSystem
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.staging.identity_decision import IdentityRegistrationDecision
from app.identity import family_writer, import_families
from app.identity.family_records import FILENAME
from app.identity.normalization import NORMALIZATION_PROFILE, normalize_identifier
from app.identity.registration_service import REGISTRATION_LOCK, evidence_context
from app.identity.inspect_service_plans import CONFIRMATION
from app.identity.inspect_remaining_sources import HEADERS
from app.intake.staging_rows import seal_row
from app.security.identity_crypto import IdentityCrypto
from migration_settings import MigrationSettings

REVISION = "f28b6d40ea73"
TABLE = "staging.family_transform_receipt"


def require(condition, reason):
    if not condition: raise RuntimeError(reason)


def counts(connection, receipt=False):
    names = sorted(set(Base.metadata.tables) | set(StagingBase.metadata.tables))
    if not receipt: names.remove(TABLE)
    return {n: connection.execute(text("SELECT count(*) FROM " + n)).scalar_one() for n in names}


def fixture(connection, crypto, backup, *, sparse=False):
    """Create a completely unrelated source, subject and NIC inside the rollback."""
    batch, archive = "FAMILY-SMOKE-" + uuid4().hex, "a" * 64
    officer, identifier, nic_assertion, file_id = (uuid4() for _ in range(4))
    nic_text = "ROLLBACK-NIC-" + uuid4().hex
    row = dict.fromkeys(HEADERS[FILENAME], "")
    row.update(officer_nic_no=nic_text)
    if not sparse:
        row.update(spouse_name="ROLLBACK-SPOUSE", spouse_date_of_birth="1990-01-02",
            date_of_marriage="2010-01-02", reference_Marriage_certificate="TEST-MARRIAGE",
            date_of_divorce="2015-01-02", reference_divorce_certificate="TEST-DIVORCE",
            children_no="2", childern_fullname="ROLLBACK-CHILD-A;ROLLBACK-CHILD-B", children_age="4;7",
            next_of_near_relative_name="ROLLBACK-KIN", next_of_relative_relationship="REPORTED-OTHER",
            next_of_relative_address="ROLLBACK-ADDRESS", recorded_by_officer_nic=nic_text,
            recorded_by_officer_name="ROLLBACK-ACTOR", recorded_by_officer_rank="SP",
            recorded_by_signature="TEST-SIGNATURE", Certified_signed_date="2020-01-02",
            date_of_death="not-a-date", reference_death_certificate="UNRESOLVED-DECEASED")
    connection.execute(IntakeBatch.__table__.insert().values(batch_id=batch, archive_sha256=archive, archive_size_bytes=1,
        expected_file_count=1, registration_receipt_id=uuid4(), registration_receipt_sha256="d" * 64, schema_version="1.0"))
    digest = hashlib.sha256((batch + FILENAME).encode()).hexdigest()
    sealed = seal_row(crypto, batch_id=batch, archive_path=FILENAME, source_file_sha256=digest,
        source_row_number=1, columns=list(row), values=list(row.values()))
    connection.execute(IntakeFile.__table__.insert().values(import_file_id=file_id, batch_id=batch, archive_path=FILENAME,
        source_file_sha256=digest, size_bytes=1, expected_row_count=1, column_count=len(row), columns=list(row), declared_encoding="UTF-8", delimiter=","))
    connection.execute(RawRecord.__table__.insert().values(**asdict(sealed), import_file_id=file_id))
    connection.execute(Officer.__table__.insert().values(officer_uid=officer, registry_state="REGISTERED"))
    source_id = connection.execute(select(SourceSystem.source_system_id).where(SourceSystem.source_system_code == "POLICE_HR_IS")).scalar_one()
    nic = normalize_identifier(nic_text, identifier_type="NIC")
    claim = dict(schema_version="1.0", source_column="officer_nic_no", reported_value=nic_text,
        normalized_value=nic.value, identifier_type="NIC", normalization_profile=NORMALIZATION_PROFILE,
        raw_record_id=sealed.raw_record_id, source_confirmation_sha256=CONFIRMATION)
    cipher, version = crypto.encrypt_assertion(claim, context=evidence_context("ASSERTION", nic_assertion))
    connection.execute(SourceAssertion.__table__.insert().values(source_assertion_id=nic_assertion, officer_uid=officer,
        source_system_id=source_id, intake_batch_id=batch, import_file_id=str(file_id), raw_record_id=sealed.raw_record_id,
        source_file_name=FILENAME, source_file_sha256=digest, source_row_number=1, assertion_type="IDENTIFIER_NIC",
        asserted_value_ciphertext=cipher, encryption_key_version=version, independence_status="UNVERIFIED"))
    cipher, version = crypto.encrypt(nic.value.encode(), context=evidence_context("IDENTIFIER", identifier))
    lookup, lookup_version = crypto.lookup_hmac(nic.value, identifier_type="NIC")
    connection.execute(OfficerIdentifierVersion.__table__.insert().values(identifier_version_id=identifier,
        identifier_chain_uid=uuid4(), officer_uid=officer, source_assertion_id=nic_assertion, identifier_type="NIC",
        identifier_value_ciphertext=cipher, identifier_lookup_hmac=lookup, normalization_profile=NORMALIZATION_PROFILE,
        encryption_key_version=version, lookup_key_version=lookup_version, version_number=1, record_state="ASSERTED"))
    raw = connection.execute(select(RawRecord.__table__).where(RawRecord.raw_record_id == sealed.raw_record_id)).mappings().one()
    file = connection.execute(select(IntakeFile.__table__).where(IntakeFile.import_file_id == file_id)).mappings().one()
    # Patch only the test workflow's batch pin; shared NIC confirmation stays pinned.
    with patch.object(import_families, "BATCH", batch), patch.object(import_families, "ARCHIVE", archive):
        payload, binding, _ = import_families.family_payload(connection, crypto, backup, raw, file, "0" * 40, {}, {})
    return batch, archive, payload, binding


class InjectedFailure(RuntimeError): pass


class InterruptedConnection:
    """Inject a failure after each real INSERT without replacing real SQL operations."""
    def __init__(self, connection, after): self.connection, self.after, self.insertions = connection, after, 0
    def execute(self, statement, *args, **kwargs):
        result = self.connection.execute(statement, *args, **kwargs)
        if getattr(statement, "is_insert", False):
            self.insertions += 1
            if self.insertions == self.after: raise InjectedFailure("Injected atomic-write interruption")
        return result


def main():
    engine, checks = None, 0
    try:
        settings = MigrationSettings()
        require((settings.host, settings.port, settings.name, settings.user) == ("127.0.0.1", 5432, "police_identity", "police_identity_migrator"), "Unexpected migration target.")
        engine = create_engine(URL.create("postgresql+psycopg", username=settings.user, password=settings.password.get_secret_value(),
            host=settings.host, port=settings.port, database=settings.name), poolclass=NullPool, hide_parameters=True, connect_args={"connect_timeout": 5})
        spec = importlib.util.spec_from_file_location("family_receipt_migration", BACKEND / "migrations/versions/a39c7e51fb84_add_family_transform_receipt.py")
        migration = importlib.util.module_from_spec(spec); spec.loader.exec_module(migration)
        with tempfile.TemporaryDirectory() as directory:
            key = base64.b64encode(os.urandom(32)).decode()
            material = dict(active_encryption_key_version="EPHEMERAL", active_lookup_key_version="EPHEMERAL", encryption_keys={"EPHEMERAL": key}, lookup_keys={"EPHEMERAL": key})
            paths = [Path(directory) / name for name in ("primary.json", "backup.json")]
            for path in paths: path.write_text(json.dumps(material)); path.chmod(0o600)
            crypto, backup = (IdentityCrypto(p) for p in paths)
            with engine.connect() as connection:
                outer = connection.begin()
                try:
                    connection.execute(text("SET LOCAL lock_timeout = '5s'"))
                    connection.execute(text("SET LOCAL statement_timeout = '30s'"))
                    connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": REGISTRATION_LOCK})
                    require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalar_one() == REVISION, "Run before receipt migration at f28b6d40ea73.")
                    baseline = counts(connection)
                    for name, number in {"identity.officer": 6596, "identity.source_assertion": 147327,
                        "identity.remaining_source_assertion": 36694, "identity.officer_family_relation": 6596,
                        "identity.officer_family_civil_event_version": 0, "identity.officer_next_of_kin_version": 0,
                        "identity.source_attestation": 0, "identity.source_assertion_classification": 0}.items():
                        require(baseline[name] == number, "Family baseline differs.")
                    with Operations.context(MigrationContext.configure(connection)): migration.upgrade()
                    context = MigrationContext.configure(connection, opts=dict(target_metadata=[Base.metadata, StagingBase.metadata], include_schemas=True,
                        include_name=lambda name, kind, parent: name in {"identity", "staging"} if kind == "schema" else name != "alembic_version" if kind == "table" else True))
                    require(not compare_metadata(context, [Base.metadata, StagingBase.metadata]), "Schema/model differences detected."); checks += 1
                    for privilege, expected in (("SELECT", True), ("INSERT", True), ("UPDATE", False), ("DELETE", False), ("TRUNCATE", False)):
                        require(connection.execute(text("SELECT has_table_privilege('police_identity_app',:table,:privilege)"), {"table": TABLE, "privilege": privilege}).scalar_one() is expected, "Family receipt app privilege differs."); checks += 1
                    def rejected(action, state):
                        nonlocal checks
                        nested = connection.begin_nested()
                        try:
                            action()
                        except DBAPIError as error:
                            require(getattr(error.orig, "sqlstate", None) == state, "Unexpected rejection SQL state.")
                            checks += 1
                        else: raise RuntimeError("Expected rejection was not enforced.")
                        finally: nested.rollback()
                    for sparse in (False, True):
                        batch, archive, payload, binding = fixture(connection, crypto, backup, sparse=sparse)
                        options = dict(binding=binding, payload=payload)
                        with patch.object(family_writer, "BATCH", batch), patch.object(family_writer, "ARCHIVE", archive):
                            require(family_writer.transform(connection, crypto, backup, **options)[0] == "PLANNED", "Read-only state differs."); checks += 1
                            before = counts(connection, receipt=True)
                            # Every INSERT boundary, including after the receipt, must roll back.
                            insertions = len(family_writer.logical_records(payload)) + 2
                            for cut in range(1, insertions + 1):
                                nested = connection.begin_nested()
                                try:
                                    family_writer.transform(InterruptedConnection(connection, cut), crypto, backup, **options, allow_write=True)
                                except InjectedFailure: pass
                                else: raise RuntimeError("Interruption was not reached.")
                                finally: nested.rollback()
                                require(counts(connection, receipt=True) == before, "Interrupted family row retained partial evidence."); checks += 1
                            created = family_writer.transform(connection, crypto, backup, **options, allow_write=True)
                            require(created[0] == "CREATED", "Family creation differs."); checks += 1
                            after = counts(connection, receipt=True)
                            for mode in (False, True):
                                require(family_writer.transform(connection, crypto, backup, **options, allow_write=mode) == ("VERIFIED_EXISTING", created[1]), "Family replay differs.")
                                require(counts(connection, receipt=True) == after, "Family replay added rows."); checks += 1
                            saved = connection.execute(select(family_writer.RECEIPT).where(family_writer.RECEIPT.c.raw_record_id == binding.raw_record_id)).mappings().one()
                            for statement in ("UPDATE staging.family_transform_receipt SET policy_version=policy_version WHERE raw_record_id=:id",
                                "DELETE FROM staging.family_transform_receipt WHERE raw_record_id=:id", "TRUNCATE staging.family_transform_receipt"):
                                rejected(lambda statement=statement: connection.execute(text(statement), {"id": binding.raw_record_id}), "P0001")
                            bad = dict(saved); bad["source_assertion_id"] = uuid4()
                            rejected(lambda: connection.execute(family_writer.RECEIPT.insert().values(**bad)), "P0001")
                            # Authenticate chain IDs: a forged receipt reference fails even
                            # though ciphertext itself was not altered in the database.
                            from copy import deepcopy
                            evidence = family_writer.recover(crypto, backup, saved["evidence_ciphertext"], saved["encryption_key_version"],
                                family_writer.aad("RECEIPT", binding.raw_record_id, saved["officer_uid"], saved["source_assertion_id"], saved["source_assertion_id"], "family_transform_receipt"))
                            if evidence["records"]:
                                tampered = deepcopy(evidence); tampered["records"][0]["chain_id"] = str(uuid4())
                                forged = dict(saved)
                                forged["evidence_ciphertext"], forged["encryption_key_version"] = family_writer.seal(crypto, backup, tampered,
                                    family_writer.aad("RECEIPT", binding.raw_record_id, saved["officer_uid"], saved["source_assertion_id"], saved["source_assertion_id"], "family_transform_receipt"))
                                try: family_writer.verify_saved(connection, crypto, backup, binding, payload, forged,
                                    connection.execute(select(RawRecord.__table__).where(RawRecord.raw_record_id == binding.raw_record_id)).mappings().one())
                                except ValueError: checks += 1
                                else: raise RuntimeError("Altered family destination reference accepted.")
                    print("Transactional family writer checks: PASSED | checks=", checks)
                finally: outer.rollback()
            with engine.connect() as connection:
                require(counts(connection) == baseline, "Rollback counts differ.")
                require(not inspect(connection).has_table("family_transform_receipt", schema="staging"), "Receipt table retained.")
                require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalar_one() == REVISION, "Applied revision changed.")
                require(connection.execute(text("SELECT to_regprocedure('identity.guard_family_receipt_insert()')")).scalar_one() is None, "Receipt function retained.")
            print("Rollback verified: receipt table/functions and synthetic family rows not retained.")
            print("Applied revision remains:", REVISION)
            print("No Mongo connection, personnel values or production encryption keys used.")
            print("Application privileges inspected; fixtures used migrator. Actual application imports remain pending.")
        return 0
    except Exception as error:
        print("Family writer check stopped:", type(error).__name__)
        # Print code locations only: no SQL, parameters, credentials or payloads.
        for frame in traceback.extract_tb(error.__traceback__):
            if Path(frame.filename).name in {"check_family_writer.py", "family_writer.py", "import_families.py"}:
                print("Code location:", Path(frame.filename).name, frame.name, "line=", frame.lineno)
        if isinstance(error, DBAPIError): print("SQL state:", getattr(error.orig, "sqlstate", None))
        elif isinstance(error, RuntimeError): print(str(error))
        print("No commit requested. Review before the receipt upgrade or family import.")
        return 1
    finally:
        if engine is not None: engine.dispose()


if __name__ == "__main__": raise SystemExit(main())
