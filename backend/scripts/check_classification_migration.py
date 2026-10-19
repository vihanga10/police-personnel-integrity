"""Exercise the new migration inside a transaction that is always rolled back.

Run from backend using the existing migration account. Creates a table and
test assessments temporarily; never commits or advances alembic_version.
Only reads existing evidence. Prints metadata/counts, not personnel values.
"""

import importlib.util
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from alembic.migration import MigrationContext
from alembic.operations import Operations
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import URL, create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool

from migration_settings import MigrationSettings


TABLE = "identity.source_assertion_classification"
REVISION = "a805e70f2e08"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    settings = MigrationSettings()
    require(settings.user == "police_identity_migrator", "Wrong migration account.")
    require(settings.name == "police_identity", "Wrong database configuration.")
    url = URL.create(
        "postgresql+psycopg", username=settings.user,
        password=settings.password.get_secret_value(), host=settings.host,
        port=settings.port, database=settings.name,
    )
    engine = create_engine(
        url, poolclass=NullPool, hide_parameters=True,
        connect_args={"connect_timeout": 5},
    )
    migration_path = BACKEND / "migrations/versions/c91a4b7e2036_add_assertion_classification_history.py"
    spec = importlib.util.spec_from_file_location("classification_migration_check", migration_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    checks = 0

    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(text("SET LOCAL lock_timeout = '5s'"))
                connection.execute(text("SET LOCAL statement_timeout = '30s'"))
                revisions = connection.execute(text(
                    "SELECT version_num FROM identity.alembic_version"
                )).scalars().all()
                require(revisions == [REVISION], "Applied revision is not the expected baseline.")
                require(connection.execute(text(
                    "SELECT to_regclass(:table)"
                ), {"table": TABLE}).scalar_one() is None, "Classification table already exists; stopping.")
                sources = connection.execute(text(
                    "SELECT source_assertion_id FROM identity.source_assertion "
                    "ORDER BY source_assertion_id LIMIT 2"
                )).scalars().all()
                require(len(sources) == 2, "Two existing assertions are required for binding tests.")
                context = MigrationContext.configure(connection)
                with Operations.context(context):
                    module.upgrade()
                checks += 1

                # Ephemeral test encryption only. No production key files are used.
                nonce = os.urandom(12)
                encrypted = nonce + AESGCM(AESGCM.generate_key(bit_length=256)).encrypt(
                    nonce, json.dumps({"purpose": "rollback-only schema test"}).encode(),
                    b"CLASSIFICATION_MIGRATION_TEST",
                )

                def record(source, **changes):
                    value = dict(
                        classification_id=uuid4(), source_assertion_id=source,
                        version_number=1, previous_classification_id=None,
                        previous_version_number=None, classification="UNASSESSED",
                        restricted_unit=None, reason_code="MIGRATION_TEST",
                        policy_version="CID_CCIB_PROTECTION_V1",
                        recorded_by="service:rollback-migration-test",
                        evidence_ciphertext=encrypted, encryption_key_version="ephemeral-test",
                    )
                    value.update(changes)
                    return value

                def insert(value):
                    columns = tuple(value)
                    connection.execute(text(
                        f"INSERT INTO {TABLE} (" + ",".join(columns) + ") VALUES (" +
                        ",".join(":" + name for name in columns) + ")"
                    ), value)

                def rejected(action, sqlstate):
                    nonlocal checks
                    try:
                        with connection.begin_nested():
                            action()
                    except DBAPIError as error:
                        actual = getattr(error.orig, "sqlstate", None)
                        require(actual == sqlstate, "Unexpected database rejection type.")
                        checks += 1
                    else:
                        raise RuntimeError("Database accepted a prohibited operation.")

                first = record(sources[0])
                insert(first)
                checks += 1
                second = record(
                    sources[0], version_number=2,
                    previous_classification_id=first["classification_id"], previous_version_number=1,
                    classification="CID_CCIB_RESTRICTED", restricted_unit="CID",
                )
                insert(second)
                checks += 1
                rejected(lambda: insert(record(sources[0])), "23505")
                rejected(lambda: insert(record(
                    sources[1], version_number=3,
                    previous_classification_id=second["classification_id"], previous_version_number=2,
                )), "23503")
                rejected(lambda: insert(record(
                    sources[1], version_number=3,
                    previous_classification_id=second["classification_id"], previous_version_number=1,
                )), "23514")
                rejected(lambda: insert(record(sources[1], classification="PUBLIC")), "23514")
                rejected(lambda: insert(record(
                    sources[1], classification="CID_CCIB_RESTRICTED", restricted_unit=None,
                )), "23514")
                rejected(lambda: insert(record(sources[1], restricted_unit="CID")), "23514")
                rejected(lambda: insert(record(sources[1], evidence_ciphertext=b"short")), "23514")
                rejected(lambda: connection.execute(text(
                    f"UPDATE {TABLE} SET reason_code = 'CHANGED'"
                )), "P0001")
                rejected(lambda: connection.execute(text(f"DELETE FROM {TABLE}")), "P0001")
                rejected(lambda: connection.execute(text(f"TRUNCATE TABLE {TABLE}")), "P0001")
                for privilege, allowed in (
                    ("SELECT", True), ("INSERT", False), ("UPDATE", False),
                    ("DELETE", False), ("TRUNCATE", False),
                ):
                    actual = connection.execute(text(
                        "SELECT has_table_privilege('police_identity_app', :table, :privilege)"
                    ), {"table": TABLE, "privilege": privilege}).scalar_one()
                    require(actual == allowed, "Application privileges do not match the planned grants.")
                    checks += 1
                require(connection.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar_one() == 2,
                        "Unexpected test assessment count.")
                checks += 1
                print("Transactional schema checks: PASSED | checks=", checks)
            finally:
                transaction.rollback()

        with engine.connect() as connection:
            require(connection.execute(text("SELECT to_regclass(:table)"),
                    {"table": TABLE}).scalar_one() is None, "Rollback verification failed.")
            require(connection.execute(text(
                "SELECT version_num FROM identity.alembic_version"
            )).scalars().all() == [REVISION], "Migration revision changed unexpectedly.")
        print("Rollback verified: classification table and test rows were not retained.")
        print("Applied revision remains:", REVISION)
        print("No personnel values displayed; no production encryption keys used.")
    finally:
        engine.dispose()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Avoid printing bound data or credential-bearing exception details.
        print("CHECK FAILED:", type(error).__name__)
        if isinstance(error, RuntimeError):
            print(str(error))
        print("No commit was requested. Stop and report this output.")
        raise SystemExit(1)
