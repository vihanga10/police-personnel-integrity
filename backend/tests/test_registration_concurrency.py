"""Opt-in committed concurrency test; uses an empty disposable database only.

This test leaves fictional test records committed. Recreate the disposable
container before repeating it or rerunning tests that require an empty registry.
"""
import base64
import csv
import hashlib
import io
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from uuid import uuid4

import pytest
from sqlalchemy import event, func, insert, select, text

from database import create_identity_engine
from settings import Settings
from app.identity import registration_service as service
from app.intake.staging_rows import seal_row
from app.models import Officer, OfficerIdentifierVersion, SourceAssertion, SourceSystem
from app.security.identity_crypto import IdentityCrypto
from app.staging.identity_decision import IdentityRegistrationDecision
from app.staging.models import IntakeBatch, IntakeFile, RawRecord

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_IDENTITY_COMMIT_TESTS") != "1",
    reason="Requires explicit permission to commit fictional test records.",
)
COUNT_MODELS = (
    Officer, SourceAssertion, OfficerIdentifierVersion,
    IdentityRegistrationDecision, SourceSystem,
)

def counts(connection):
    return tuple(
        connection.execute(select(func.count()).select_from(model.__table__)).scalar_one()
        for model in COUNT_MODELS
    )

@pytest.fixture
def committed_case(tmp_path):
    settings = Settings()
    if settings.host != "127.0.0.1" or settings.port != 55432:
        pytest.fail("Committed tests require the isolated server on 127.0.0.1:55432.")
    engine = create_identity_engine(settings)
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                account, database = connection.execute(
                    text("SELECT current_user, current_database()")
                ).one()
                if account != "police_identity_app" or database != "police_identity":
                    raise RuntimeError("Use the restricted identity application account.")
                # Do not mix test keyrings with an already populated identity registry.
                if any(counts(connection)[:4]):
                    pytest.fail(
                        "Committed tests need an empty identity registry in an isolated "
                        "database. Existing identity records were not changed."
                    )

                def key():
                    return base64.b64encode(os.urandom(32)).decode("ascii")

                key_path = tmp_path / "test-keys.json"
                key_path.write_text(json.dumps({
                    "active_encryption_key_version": "test-enc-v1",
                    "encryption_keys": {"test-enc-v1": key()},
                    "active_lookup_key_version": "test-lookup-v1",
                    "lookup_keys": {
                        "test-lookup-v1": key(), "test-lookup-v2": key(),
                    },
                }), encoding="utf-8")
                key_path.chmod(0o600)
                crypto = IdentityCrypto(key_path)

                batch_id = f"TEST-REGISTRATION-{uuid4()}"
                file_id = uuid4()
                archive_path = f"{batch_id}/original/{service.PROFILE_FILENAME}"
                columns = list(service.IDENTIFIER_FIELDS)

                def profile():
                    token = uuid4().hex
                    # These fictional text identifiers are not NIC-validity fixtures.
                    return [f"TEST-NIC-{token}", f"TEST-POLICE-{token}", "", f"TEST-TIN-{token}"]

                first = profile()
                missing_nic = profile()
                missing_nic[0] = ""
                rows = [first, profile(), list(first), missing_nic, profile()]
                buffer = io.StringIO(newline="")
                writer = csv.writer(buffer)
                writer.writerow(columns)
                writer.writerows(rows)
                csv_bytes = buffer.getvalue().encode("utf-8")
                file_hash = hashlib.sha256(csv_bytes).hexdigest()
                archive_hash = hashlib.sha256(batch_id.encode("utf-8")).hexdigest()

                confirmation_path = tmp_path / "confirmation.json"
                confirmation_path.write_text(json.dumps({
                    "schema_version": "1.0",
                    "confirmation_id": f"TEST-CONFIRMATION-{uuid4()}",
                    "batch_id": batch_id,
                    "archive_sha256": archive_hash,
                    "confirmed_on": "2026-10-06",
                    "confirmed_by": "Test fixture",
                    "confirmation_basis": "Test-only attribution",
                    "scope": "Reported supplying source",
                    "original_archive_modified": False,
                    "independent_custodian_verification": "NOT_ESTABLISHED",
                    "source_independence": "UNVERIFIED",
                    "source_truth": "NOT_ASSESSED",
                    "files": [{
                        "file_name": service.PROFILE_FILENAME,
                        "reported_source_system_code": "PF_REGISTRY",
                    }],
                }), encoding="utf-8")
                confirmation_hash = hashlib.sha256(confirmation_path.read_bytes()).hexdigest()

                connection.execute(insert(IntakeBatch.__table__), {
                    "batch_id": batch_id, "archive_sha256": archive_hash,
                    "archive_size_bytes": len(csv_bytes), "expected_file_count": 1,
                    "registration_receipt_id": uuid4(),
                    "registration_receipt_sha256": "b" * 64, "schema_version": "1.0",
                })
                connection.execute(insert(IntakeFile.__table__), {
                    "import_file_id": file_id, "batch_id": batch_id,
                    "archive_path": archive_path, "source_file_sha256": file_hash,
                    "size_bytes": len(csv_bytes), "expected_row_count": len(rows),
                    "column_count": len(columns), "columns": columns,
                    "declared_encoding": "UTF-8", "delimiter": ",",
                })
                row_ids = []
                for number, values in enumerate(rows, 1):
                    sealed = seal_row(
                        crypto, batch_id=batch_id, archive_path=archive_path,
                        source_file_sha256=file_hash, source_row_number=number,
                        columns=columns, values=values,
                    )
                    stored = {**asdict(sealed), "import_file_id": file_id}
                    if number == 5:
                        # Insert a deliberately damaged test envelope, never alter real rows.
                        damaged = bytearray(stored["payload_ciphertext"])
                        damaged[-1] ^= 1
                        stored["payload_ciphertext"] = bytes(damaged)
                    connection.execute(insert(RawRecord.__table__), stored)
                    row_ids.append(sealed.raw_record_id)

                # Publish fixtures so independent sessions can read them.
                transaction.commit()
                # Return the fixture connection so both pool slots are available.
                connection.close()
                yield {
                    "connection": connection, "engine": engine,
                    "crypto": crypto,
                    "row_ids": row_ids, "rows": rows,
                    "confirmation_path": confirmation_path,
                    "confirmation_hash": confirmation_hash,
                }
            finally:
                # Committed test evidence stays in this disposable database.
                # Never delete records from the application's real database.
                if transaction.is_active:
                    transaction.rollback()
    finally:
        engine.dispose()


def test_overlapping_commits_create_one_officer(committed_case):
    case = committed_case
    engine = case["engine"]
    acquired = threading.Event()
    release = threading.Event()
    waiter_started = threading.Event()
    pids = {}

    def before_execute(connection, cursor, statement, parameters, context, many):
        if "pg_advisory_xact_lock" in statement:
            # Record session IDs without inspecting encrypted or personnel values.
            name = threading.current_thread().name
            pids[name] = connection.connection.driver_connection.info.backend_pid
            if name.endswith("_1"):
                waiter_started.set()

    def after_execute(connection, cursor, statement, parameters, context, many):
        if "pg_advisory_xact_lock" in statement:
            if threading.current_thread().name.endswith("_0"):
                # Hold the first transaction until PostgreSQL confirms contention.
                acquired.set()
                if not release.wait(15):
                    raise RuntimeError("Timed out waiting for concurrency verification.")

    def register():
        return service.register_personal_row(
            engine, case["crypto"], raw_record_id=case["row_ids"][0],
            confirmation_path=case["confirmation_path"],
            expected_confirmation_sha256=case["confirmation_hash"],
            code_revision="a" * 40,
        )

    event.listen(engine, "before_cursor_execute", before_execute)
    event.listen(engine, "after_cursor_execute", after_execute)
    observer = create_identity_engine(Settings())
    try:
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="registration") as pool:
            try:
                first = pool.submit(register)
                assert acquired.wait(10), "First registration did not acquire the lock."
                second = pool.submit(register)
                assert waiter_started.wait(10), "Second registration did not start."
                holder_pid = pids["registration_0"]
                waiter_pid = pids["registration_1"]
                assert holder_pid != waiter_pid
                deadline = time.monotonic() + 10
                blocked = False
                with observer.connect() as connection:
                    while time.monotonic() < deadline:
                        blockers = connection.execute(
                            text("SELECT pg_blocking_pids(:pid)"), {"pid": waiter_pid}
                        ).scalar_one()
                        if holder_pid in blockers:
                            blocked = True
                            break
                        time.sleep(0.02)
                assert blocked, "PostgreSQL did not observe the second session waiting."
            finally:
                # Always free the worker, including when an assertion fails.
                release.set()
            created = first.result(timeout=15)
            replay = second.result(timeout=15)

        assert created.outcome == "CREATED" and not created.replayed
        assert replay.replayed
        assert replay.officer_uid == created.officer_uid
        assert replay.decision_id == created.decision_id
        # Query from a separate connection after both real commits completed.
        with observer.connect() as connection:
            assert counts(connection) == (1, 3, 3, 1, 1)
    finally:
        release.set()
        event.remove(engine, "before_cursor_execute", before_execute)
        event.remove(engine, "after_cursor_execute", after_execute)
        observer.dispose()
