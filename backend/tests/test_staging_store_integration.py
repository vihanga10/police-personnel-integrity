"""Explicitly enabled PostgreSQL tests; all test records are rolled back."""

import base64
import json
import os
from contextlib import contextmanager
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text

from app.intake.staging_rows import open_row
from app.intake.staging_store import (
    StagingConflict,
    stage_file,
    stored_row,
)
from app.security.identity_crypto import IdentityCrypto
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from database import create_identity_engine
from settings import Settings


# Ordinary unit-test runs should not require a running local database.
pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_STAGING_DB_TESTS") != "1",
    reason="Set RUN_STAGING_DB_TESTS=1 to run PostgreSQL integration tests.",
)


class RollbackTestEngine:
    """Use savepoints for file transactions inside a rollback-only test."""

    def __init__(self, connection):
        self.connection = connection

    @contextmanager
    def begin(self):
        # A failed file operation rolls back its own savepoint.
        with self.connection.begin_nested():
            yield self.connection


@pytest.fixture
def staging_case(tmp_path):
    """Provide a restricted connection and disposable encryption keys."""
    key_path = tmp_path / "test-keys.json"
    keys = {
        "active_encryption_key_version": "test-enc",
        "encryption_keys": {
            "test-enc": base64.b64encode(os.urandom(32)).decode("ascii")
        },
        "active_lookup_key_version": "test-lookup",
        "lookup_keys": {
            "test-lookup": base64.b64encode(os.urandom(32)).decode("ascii")
        },
    }

    descriptor = os.open(
        key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(keys, stream)

    crypto = IdentityCrypto(key_path)
    engine = create_identity_engine(Settings())

    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                # Fail if the test accidentally uses a privileged account.
                account = connection.execute(
                    text("SELECT current_user")
                ).scalar_one()
                assert account == "police_identity_app"

                batch = {
                    "batch_id": "TEST-" + str(uuid4()),
                    "archive_sha256": "a" * 64,
                    "archive_size_bytes": 100,
                    "expected_file_count": 1,
                    "registration_receipt_id": uuid4(),
                    "registration_receipt_sha256": "b" * 64,
                    "schema_version": "1.0",
                }
                file = {
                    "archive_path": "test/original/example.csv",
                    "source_file_sha256": "c" * 64,
                    "size_bytes": 20,
                    "expected_row_count": 2,
                    "column_count": 2,
                    "columns": ["id", "value"],
                    "declared_encoding": "UTF-8",
                    "delimiter": ",",
                }

                yield (
                    RollbackTestEngine(connection),
                    connection,
                    crypto,
                    batch,
                    file,
                )
            finally:
                # Never retain test evidence in the local research database.
                transaction.rollback()
    finally:
        engine.dispose()


def stored_count(connection, table, batch_id):
    """Count only records belonging to this unique test batch."""
    return connection.execute(
        select(func.count())
        .select_from(table)
        .where(table.c.batch_id == batch_id)
    ).scalar_one()


def test_import_preserves_encrypted_values(staging_case):
    test_engine, connection, crypto, batch, file = staging_case
    rows = [["001", "සිංහල"], ["002", " spaced "]]

    result = stage_file(
        test_engine, crypto,
        batch_values=batch, file_values=file, rows=rows,
    )

    assert result.outcome == "IMPORTED"
    assert result.row_count == 2

    records = connection.execute(
        select(RawRecord.__table__)
        .where(RawRecord.batch_id == batch["batch_id"])
        .order_by(RawRecord.source_row_number)
    ).mappings().all()

    assert len(records) == 2
    assert [
        open_row(crypto, stored_row(record))["values"]
        for record in records
    ] == rows


def test_identical_reimport_creates_no_duplicates(staging_case):
    test_engine, connection, crypto, batch, file = staging_case
    rows = [["001", "first"], ["002", "second"]]

    stage_file(
        test_engine, crypto,
        batch_values=batch, file_values=file, rows=rows,
    )
    result = stage_file(
        test_engine, crypto,
        batch_values=batch, file_values=file, rows=rows,
    )

    assert result.outcome == "VERIFIED_EXISTING"
    assert stored_count(
        connection, IntakeFile.__table__, batch["batch_id"]
    ) == 1
    assert stored_count(
        connection, RawRecord.__table__, batch["batch_id"]
    ) == 2


def test_conflicting_reimport_preserves_original(staging_case):
    test_engine, connection, crypto, batch, file = staging_case
    original = [["001", "first"], ["002", "second"]]

    stage_file(
        test_engine, crypto,
        batch_values=batch, file_values=file, rows=original,
    )

    # Same declared source, different content: must not overwrite evidence.
    with pytest.raises(StagingConflict, match="Existing content differs"):
        stage_file(
            test_engine, crypto,
            batch_values=batch,
            file_values=file,
            rows=[["001", "changed"], ["002", "second"]],
        )

    # A successful comparison afterward confirms original content survived.
    result = stage_file(
        test_engine, crypto,
        batch_values=batch, file_values=file, rows=original,
    )
    assert result.outcome == "VERIFIED_EXISTING"


def test_failure_after_insert_rolls_back_file(staging_case):
    test_engine, connection, crypto, batch, file = staging_case
    file = {**file, "expected_row_count": 501}

    # The first 500 rows trigger an actual database insert.
    rows = [[str(number), "test"] for number in range(500)]
    rows.append(["wrong-width"])

    with pytest.raises(ValueError, match="Invalid structure"):
        stage_file(
            test_engine, crypto,
            batch_values=batch, file_values=file, rows=rows,
        )

    for table in (
        IntakeBatch.__table__,
        IntakeFile.__table__,
        RawRecord.__table__,
    ):
        assert stored_count(connection, table, batch["batch_id"]) == 0