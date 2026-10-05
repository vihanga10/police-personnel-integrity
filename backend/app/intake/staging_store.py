"""Transactional persistence for verified, encrypted intake evidence."""

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy import Engine, insert, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.intake.staging_rows import StagedRow, open_row, seal_row
from app.security.identity_crypto import IdentityCrypto
from app.staging.models import IntakeBatch, IntakeFile, RawRecord


class StagingConflict(ValueError):
    """Existing evidence differs from the proposed repeat import."""


@dataclass(frozen=True)
class StagingResult:
    """Result returned only after the file transaction commits."""

    batch_id: str
    archive_path: str
    row_count: int
    outcome: str


BATCH_FIELDS = {
    "batch_id",
    "archive_sha256",
    "archive_size_bytes",
    "expected_file_count",
    "registration_receipt_id",
    "registration_receipt_sha256",
    "schema_version",
}

FILE_FIELDS = {
    "archive_path",
    "source_file_sha256",
    "size_bytes",
    "expected_row_count",
    "column_count",
    "columns",
    "declared_encoding",
    "delimiter",
}


def require_matching(
    existing: Mapping,
    expected: Mapping,
    *,
    label: str,
) -> None:
    """Compare metadata without exposing its values in error messages."""
    for field, value in expected.items():
        if existing[field] != value:
            raise StagingConflict(f"{label} differs in field: {field}")


def stored_row(record: Mapping) -> StagedRow:
    """Reconstruct the encryption envelope from a database record."""
    return StagedRow(
        raw_record_id=record["raw_record_id"],
        batch_id=record["batch_id"],
        archive_path=record["archive_path"],
        source_file_sha256=record["source_file_sha256"],
        source_row_number=record["source_row_number"],
        schema_version=record["schema_version"],
        payload_ciphertext=bytes(record["payload_ciphertext"]),
        encryption_key_version=record["encryption_key_version"],
    )


def stage_file(
    engine: Engine,
    crypto: IdentityCrypto,
    *,
    batch_values: dict,
    file_values: dict,
    rows: Iterable[list[str]],
) -> StagingResult:
    """Persist one verified file atomically, or verify an identical reimport.

    The caller must verify archive integrity and CSV structure before calling.
    The rows iterable must supply parsed strings in original column order.
    """
    if set(batch_values) != BATCH_FIELDS:
        raise ValueError("Unexpected batch metadata fields.")
    if set(file_values) != FILE_FIELDS:
        raise ValueError("Unexpected file metadata fields.")

    # Copy caller metadata so mutable header lists are not shared.
    batch_values = dict(batch_values)
    file_values = dict(file_values)
    columns = list(file_values["columns"])
    file_values["columns"] = columns

    if (
        not columns
        or any(not isinstance(name, str) or not name.strip() for name in columns)
        or len(columns) != len(set(columns))
        or file_values["column_count"] != len(columns)
    ):
        raise ValueError("Invalid file header metadata.")

    expected_count = file_values["expected_row_count"]
    if type(expected_count) is not int or expected_count < 0:
        raise ValueError("Invalid expected row count.")

    batch_id = batch_values["batch_id"]
    if not isinstance(batch_id, str) or not batch_id.strip():
        raise ValueError("Batch ID is required.")

    batch_table = IntakeBatch.__table__
    file_table = IntakeFile.__table__
    row_table = RawRecord.__table__

    # A transaction-scoped advisory lock serializes this importer's batch writes.
    # Hash collisions merely serialize unrelated batches; they do not merge them.
    lock_key = int.from_bytes(
        hashlib.sha256(
            ("STAGING_BATCH_V1:" + batch_id).encode("utf-8")
        ).digest()[:8],
        byteorder="big",
        signed=True,
    )

    with engine.begin() as connection:
        connection.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": lock_key},
        )

        # Never update an existing batch registration.
        connection.execute(
            pg_insert(batch_table)
            .values(**batch_values)
            .on_conflict_do_nothing(index_elements=["batch_id"])
        )
        existing_batch = connection.execute(
            select(batch_table).where(batch_table.c.batch_id == batch_id)
        ).mappings().one()
        require_matching(existing_batch, batch_values, label="Batch registration")

        existing_file = connection.execute(
            select(file_table).where(
                file_table.c.batch_id == batch_id,
                file_table.c.archive_path == file_values["archive_path"],
            )
        ).mappings().one_or_none()

        is_repeat = existing_file is not None

        if is_repeat:
            require_matching(
                existing_file, file_values, label="File registration"
            )
            file_id = existing_file["import_file_id"]

            # Fetch this file's encrypted records for complete repeat comparison.
            existing_rows = {
                record["source_row_number"]: record
                for record in connection.execute(
                    select(row_table).where(
                        row_table.c.import_file_id == file_id
                    )
                ).mappings()
            }
            if len(existing_rows) != expected_count:
                raise StagingConflict(
                    "Existing file has an incomplete or unexpected row count."
                )
        else:
            file_id = uuid4()
            connection.execute(
                insert(file_table).values(
                    import_file_id=file_id,
                    batch_id=batch_id,
                    **file_values,
                )
            )
            existing_rows = {}

        pending = []
        count = 0

        for count, values in enumerate(rows, start=1):
            if count > expected_count:
                raise StagingConflict("Input contains more rows than registered.")
            if (
                len(values) != len(columns)
                or any(not isinstance(value, str) for value in values)
            ):
                raise ValueError(f"Invalid structure at data record {count}.")

            if is_repeat:
                existing = existing_rows.get(count)
                if existing is None:
                    raise StagingConflict("Existing source-row sequence differs.")

                # Compare decrypted values, not randomized ciphertext bytes.
                payload = open_row(crypto, stored_row(existing))
                expected_payload = {
                    "schema_version": "1.0",
                    "columns": columns,
                    "values": list(values),
                }
                if payload != expected_payload:
                    raise StagingConflict(
                        f"Existing content differs at data record {count}."
                    )
            else:
                sealed = seal_row(
                    crypto,
                    batch_id=batch_id,
                    archive_path=file_values["archive_path"],
                    source_file_sha256=file_values["source_file_sha256"],
                    source_row_number=count,
                    columns=columns,
                    values=list(values),
                )
                pending.append({
                    "raw_record_id": sealed.raw_record_id,
                    "import_file_id": file_id,
                    "batch_id": sealed.batch_id,
                    "archive_path": sealed.archive_path,
                    "source_file_sha256": sealed.source_file_sha256,
                    "source_row_number": sealed.source_row_number,
                    "schema_version": sealed.schema_version,
                    "payload_ciphertext": sealed.payload_ciphertext,
                    "encryption_key_version": sealed.encryption_key_version,
                })

                # Batch inserts reduce round trips while retaining one transaction.
                if len(pending) >= 500:
                    connection.execute(insert(row_table), pending)
                    pending.clear()

        if count != expected_count:
            raise StagingConflict("Input contains fewer rows than registered.")

        if pending:
            connection.execute(insert(row_table), pending)

        # Any exception above rolls back this file's inserts automatically.

    return StagingResult(
        batch_id=batch_id,
        archive_path=file_values["archive_path"],
        row_count=count,
        outcome="VERIFIED_EXISTING" if is_repeat else "IMPORTED",
    )