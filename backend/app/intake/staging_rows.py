"""Prepare encrypted, source-linked CSV rows for protected staging."""

import hashlib
import json
import re
from dataclasses import dataclass

from app.security.identity_crypto import IdentityCrypto


@dataclass(frozen=True)
class StagedRow:
    """Encrypted row content and the metadata needed to identify its source."""

    raw_record_id: str
    batch_id: str
    archive_path: str
    source_file_sha256: str
    source_row_number: int
    schema_version: str
    payload_ciphertext: bytes
    encryption_key_version: str


def row_context(
    *,
    batch_id: str,
    archive_path: str,
    source_file_sha256: str,
    source_row_number: int,
    schema_version: str,
) -> str:
    """Build a deterministic context from source metadata, never cell values."""
    if not isinstance(batch_id, str) or not batch_id.strip():
        raise ValueError("Batch ID is required.")

    if (
        not isinstance(archive_path, str)
        or not archive_path
        or "\\" in archive_path
        or ":" in archive_path
        or "\x00" in archive_path
        or any(part in {"", ".", ".."} for part in archive_path.split("/"))
    ):
        raise ValueError("A safe relative archive path is required.")

    if (
        not isinstance(source_file_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", source_file_sha256) is None
    ):
        raise ValueError("Source SHA-256 must be lowercase hexadecimal.")

    # Number logical data records from 1, excluding the CSV header.
    if type(source_row_number) is not int or source_row_number < 1:
        raise ValueError("Source row number must be a positive integer.")

    if schema_version != "1.0":
        raise ValueError("Unsupported staging schema version.")

    return json.dumps(
        [
            "PROTECTED_STAGING_ROW_V1",
            schema_version,
            batch_id,
            archive_path,
            source_file_sha256,
            source_row_number,
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def context_record_id(context: str) -> str:
    """Derive a stable source-row reference without hashing personal values."""
    return hashlib.sha256(context.encode("utf-8")).hexdigest()


def seal_row(
    crypto: IdentityCrypto,
    *,
    batch_id: str,
    archive_path: str,
    source_file_sha256: str,
    source_row_number: int,
    columns: list[str],
    values: list[str],
) -> StagedRow:
    """Encrypt a structurally validated row without normalizing its values."""
    if (
        not columns
        or any(not isinstance(name, str) or not name.strip() for name in columns)
        or len(columns) != len(set(columns))
    ):
        raise ValueError("Column names must be nonempty and unique.")

    if len(values) != len(columns):
        raise ValueError("Row width differs from the header.")

    if any(not isinstance(value, str) for value in values):
        raise ValueError("CSV values must remain strings.")

    schema_version = "1.0"
    context = row_context(
        batch_id=batch_id,
        archive_path=archive_path,
        source_file_sha256=source_file_sha256,
        source_row_number=source_row_number,
        schema_version=schema_version,
    )

    # Lists preserve column order and exact parsed strings.
    payload = {
        "schema_version": schema_version,
        "columns": list(columns),
        "values": list(values),
    }
    ciphertext, key_version = crypto.encrypt_assertion(
        payload,
        context=context,
    )

    return StagedRow(
        raw_record_id=context_record_id(context),
        batch_id=batch_id,
        archive_path=archive_path,
        source_file_sha256=source_file_sha256,
        source_row_number=source_row_number,
        schema_version=schema_version,
        payload_ciphertext=ciphertext,
        encryption_key_version=key_version,
    )


def open_row(crypto: IdentityCrypto, row: StagedRow) -> dict[str, object]:
    """Decrypt only when the stored source metadata matches the encryption."""
    context = row_context(
        batch_id=row.batch_id,
        archive_path=row.archive_path,
        source_file_sha256=row.source_file_sha256,
        source_row_number=row.source_row_number,
        schema_version=row.schema_version,
    )
    if row.raw_record_id != context_record_id(context):
        raise ValueError("Staging record ID differs from its source metadata.")

    # AES-GCM checks that ciphertext belongs to this exact context.
    payload = crypto.decrypt_assertion(
        row.payload_ciphertext,
        key_version=row.encryption_key_version,
        context=context,
    )

    columns = payload.get("columns")
    values = payload.get("values")
    if (
        payload.get("schema_version") != row.schema_version
        or not isinstance(columns, list)
        or not isinstance(values, list)
        or not columns
        or any(not isinstance(name, str) or not name.strip() for name in columns)
        or len(columns) != len(set(columns))
        or len(columns) != len(values)
        or any(not isinstance(value, str) for value in values)
    ):
        raise ValueError("Invalid decrypted staging payload.")

    return payload