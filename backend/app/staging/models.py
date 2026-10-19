"""Database models for protected, source-linked intake evidence."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.staging_base import StagingBase


class IntakeBatch(StagingBase):
    """A batch bound to one verified archive and its registration evidence."""

    __tablename__ = "intake_batch"
    __table_args__ = (
        CheckConstraint(
            "length(trim(batch_id)) > 0",
            name="batch_id_not_empty",
        ),
        CheckConstraint(
            "archive_sha256 ~ '^[0-9a-f]{64}$'",
            name="archive_sha256",
        ),
        CheckConstraint(
            "registration_receipt_sha256 ~ '^[0-9a-f]{64}$'",
            name="receipt_sha256",
        ),
        CheckConstraint(
            "archive_size_bytes > 0 AND expected_file_count > 0",
            name="positive_batch_sizes",
        ),
        CheckConstraint(
            "schema_version = '1.0'",
            name="supported_batch_schema",
        ),
    )

    batch_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    archive_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    archive_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expected_file_count: Mapped[int] = mapped_column(Integer, nullable=False)

    # Bind registration metadata by both its identifier and exact file hash.
    registration_receipt_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), nullable=False
    )
    registration_receipt_sha256: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    schema_version: Mapped[str] = mapped_column(
        String(20), nullable=False, default="1.0"
    )
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class IntakeFile(StagingBase):
    """A verified source file with its exact header and parsing contract."""

    __tablename__ = "intake_file"
    __table_args__ = (
        # A repeated import must resolve this existing registration.
        UniqueConstraint(
            "batch_id", "archive_path",
            name="uq_intake_file_batch_path",
        ),
        # This key lets raw rows enforce their complete source binding.
        UniqueConstraint(
            "import_file_id", "batch_id", "archive_path", "source_file_sha256",
            name="uq_intake_file_source_binding",
        ),
        CheckConstraint(
            "source_file_sha256 ~ '^[0-9a-f]{64}$'",
            name="file_sha256",
        ),
        CheckConstraint(
            "length(trim(archive_path)) > 0",
            name="file_path_not_empty",
        ),
        CheckConstraint(
            "size_bytes > 0 AND expected_row_count >= 0 AND column_count > 0",
            name="valid_file_counts",
        ),
        CheckConstraint(
            "jsonb_typeof(columns) = 'array'",
            name="columns_array",
        ),
        CheckConstraint(
            "jsonb_array_length(columns) = column_count",
            name="columns_count_matches",
        ),
        CheckConstraint(
            "declared_encoding IN ('UTF-8', 'UTF-8-BOM')",
            name="supported_encoding",
        ),
        CheckConstraint(
            "delimiter = ','",
            name="supported_delimiter",
        ),
    )

    import_file_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    batch_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("staging.intake_batch.batch_id", ondelete="RESTRICT"),
        nullable=False,
    )
    archive_path: Mapped[str] = mapped_column(Text, nullable=False)
    source_file_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expected_row_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    column_count: Mapped[int] = mapped_column(Integer, nullable=False)

    # Header names are metadata; personnel cell values belong in ciphertext.
    columns: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    declared_encoding: Mapped[str] = mapped_column(String(20), nullable=False)
    delimiter: Mapped[str] = mapped_column(String(1), nullable=False)
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class RawRecord(StagingBase):
    """An encrypted logical CSV record bound to its registered source file."""

    __tablename__ = "raw_record"
    __table_args__ = (
        # Block duplicate logical records even if a caller supplies another ID.
        UniqueConstraint(
            "import_file_id", "source_row_number",
            name="uq_raw_record_file_row",
        ),
        # Prevent a row from claiming metadata belonging to a different file.
        ForeignKeyConstraint(
            [
                "import_file_id",
                "batch_id",
                "archive_path",
                "source_file_sha256",
            ],
            [
                "staging.intake_file.import_file_id",
                "staging.intake_file.batch_id",
                "staging.intake_file.archive_path",
                "staging.intake_file.source_file_sha256",
            ],
            name="fk_raw_record_registered_source",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "raw_record_id ~ '^[0-9a-f]{64}$'",
            name="record_id_format",
        ),
        CheckConstraint(
            "source_file_sha256 ~ '^[0-9a-f]{64}$'",
            name="record_source_sha256",
        ),
        CheckConstraint(
            "source_row_number > 0",
            name="positive_record_number",
        ),
        CheckConstraint(
            "octet_length(payload_ciphertext) > 28",
            name="ciphertext_envelope_length",
        ),
        CheckConstraint(
            "length(trim(encryption_key_version)) > 0",
            name="key_version_not_empty",
        ),
        CheckConstraint(
            "schema_version = '1.0'",
            name="supported_record_schema",
        ),
    )

    raw_record_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    import_file_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), nullable=False
    )

    # These values reproduce the encryption context used by staging_rows.py.
    batch_id: Mapped[str] = mapped_column(String(100), nullable=False)
    archive_path: Mapped[str] = mapped_column(Text, nullable=False)
    source_file_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source_row_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    schema_version: Mapped[str] = mapped_column(
        String(20), nullable=False, default="1.0"
    )

    payload_ciphertext: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False
    )
    encryption_key_version: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    staged_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )