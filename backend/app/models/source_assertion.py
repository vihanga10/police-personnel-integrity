from datetime import date, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SourceAssertion(Base):
    """A source's claim about an officer's identity information."""

    __tablename__ = "source_assertion"
    __table_args__ = (
        CheckConstraint(
            "valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from",
            name="source_assertion_valid_period",
        ),
        CheckConstraint(
            """
            transaction_end IS NULL
            OR transaction_end > transaction_start
            """,
            name="source_assertion_transaction_period",
        ),
        CheckConstraint(
            "source_row_number IS NULL OR source_row_number > 0",
            name="source_assertion_positive_row_number",
        ),
        CheckConstraint(
            "source_file_sha256 ~ '^[0-9a-f]{64}$'",
            name="source_assertion_valid_sha256",
        ),
        CheckConstraint(
            "octet_length(asserted_value_ciphertext) > 0",
            name="source_assertion_has_ciphertext",
        ),
        CheckConstraint(
            "length(trim(encryption_key_version)) > 0",
            name="source_assertion_encryption_key_version",
        ),
        CheckConstraint(
            """
            length(trim(intake_batch_id)) > 0
            AND length(trim(import_file_id)) > 0
            AND length(trim(raw_record_id)) > 0
            AND length(trim(source_file_name)) > 0
            """,
            name="source_assertion_provenance_ids",
        ),
        CheckConstraint(
            """
            assertion_state IN (
                'ACTIVE',
                'SUPERSEDED',
                'WITHDRAWN',
                'DISPUTED'
            )
            """,
            name="source_assertion_state",
        ),
        CheckConstraint(
            """
            independence_status IN (
                'UNVERIFIED',
                'INDEPENDENT',
                'NOT_INDEPENDENT'
            )
            """,
            name="source_assertion_independence",
        ),
        Index(
            "ix_source_assertion_officer_type",
            "officer_uid",
            "assertion_type",
        ),
    )

    source_assertion_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    officer_uid: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.officer.officer_uid",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    source_system_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.source_system.source_system_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    assertion_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    asserted_value_ciphertext: Mapped[bytes] = mapped_column(
    LargeBinary,
    nullable=False,
    )
    encryption_key_version: Mapped[str] = mapped_column(
    String(50),
    nullable=False,
    )

    source_record_id: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True,
    )
    source_document_id: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True,
    )
    source_page: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    intake_batch_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    import_file_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    raw_record_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    source_file_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    source_file_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    source_row_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    valid_from: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )
    valid_to: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )
    source_recorded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    captured_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    transaction_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    transaction_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    assertion_state: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="ACTIVE",
        server_default=text("'ACTIVE'"),
    )
    independence_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="UNVERIFIED",
        server_default=text("'UNVERIFIED'"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )