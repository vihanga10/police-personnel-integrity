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
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class OfficerIdentifierVersion(Base):
    """A protected, versioned source identifier belonging to an officer."""

    __tablename__ = "officer_identifier_version"
    __table_args__ = (
        CheckConstraint(
            """
            identifier_type IN (
                'NIC',
                'POLICE_ID',
                'REGIMENTAL_NUMBER',
                'TIN'
            )
            """,
            name="officer_identifier_type",
        ),
        CheckConstraint(
            "version_number > 0",
            name="officer_identifier_positive_version",
        ),
        CheckConstraint(
            "octet_length(identifier_value_ciphertext) > 0",
            name="officer_identifier_has_ciphertext",
        ),
        CheckConstraint(
            "identifier_lookup_hmac ~ '^[0-9a-f]{64}$'",
            name="officer_identifier_valid_lookup_hmac",
        ),
        CheckConstraint(
            "length(encryption_key_version) > 0",
            name="officer_identifier_encryption_key_version",
        ),
        CheckConstraint(
            "length(lookup_key_version) > 0",
            name="officer_identifier_lookup_key_version",
        ),
        CheckConstraint(
            """
            valid_to IS NULL
            OR valid_from IS NULL
            OR valid_to >= valid_from
            """,
            name="officer_identifier_valid_period",
        ),
        CheckConstraint(
            """
            transaction_end IS NULL
            OR transaction_end > transaction_start
            """,
            name="officer_identifier_transaction_period",
        ),
        CheckConstraint(
            """
            record_state IN (
                'ASSERTED',
                'ACCEPTED',
                'SUPERSEDED',
                'DISPUTED',
                'WITHDRAWN'
            )
            """,
            name="officer_identifier_record_state",
        ),
        UniqueConstraint(
            "identifier_chain_uid",
            "version_number",
            name="uq_officer_identifier_chain_version",
        ),
        Index(
            "ix_officer_identifier_officer_type",
            "officer_uid",
            "identifier_type",
        ),
        Index(
            "ix_officer_identifier_lookup_hmac",
            "identifier_type",
            "identifier_lookup_hmac",
        ),
    )

    identifier_version_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    identifier_chain_uid: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
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

    source_assertion_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.source_assertion.source_assertion_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    supersedes_identifier_version_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.officer_identifier_version.identifier_version_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    identifier_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    identifier_value_ciphertext: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )

    identifier_lookup_hmac: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    normalization_profile: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    encryption_key_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    lookup_key_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    version_number: Mapped[int] = mapped_column(
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

    transaction_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    transaction_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    record_state: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="ASSERTED",
        server_default=text("'ASSERTED'"),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )