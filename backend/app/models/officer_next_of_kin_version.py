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


class OfficerNextOfKinVersion(Base):
    """A versioned next-of-kin designation for an officer."""

    __tablename__ = "officer_next_of_kin_version"
    __table_args__ = (
        CheckConstraint(
            "length(trim(related_person_name)) > 0",
            name="officer_next_of_kin_has_name",
        ),
        CheckConstraint(
            "length(trim(relationship_type)) > 0",
            name="officer_next_of_kin_has_relationship",
        ),
        CheckConstraint(
            """
            address_ciphertext IS NULL
            OR octet_length(address_ciphertext) > 0
            """,
            name="officer_next_of_kin_address",
        ),
        CheckConstraint(
            """
            address_ciphertext IS NULL
            OR (
                encryption_key_version IS NOT NULL
                AND length(encryption_key_version) > 0
            )
            """,
            name="officer_next_of_kin_encryption_key",
        ),
        CheckConstraint(
            "version_number > 0",
            name="officer_next_of_kin_positive_version",
        ),
        CheckConstraint(
            """
            valid_to IS NULL
            OR valid_from IS NULL
            OR valid_to >= valid_from
            """,
            name="officer_next_of_kin_valid_period",
        ),
        CheckConstraint(
            """
            transaction_end IS NULL
            OR transaction_end > transaction_start
            """,
            name="officer_next_of_kin_transaction_period",
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
            name="officer_next_of_kin_record_state",
        ),
        UniqueConstraint(
            "next_of_kin_chain_uid",
            "version_number",
            name="uq_officer_next_of_kin_chain_version",
        ),
        Index(
            "ix_officer_next_of_kin_officer",
            "officer_uid",
        ),
        Index(
            "ix_officer_next_of_kin_valid_time",
            "officer_uid",
            "valid_from",
            "valid_to",
        ),
# Prevent two replacements from superseding the same evidence version.
        Index(
            "uq_officer_next_of_kin_version_predecessor",
            "supersedes_next_of_kin_version_id",
             unique=True,
             postgresql_where=text(
            "supersedes_next_of_kin_version_id IS NOT NULL"
            ),
        ),
    )

    next_of_kin_version_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    next_of_kin_chain_uid: Mapped[UUID] = mapped_column(
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

    family_relation_version_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.officer_family_relation.family_relation_version_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    source_assertion_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.source_assertion.source_assertion_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    supersedes_next_of_kin_version_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.officer_next_of_kin_version.next_of_kin_version_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    related_person_name: Mapped[str] = mapped_column(
        String(300),
        nullable=False,
    )

    relationship_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    address_ciphertext: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
    )

    encryption_key_version: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
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