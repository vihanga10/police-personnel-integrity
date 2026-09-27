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


class OfficerFamilyCivilEventVersion(Base):
    """A versioned family civil event and its protected evidence reference."""

    __tablename__ = "officer_family_civil_event_version"
    __table_args__ = (
        CheckConstraint(
            "event_type IN ('MARRIAGE', 'DIVORCE', 'DEATH')",
            name="officer_family_civil_event_type",
        ),
        CheckConstraint(
            """
            event_date IS NOT NULL
            OR evidence_reference_ciphertext IS NOT NULL
            """,
            name="officer_family_civil_event_has_value",
        ),
        CheckConstraint(
            """
            evidence_reference_ciphertext IS NULL
            OR octet_length(evidence_reference_ciphertext) > 0
            """,
            name="officer_family_civil_event_evidence_reference",
        ),
        CheckConstraint(
            """
            evidence_reference_ciphertext IS NULL
            OR (
                encryption_key_version IS NOT NULL
                AND length(encryption_key_version) > 0
            )
            """,
            name="officer_family_civil_event_encryption_key",
        ),
        CheckConstraint(
            "version_number > 0",
            name="officer_family_civil_event_positive_version",
        ),
        CheckConstraint(
            """
            transaction_end IS NULL
            OR transaction_end > transaction_start
            """,
            name="officer_family_civil_event_transaction_period",
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
            name="officer_family_civil_event_record_state",
        ),
        UniqueConstraint(
            "civil_event_chain_uid",
            "version_number",
            name="uq_officer_family_civil_event_chain_version",
        ),
        Index(
            "ix_officer_family_civil_event_officer_type",
            "officer_uid",
            "event_type",
        ),
        Index(
            "ix_officer_family_civil_event_date",
            "officer_uid",
            "event_date",
        ),
    )

    civil_event_version_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    civil_event_chain_uid: Mapped[UUID] = mapped_column(
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

    family_relation_version_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.officer_family_relation.family_relation_version_id",
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

    supersedes_civil_event_version_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.officer_family_civil_event_version.civil_event_version_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    event_date: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )

    evidence_reference_ciphertext: Mapped[bytes | None] = mapped_column(
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