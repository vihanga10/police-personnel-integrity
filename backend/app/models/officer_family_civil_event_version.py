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
    """Encrypted reported civil-event claims; no plaintext type or reported date."""

    __tablename__ = "officer_family_civil_event_version"
    __table_args__ = (
        # Personnel values, including reported dates, live only in this envelope.
        CheckConstraint("octet_length(profile_payload_ciphertext) > 28", name="family_payload_present"),
        CheckConstraint("length(trim(encryption_key_version)) > 0", name="family_key_present"),
        Index("ix_officer_family_civil_event_officer", "officer_uid"),
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
# Prevent two replacements from superseding the same evidence version.
        Index(
            "uq_officer_family_civil_event_version_predecessor",
            "supersedes_civil_event_version_id",
             unique=True,
             postgresql_where=text(
            "supersedes_civil_event_version_id IS NOT NULL"
            ),
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

    # Uniform protected-payload columns match the existing encrypted family relation.
    profile_payload_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_key_version: Mapped[str] = mapped_column(String(50), nullable=False)
