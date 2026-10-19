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


class SourceAttestation(Base):
    """Encrypted recording/certification claims; metadata does not verify authority."""

    __tablename__ = "source_attestation"
    __table_args__ = (
        # Personnel values, including reported dates, live only in this envelope.
        CheckConstraint("octet_length(profile_payload_ciphertext) > 28", name="family_payload_present"),
        CheckConstraint("length(trim(encryption_key_version)) > 0", name="family_key_present"),
        CheckConstraint(
            "attestation_type IN ('RECORDED_BY', 'CERTIFIED_BY')",
            name="attestation_type",
        ),
        CheckConstraint(
            """
            resolution_status IN (
                'UNRESOLVED',
                'RESOLVED',
                'AMBIGUOUS',
                'NOT_SUPPLIED'
            )
            """,
            name="attestation_resolution",
        ),
        CheckConstraint(
            """
            (
                resolution_status = 'RESOLVED'
                AND actor_officer_uid IS NOT NULL
            )
            OR (
                resolution_status <> 'RESOLVED'
                AND actor_officer_uid IS NULL
            )
            """,
            name="attestation_resolved_actor",
        ),
        CheckConstraint(
            "version_number > 0",
            name="attestation_positive_version",
        ),
        CheckConstraint(
            """
            transaction_end IS NULL
            OR transaction_end > transaction_start
            """,
            name="attestation_transaction_period",
        ),
        CheckConstraint(
            """
            record_state IN (
                'ACTIVE',
                'SUPERSEDED',
                'DISPUTED',
                'WITHDRAWN'
            )
            """,
            name="attestation_record_state",
        ),
        UniqueConstraint(
            "attestation_chain_uid",
            "version_number",
            name="uq_source_attestation_chain_version",
        ),
        Index(
            "ix_source_attestation_assertion",
            "source_assertion_id",
        ),
        Index(
            "ix_source_attestation_actor",
            "actor_officer_uid",
        ),
# Prevent two replacements from superseding the same evidence version.
        Index(
            "uq_source_attestation_predecessor",
            "supersedes_attestation_version_id",
             unique=True,
             postgresql_where=text(
            "supersedes_attestation_version_id IS NOT NULL"
            ),
        ),
    )

    attestation_version_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    attestation_chain_uid: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
        default=uuid4,
    )

    source_assertion_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.source_assertion.source_assertion_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    actor_officer_uid: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.officer.officer_uid",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    supersedes_attestation_version_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.source_attestation.attestation_version_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    attestation_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )










    resolution_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="UNRESOLVED",
        server_default=text("'UNRESOLVED'"),
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
        default="ACTIVE",
        server_default=text("'ACTIVE'"),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Uniform protected-payload columns match the existing encrypted family relation.
    profile_payload_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_key_version: Mapped[str] = mapped_column(String(50), nullable=False)
