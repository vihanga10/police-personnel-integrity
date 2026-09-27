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
    """Versioned recording or certification evidence for a source assertion."""

    __tablename__ = "source_attestation"
    __table_args__ = (
        CheckConstraint(
            "attestation_type IN ('RECORDED_BY', 'CERTIFIED_BY')",
            name="attestation_type",
        ),
        CheckConstraint(
            """
            actor_officer_uid IS NOT NULL
            OR actor_name_ciphertext IS NOT NULL
            OR actor_identifier_ciphertext IS NOT NULL
            OR actor_rank_asserted IS NOT NULL
            OR signature_reference_ciphertext IS NOT NULL
            OR attested_on IS NOT NULL
            """,
            name="attestation_has_value",
        ),
        CheckConstraint(
            """
            actor_name_ciphertext IS NULL
            OR octet_length(actor_name_ciphertext) > 0
            """,
            name="attestation_actor_name",
        ),
        CheckConstraint(
            """
            actor_identifier_ciphertext IS NULL
            OR octet_length(actor_identifier_ciphertext) > 0
            """,
            name="attestation_actor_identifier",
        ),
        CheckConstraint(
            """
            signature_reference_ciphertext IS NULL
            OR octet_length(signature_reference_ciphertext) > 0
            """,
            name="attestation_signature",
        ),
        CheckConstraint(
            """
            (
                actor_name_ciphertext IS NULL
                AND actor_identifier_ciphertext IS NULL
                AND signature_reference_ciphertext IS NULL
            )
            OR (
                encryption_key_version IS NOT NULL
                AND length(encryption_key_version) > 0
            )
            """,
            name="attestation_encryption_key",
        ),
        CheckConstraint(
            """
            actor_identifier_lookup_hmac IS NULL
            OR actor_identifier_lookup_hmac ~ '^[0-9a-f]{64}$'
            """,
            name="attestation_lookup_hmac",
        ),
        CheckConstraint(
            """
            actor_identifier_lookup_hmac IS NULL
            OR (
                lookup_key_version IS NOT NULL
                AND length(lookup_key_version) > 0
                AND actor_identifier_type IS NOT NULL
            )
            """,
            name="attestation_lookup_key",
        ),
        CheckConstraint(
            """
            actor_identifier_type IS NULL
            OR actor_identifier_type IN (
                'NIC',
                'POLICE_ID',
                'REGIMENTAL_NUMBER'
            )
            """,
            name="attestation_identifier_type",
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

    actor_name_ciphertext: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
    )

    actor_identifier_type: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    actor_identifier_ciphertext: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
    )

    actor_identifier_lookup_hmac: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    actor_rank_asserted: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    signature_reference_ciphertext: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
    )

    attested_on: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )

    encryption_key_version: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    lookup_key_version: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
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