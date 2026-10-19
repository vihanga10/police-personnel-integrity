"""Versioned decisions for registering single-officer source rows."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.staging_base import StagingBase
from app.models import Officer, SourceSystem
from app.staging.models import RawRecord


class IdentityRegistrationDecision(StagingBase):
    """Preserve each registration decision and its protected explanation."""

    __tablename__ = "identity_registration_decision"
    __table_args__ = (
        # Each source row has one ordered sequence of decision versions.
        UniqueConstraint(
            "raw_record_id",
            "version_number",
            name="uq_identity_decision_row_version",
        ),
        # Provide the complete target for the predecessor relationship.
        UniqueConstraint(
            "decision_id",
            "raw_record_id",
            "version_number",
            name="uq_identity_decision_version_binding",
        ),
        # A predecessor cannot branch into two replacement decisions.
        UniqueConstraint(
            "previous_decision_id",
            name="uq_identity_decision_previous",
        ),
        # Require the predecessor to belong to this same staged row.
        ForeignKeyConstraint(
            [
                "previous_decision_id",
                "raw_record_id",
                "previous_version_number",
            ],
            [
                "staging.identity_registration_decision.decision_id",
                "staging.identity_registration_decision.raw_record_id",
                "staging.identity_registration_decision.version_number",
            ],
            name="fk_identity_decision_previous",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            """
            (
                version_number = 1
                AND previous_decision_id IS NULL
                AND previous_version_number IS NULL
            )
            OR
            (
                version_number > 1
                AND previous_decision_id IS NOT NULL
                AND previous_version_number IS NOT NULL
                AND previous_version_number > 0
                AND version_number = previous_version_number + 1
            )
            """,
            name="decision_version_chain",
        ),
        CheckConstraint(
            "outcome IN ('CREATED', 'MATCHED', 'REVIEW_REQUIRED')",
            name="decision_outcome",
        ),
        CheckConstraint(
            """
            (
                outcome IN ('CREATED', 'MATCHED')
                AND officer_uid IS NOT NULL
            )
            OR
            (
                outcome = 'REVIEW_REQUIRED'
                AND officer_uid IS NULL
            )
            """,
            name="decision_officer_binding",
        ),
        CheckConstraint(
            "source_confirmation_sha256 ~ '^[0-9a-f]{64}$'",
            name="decision_confirmation_sha256",
        ),
        CheckConstraint(
            "code_revision ~ '^[0-9a-f]{40}$'",
            name="decision_code_revision",
        ),
        CheckConstraint(
            "reason_code ~ '^[A-Z][A-Z0-9_]{0,79}$'",
            name="decision_reason_code",
        ),
        CheckConstraint(
            """
            length(trim(source_confirmation_id)) > 0
            AND length(trim(policy_version)) > 0
            AND length(trim(normalization_profile)) > 0
            AND length(trim(encryption_key_version)) > 0
            """,
            name="decision_required_metadata",
        ),
        CheckConstraint(
            "octet_length(evidence_ciphertext) > 28",
            name="decision_encrypted_evidence",
        ),
    )

    decision_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    # The raw row already links to its file, batch, checksum and row number.
    raw_record_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey(
            RawRecord.__table__.c.raw_record_id,
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    version_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    previous_decision_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=True,
    )
    previous_version_number: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(80), nullable=False)

    # Actual column references connect the two separate metadata collections.
    officer_uid: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            Officer.__table__.c.officer_uid,
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    source_system_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            SourceSystem.__table__.c.source_system_id,
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    # Preserve exactly which source declaration and rules were used.
    source_confirmation_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    source_confirmation_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    policy_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    normalization_profile: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    code_revision: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
    )

    # Candidate evidence and detailed explanations remain encrypted.
    # The writer will bind encryption to this decision and source row.
    evidence_ciphertext: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )
    encryption_key_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )