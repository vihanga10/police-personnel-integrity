"""Append-only confidentiality assessments; absence means unassessed."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Integer,
    LargeBinary, String, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SourceAssertionClassification(Base):
    """Classification of evidence, separate from current posting restrictions.

    The officer is derived from the assertion to avoid conflicting ownership.
    Consumers must also evaluate all other sources contributing to a record.
    This model supplies no role grants or automatic declassification.
    """

    __tablename__ = "source_assertion_classification"
    __table_args__ = (
        CheckConstraint(
            "classification IN ('ORDINARY', 'CID_CCIB_RESTRICTED', 'UNASSESSED')",
            name="class_value",
        ),
        CheckConstraint(
            "(classification = 'CID_CCIB_RESTRICTED' AND restricted_unit IS NOT NULL "
            "AND restricted_unit IN ('CID', 'CCIB', 'CID_AND_CCIB')) OR "
            "(classification IN ('ORDINARY', 'UNASSESSED') AND restricted_unit IS NULL)",
            name="class_unit",
        ),
        CheckConstraint(
            "(version_number = 1 AND previous_classification_id IS NULL "
            "AND previous_version_number IS NULL) OR "
            "(version_number > 1 AND previous_classification_id IS NOT NULL "
            "AND previous_version_number IS NOT NULL "
            "AND previous_version_number = version_number - 1)",
            name="class_chain",
        ),
        CheckConstraint("octet_length(evidence_ciphertext) > 28", name="class_evidence"),
        CheckConstraint("length(trim(encryption_key_version)) > 0", name="class_key"),
        CheckConstraint("length(trim(policy_version)) > 0", name="class_policy"),
        CheckConstraint("length(trim(recorded_by)) > 0", name="class_actor"),
        CheckConstraint("reason_code ~ '^[A-Z][A-Z0-9_]{0,79}$'", name="class_reason"),
        UniqueConstraint("source_assertion_id", "version_number", name="uq_class_assertion_version"),
        UniqueConstraint(
            "classification_id", "source_assertion_id", "version_number",
            name="uq_class_identity_binding",
        ),
        UniqueConstraint("previous_classification_id", name="uq_class_predecessor"),
        ForeignKeyConstraint(
            ["previous_classification_id", "source_assertion_id", "previous_version_number"],
            ["identity.source_assertion_classification.classification_id",
             "identity.source_assertion_classification.source_assertion_id",
             "identity.source_assertion_classification.version_number"],
            name="fk_class_predecessor_binding", ondelete="RESTRICT",
        ),
    )

    classification_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    source_assertion_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("identity.source_assertion.source_assertion_id", name="fk_class_assertion", ondelete="RESTRICT"),
        nullable=False,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    previous_classification_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    previous_version_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    classification: Mapped[str] = mapped_column(String(30), nullable=False)
    restricted_unit: Mapped[str | None] = mapped_column(String(20), nullable=True)
    reason_code: Mapped[str] = mapped_column(String(80), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(50), nullable=False)
    recorded_by: Mapped[str] = mapped_column(String(200), nullable=False)
    evidence_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_key_version: Mapped[str] = mapped_column(String(50), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
