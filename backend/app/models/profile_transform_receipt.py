"""Immutable receipt for one atomic PF-profile transformation."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, LargeBinary, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column
from app.db.staging_base import StagingBase
from app.models import Officer, SourceAssertion
from app.staging.models import RawRecord


class ProfileTransformReceipt(StagingBase):
    __tablename__ = "profile_transform_receipt"
    __table_args__ = (
        CheckConstraint("raw_record_id ~ '^[0-9a-f]{64}$'", name="profile_receipt_raw_id"),
        CheckConstraint("confirmation_sha256 ~ '^[0-9a-f]{64}$'", name="profile_receipt_confirmation"),
        CheckConstraint("code_revision ~ '^[0-9a-f]{40}$'", name="profile_receipt_revision"),
        CheckConstraint("octet_length(evidence_ciphertext) > 28", name="profile_receipt_evidence"),
        CheckConstraint("length(trim(encryption_key_version)) > 0", name="profile_receipt_key"),
        CheckConstraint("length(trim(policy_version)) > 0", name="profile_receipt_policy"),
        UniqueConstraint("source_assertion_id", name="uq_profile_receipt_assertion"),
    )
    raw_record_id: Mapped[str] = mapped_column(String(64), ForeignKey(RawRecord.__table__.c.raw_record_id, name="fk_profile_receipt_raw", ondelete="RESTRICT"), primary_key=True)
    officer_uid: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey(Officer.__table__.c.officer_uid, name="fk_profile_receipt_officer", ondelete="RESTRICT"), nullable=False)
    identity_decision_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("staging.identity_registration_decision.decision_id", name="fk_profile_receipt_decision", ondelete="RESTRICT"), nullable=False)
    source_assertion_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey(SourceAssertion.__table__.c.source_assertion_id, name="fk_profile_receipt_assertion", ondelete="RESTRICT"), nullable=False)
    confirmation_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(50), nullable=False)
    code_revision: Mapped[str] = mapped_column(String(40), nullable=False)
    evidence_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_key_version: Mapped[str] = mapped_column(String(50), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
