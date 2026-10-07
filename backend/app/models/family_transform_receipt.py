"""One immutable receipt for an atomic HR family evidence transformation."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, LargeBinary, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column
from app.db.staging_base import StagingBase
from app.models import Officer, OfficerIdentifierVersion, SourceAssertion
from app.staging.models import RawRecord


class FamilyTransformReceipt(StagingBase):
    __tablename__ = "family_transform_receipt"
    __table_args__ = (
        CheckConstraint("raw_record_id ~ '^[0-9a-f]{64}$'", name="family_receipt_raw"),
        CheckConstraint("confirmation_sha256 ~ '^[0-9a-f]{64}$'", name="family_receipt_confirmation"),
        CheckConstraint("code_revision ~ '^[0-9a-f]{40}$'", name="family_receipt_revision"),
        CheckConstraint("policy_version = 'HR_FAMILY_WRITER_V1'", name="family_receipt_policy"),
        CheckConstraint("octet_length(evidence_ciphertext) > 28", name="family_receipt_cipher"),
        CheckConstraint("length(trim(encryption_key_version)) > 0", name="family_receipt_key"),
        UniqueConstraint("source_assertion_id", name="uq_family_receipt_assertion"),
    )
    raw_record_id: Mapped[str] = mapped_column(String(64), ForeignKey(RawRecord.__table__.c.raw_record_id, name="fk_family_receipt_raw", ondelete="RESTRICT"), primary_key=True)
    officer_uid: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey(Officer.__table__.c.officer_uid, name="fk_family_receipt_officer", ondelete="RESTRICT"), nullable=False)
    identifier_version_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey(OfficerIdentifierVersion.__table__.c.identifier_version_id, name="fk_family_receipt_identifier", ondelete="RESTRICT"), nullable=False)
    source_assertion_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey(SourceAssertion.__table__.c.source_assertion_id, name="fk_family_receipt_assertion", ondelete="RESTRICT"), nullable=False)
    confirmation_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    code_revision: Mapped[str] = mapped_column(String(40), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(50), nullable=False)
    evidence_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_key_version: Mapped[str] = mapped_column(String(50), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
