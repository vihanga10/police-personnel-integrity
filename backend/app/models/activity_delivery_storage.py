"""Immutable preparation and completion facts for cross-database SRB activity activity delivery."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, LargeBinary, String, Integer, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column
from app.db.staging_base import StagingBase
from app.models.officer import Officer
from app.models.officer_identifier_version import OfficerIdentifierVersion
from app.models.source_assertion import SourceAssertion
from app.staging.models import RawRecord


class ActivityDeliveryPreparation(StagingBase):
    """A committed source assertion and exact sealed Mongo envelope awaiting delivery."""
    __tablename__ = "activity_delivery_preparation"
    __table_args__ = (
        UniqueConstraint("raw_record_id", "writer_policy", name="uq_activity_preparation_source_policy"),
        UniqueConstraint("source_assertion_id", name="uq_activity_preparation_assertion"),
        UniqueConstraint("delivery_id", "document_sha256", name="uq_activity_preparation_digest"),
        CheckConstraint("raw_record_id ~ '^[0-9a-f]{64}$'", name="activity_preparation_raw"),
        CheckConstraint("confirmation_sha256 ~ '^[0-9a-f]{64}$'", name="activity_preparation_confirmation"),
        CheckConstraint("code_revision ~ '^[0-9a-f]{40}$'", name="activity_preparation_revision"),
        # Collection, source filename and writer policy must agree exactly.
        CheckConstraint("(source_file_name = 'officer_duty_periods.csv' AND mongo_collection = 'duty_periods' AND writer_policy = 'SRB_DUTY_EVIDENCE_V1') OR (source_file_name = 'officer_firearms_expertise.csv' AND mongo_collection = 'firearms_assessments' AND writer_policy = 'SRB_FIREARMS_EVIDENCE_V1') OR (source_file_name = 'good_conduct_register.csv' AND mongo_collection = 'good_conduct_records' AND writer_policy = 'SRB_GOOD_CONDUCT_EVIDENCE_V1') OR (source_file_name = 'bad_conduct_register.csv' AND mongo_collection = 'bad_conduct_records' AND writer_policy = 'SRB_BAD_CONDUCT_EVIDENCE_V1')", name="activity_preparation_routing"),
        CheckConstraint("(source_file_name = 'officer_duty_periods.csv' AND field_review_count BETWEEN 0 AND 17) OR (source_file_name = 'officer_firearms_expertise.csv' AND field_review_count BETWEEN 0 AND 41) OR (source_file_name = 'good_conduct_register.csv' AND field_review_count BETWEEN 0 AND 33) OR (source_file_name = 'bad_conduct_register.csv' AND field_review_count BETWEEN 0 AND 31)", name="activity_preparation_review_count"),
        CheckConstraint("row_review_count BETWEEN 0 AND 32", name="activity_preparation_row_reviews"),
        CheckConstraint("(field_review_count = 0 AND row_review_count = 0 AND review_state = 'NO_STRUCTURAL_REVIEW') OR ((field_review_count > 0 OR row_review_count > 0) AND review_state = 'STRUCTURAL_REVIEW_REQUIRED')", name="activity_preparation_review_state"),
        CheckConstraint("linkage_method = 'EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH' AND historical_eligibility = 'UNASSESSED'", name="activity_preparation_linkage"),
        CheckConstraint("octet_length(document_bson) BETWEEN 29 AND 12582912", name="activity_preparation_size"),
        # PostgreSQL 16 provides sha256(bytea); no extension/privilege change is needed.
        CheckConstraint("document_sha256 = encode(sha256(document_bson), 'hex')", name="activity_preparation_digest"),
    )
    delivery_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    raw_record_id: Mapped[str] = mapped_column(String(64), ForeignKey(RawRecord.__table__.c.raw_record_id, name="fk_activity_preparation_raw", ondelete="RESTRICT"), nullable=False)
    officer_uid: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey(Officer.__table__.c.officer_uid, name="fk_activity_preparation_officer", ondelete="RESTRICT"), nullable=False)
    source_assertion_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey(SourceAssertion.__table__.c.source_assertion_id, name="fk_activity_preparation_assertion", ondelete="RESTRICT"), nullable=False)
    identifier_version_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey(OfficerIdentifierVersion.__table__.c.identifier_version_id, name="fk_activity_preparation_identifier", ondelete="RESTRICT"), nullable=False)
    confirmation_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    code_revision: Mapped[str] = mapped_column(String(40), nullable=False)
    source_file_name: Mapped[str] = mapped_column(String(100), nullable=False)
    mongo_collection: Mapped[str] = mapped_column(String(50), nullable=False)
    # This describes field-level review only, never authority/source-truth acceptance.
    field_review_count: Mapped[int] = mapped_column(Integer, nullable=False)
    # Row-level consistency issues remain distinct from individual field errors.
    row_review_count: Mapped[int] = mapped_column(Integer, nullable=False)
    review_state: Mapped[str] = mapped_column(String(30), nullable=False)
    writer_policy: Mapped[str] = mapped_column(String(50), nullable=False)
    linkage_method: Mapped[str] = mapped_column(String(50), nullable=False)
    historical_eligibility: Mapped[str] = mapped_column(String(20), nullable=False)
    document_bson: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    document_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ActivityDeliveryCompletion(StagingBase):
    """Append-only receipt, whose digest must refer to exactly one preparation."""
    __tablename__ = "activity_delivery_completion"
    __table_args__ = (
        ForeignKeyConstraint(["delivery_id", "document_sha256"],
                             ["staging.activity_delivery_preparation.delivery_id", "staging.activity_delivery_preparation.document_sha256"],
                             name="fk_activity_completion_prepared_digest", ondelete="RESTRICT"),
    )
    delivery_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    document_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.clock_timestamp())
