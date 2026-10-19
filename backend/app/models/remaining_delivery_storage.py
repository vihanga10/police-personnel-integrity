"""Immutable preparation and completion facts for cross-database SRB remaining remaining delivery."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, LargeBinary, String, Integer, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column
from app.db.staging_base import StagingBase
from app.models.officer import Officer
from app.models.officer_identifier_version import OfficerIdentifierVersion
from app.models.source_assertion import SourceAssertion
from app.db.base import Base
from app.models.source_system import SourceSystem
from app.staging.models import RawRecord



class RemainingSourceAssertion(Base):
    """Opaque encrypted source claim; multi-person events have no single officer."""
    __tablename__ = "remaining_source_assertion"
    __table_args__ = (
        UniqueConstraint("raw_record_id", "assertion_type", name="uq_remaining_assertion_source_type"),
        CheckConstraint("assertion_type IN ('HR_EDUCATION_EVIDENCE', 'PF_OPERATION_EVIDENCE', 'PF_COURT_EVIDENCE', 'PF_COMPLAINT_EVIDENCE', 'PF_DEMOTION_EVIDENCE')", name="remaining_assertion_type"),
        CheckConstraint("(source_file_name IN ('operations.csv','court_details.csv') AND officer_uid IS NULL) OR (source_file_name IN ('officer_education.csv','public_complaints.csv','_demotions_enacted.csv') AND officer_uid IS NOT NULL)", name="remaining_assertion_subject"),
        CheckConstraint("assertion_state = 'ACTIVE' AND independence_status = 'UNVERIFIED' AND classification = 'UNASSESSED'", name="remaining_assertion_state"),
        CheckConstraint("valid_from IS NULL AND valid_to IS NULL AND transaction_end IS NULL AND source_recorded_at IS NULL AND captured_at IS NULL AND source_record_id IS NULL AND source_document_id IS NULL AND source_page IS NULL", name="remaining_assertion_unknown_semantics"),
        CheckConstraint("octet_length(asserted_value_ciphertext) BETWEEN 29 AND 12582912 AND length(encryption_key_version) BETWEEN 1 AND 128", name="remaining_assertion_cipher"),
        CheckConstraint("source_row_number > 0 AND source_file_sha256 ~ '^[0-9a-f]{64}$'", name="remaining_assertion_source"),
    )
    source_assertion_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    officer_uid: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey(Officer.__table__.c.officer_uid, ondelete="RESTRICT"), nullable=True)
    source_system_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey(SourceSystem.__table__.c.source_system_id, ondelete="RESTRICT"), nullable=False)
    raw_record_id: Mapped[str] = mapped_column(String(64), ForeignKey(RawRecord.__table__.c.raw_record_id, ondelete="RESTRICT"), nullable=False)
    intake_batch_id: Mapped[str] = mapped_column(String(100), nullable=False)
    import_file_id: Mapped[str] = mapped_column(String(100), nullable=False)
    source_file_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_file_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source_row_number: Mapped[int] = mapped_column(Integer, nullable=False)
    assertion_type: Mapped[str] = mapped_column(String(50), nullable=False)
    asserted_value_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_key_version: Mapped[str] = mapped_column(String(128), nullable=False)
    assertion_state: Mapped[str] = mapped_column(String(20), nullable=False, server_default="ACTIVE")
    independence_status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="UNVERIFIED")
    classification: Mapped[str] = mapped_column(String(20), nullable=False, server_default="UNASSESSED")
    # These nullable metadata remain unknown; no inferred effective interval is saved.
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    transaction_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_recorded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    captured_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_record_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source_document_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source_page: Mapped[str | None] = mapped_column(String(100), nullable=True)
    transaction_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.clock_timestamp())


class RemainingDeliveryPreparation(StagingBase):
    """A committed source assertion and exact sealed Mongo envelope awaiting delivery."""
    __tablename__ = "remaining_delivery_preparation"
    __table_args__ = (
        UniqueConstraint("raw_record_id", "writer_policy", name="uq_remaining_preparation_source_policy"),
        UniqueConstraint("source_assertion_id", name="uq_remaining_preparation_assertion"),
        UniqueConstraint("delivery_id", "document_sha256", name="uq_remaining_preparation_digest"),
        CheckConstraint("raw_record_id ~ '^[0-9a-f]{64}$'", name="remaining_preparation_raw"),
        CheckConstraint("confirmation_sha256 ~ '^[0-9a-f]{64}$'", name="remaining_preparation_confirmation"),
        CheckConstraint("code_revision ~ '^[0-9a-f]{40}$'", name="remaining_preparation_revision"),
        # Collection, source filename and writer policy must agree exactly.
        CheckConstraint("(source_file_name = 'officer_education.csv' AND mongo_collection = 'education_records' AND writer_policy = 'HR_EDUCATION_EVIDENCE_V1') OR (source_file_name = 'operations.csv' AND mongo_collection = 'operation_records' AND writer_policy = 'PF_OPERATION_EVIDENCE_V1') OR (source_file_name = 'court_details.csv' AND mongo_collection = 'court_records' AND writer_policy = 'PF_COURT_EVIDENCE_V1') OR (source_file_name = 'public_complaints.csv' AND mongo_collection = 'complaint_records' AND writer_policy = 'PF_COMPLAINT_EVIDENCE_V1') OR (source_file_name = '_demotions_enacted.csv' AND mongo_collection = 'demotion_events' AND writer_policy = 'PF_DEMOTION_EVIDENCE_V1')", name="remaining_preparation_routing"),
        CheckConstraint("(source_file_name = 'officer_education.csv' AND field_review_count BETWEEN 0 AND 19) OR (source_file_name = 'operations.csv' AND field_review_count BETWEEN 0 AND 32) OR (source_file_name = 'court_details.csv' AND field_review_count BETWEEN 0 AND 16) OR (source_file_name = 'public_complaints.csv' AND field_review_count BETWEEN 0 AND 54) OR (source_file_name = '_demotions_enacted.csv' AND field_review_count BETWEEN 0 AND 4)", name="remaining_preparation_review_count"),
        CheckConstraint("row_review_count BETWEEN 0 AND 32", name="remaining_preparation_row_reviews"),
        CheckConstraint("(field_review_count = 0 AND row_review_count = 0 AND review_state = 'NO_STRUCTURAL_REVIEW') OR ((field_review_count > 0 OR row_review_count > 0) AND review_state = 'STRUCTURAL_REVIEW_REQUIRED')", name="remaining_preparation_review_state"),
        CheckConstraint("historical_eligibility = 'UNASSESSED' AND ((source_file_name IN ('operations.csv','court_details.csv') AND officer_uid IS NULL AND identifier_version_id IS NULL AND linkage_method = 'MULTI_PERSON_SOURCE_NO_SINGLE_SUBJECT') OR (source_file_name NOT IN ('operations.csv','court_details.csv') AND officer_uid IS NOT NULL AND identifier_version_id IS NOT NULL AND linkage_method = 'EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH'))", name="remaining_preparation_linkage"),
        CheckConstraint("octet_length(document_bson) BETWEEN 29 AND 12582912", name="remaining_preparation_size"),
        # PostgreSQL 16 provides sha256(bytea); no extension/privilege change is needed.
        CheckConstraint("document_sha256 = encode(sha256(document_bson), 'hex')", name="remaining_preparation_digest"),
    )
    delivery_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    raw_record_id: Mapped[str] = mapped_column(String(64), ForeignKey(RawRecord.__table__.c.raw_record_id, name="fk_remaining_preparation_raw", ondelete="RESTRICT"), nullable=False)
    officer_uid: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey(Officer.__table__.c.officer_uid, name="fk_remaining_preparation_officer", ondelete="RESTRICT"), nullable=True)
    source_assertion_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey(RemainingSourceAssertion.__table__.c.source_assertion_id, name="fk_remaining_preparation_assertion", ondelete="RESTRICT"), nullable=False)
    identifier_version_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey(OfficerIdentifierVersion.__table__.c.identifier_version_id, name="fk_remaining_preparation_identifier", ondelete="RESTRICT"), nullable=True)
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


class RemainingDeliveryCompletion(StagingBase):
    """Append-only receipt, whose digest must refer to exactly one preparation."""
    __tablename__ = "remaining_delivery_completion"
    __table_args__ = (
        ForeignKeyConstraint(["delivery_id", "document_sha256"],
                             ["staging.remaining_delivery_preparation.delivery_id", "staging.remaining_delivery_preparation.document_sha256"],
                             name="fk_remaining_completion_prepared_digest", ondelete="RESTRICT"),
    )
    delivery_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    document_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.clock_timestamp())
