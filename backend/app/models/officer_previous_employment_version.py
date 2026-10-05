from datetime import date, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class OfficerPreviousEmploymentVersion(Base):
    """A versioned previous-employment assertion for an officer."""

    __tablename__ = "officer_previous_employment_version"
    __table_args__ = (
        CheckConstraint(
            "length(trim(employer_department_name)) > 0",
            name="officer_previous_employment_has_department",
        ),
        CheckConstraint(
            "version_number > 0",
            name="officer_previous_employment_positive_version",
        ),
        CheckConstraint(
            """
            valid_to IS NULL
            OR valid_from IS NULL
            OR valid_to >= valid_from
            """,
            name="officer_previous_employment_valid_period",
        ),
        CheckConstraint(
            """
            transaction_end IS NULL
            OR transaction_end > transaction_start
            """,
            name="officer_previous_employment_transaction_period",
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
            name="officer_previous_employment_record_state",
        ),
        UniqueConstraint(
            "employment_chain_uid",
            "version_number",
            name="uq_officer_previous_employment_chain_version",
        ),
        Index(
            "ix_officer_previous_employment_officer",
            "officer_uid",
        ),
        Index(
            "ix_officer_previous_employment_valid_time",
            "officer_uid",
            "valid_from",
            "valid_to",
        ),
# Prevent two replacements from superseding the same evidence version.
        Index(
            "uq_officer_previous_employment_version_predecessor",
            "supersedes_employment_version_id",
             unique=True,
             postgresql_where=text(
            "supersedes_employment_version_id IS NOT NULL"
            ),
        ),
    )

    employment_version_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    employment_chain_uid: Mapped[UUID] = mapped_column(
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

    source_assertion_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.source_assertion.source_assertion_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    supersedes_employment_version_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.officer_previous_employment_version.employment_version_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    employer_department_name: Mapped[str] = mapped_column(
        String(300),
        nullable=False,
    )

    version_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    valid_from: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )

    valid_to: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
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