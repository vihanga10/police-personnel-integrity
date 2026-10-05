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


class OfficerDemographicVersion(Base):
    """Versioned demographic master data for an officer."""

    __tablename__ = "officer_demographic_version"
    __table_args__ = (
        CheckConstraint(
            """
            date_of_birth IS NOT NULL
            OR place_of_birth IS NOT NULL
            OR nationality_code IS NOT NULL
            OR religion_code IS NOT NULL
            OR gender_code IS NOT NULL
            OR marital_status_code IS NOT NULL
            """,
            name="officer_demographic_has_value",
        ),
        CheckConstraint(
            "version_number > 0",
            name="officer_demographic_positive_version",
        ),
        CheckConstraint(
            "valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from",
            name="officer_demographic_valid_period",
        ),
        CheckConstraint(
            """
            transaction_end IS NULL
            OR transaction_end > transaction_start
            """,
            name="officer_demographic_transaction_period",
        ),
        CheckConstraint(
            """
            record_state IN (
                'ASSERTED',
                'ACCEPTED',
                'SUPERSEDED',
                'DISPUTED'
            )
            """,
            name="officer_demographic_record_state",
        ),
        UniqueConstraint(
            "officer_uid",
            "version_number",
            name="uq_officer_demographic_version_number",
        ),
        Index(
            "ix_officer_demographic_valid_time",
            "officer_uid",
            "valid_from",
            "valid_to",
        ),
        # Prevent two replacements from superseding the same evidence version.
        Index(
            "uq_officer_demographic_version_predecessor",
            "supersedes_demographic_version_id",
            unique=True,
            postgresql_where=text(
            "supersedes_demographic_version_id IS NOT NULL"
            ),
        ),
    )

    demographic_version_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
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

    supersedes_demographic_version_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.officer_demographic_version.demographic_version_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    version_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    date_of_birth: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )
    place_of_birth: Mapped[str | None] = mapped_column(
        String(250),
        nullable=True,
    )
    nationality_code: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    religion_code: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    gender_code: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    marital_status_code: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
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