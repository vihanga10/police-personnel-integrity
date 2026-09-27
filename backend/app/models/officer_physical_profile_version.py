from datetime import date, datetime
from decimal import Decimal
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class OfficerPhysicalProfileVersion(Base):
    """Versioned, restricted physical-profile information."""

    __tablename__ = "officer_physical_profile_version"
    __table_args__ = (
        CheckConstraint(
            """
            height_cm IS NOT NULL
            OR chest_cm IS NOT NULL
            """,
            name="officer_physical_profile_has_value",
        ),
        CheckConstraint(
            "height_cm IS NULL OR height_cm > 0",
            name="officer_physical_profile_positive_height",
        ),
        CheckConstraint(
            "chest_cm IS NULL OR chest_cm > 0",
            name="officer_physical_profile_positive_chest",
        ),
        CheckConstraint(
            "version_number > 0",
            name="officer_physical_profile_positive_version",
        ),
        CheckConstraint(
            "valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from",
            name="officer_physical_profile_valid_period",
        ),
        CheckConstraint(
            """
            transaction_end IS NULL
            OR transaction_end > transaction_start
            """,
            name="officer_physical_profile_transaction_period",
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
            name="officer_physical_profile_record_state",
        ),
        UniqueConstraint(
            "officer_uid",
            "version_number",
            name="uq_officer_physical_profile_version_number",
        ),
        Index(
            "ix_officer_physical_profile_valid_time",
            "officer_uid",
            "valid_from",
            "valid_to",
        ),
    )

    physical_profile_version_id: Mapped[UUID] = mapped_column(
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
    supersedes_physical_profile_version_id: Mapped[UUID | None] = (
        mapped_column(
            PGUUID(as_uuid=True),
            ForeignKey(
                "identity.officer_physical_profile_version.physical_profile_version_id",
                ondelete="RESTRICT",
            ),
            nullable=True,
        )
    )

    version_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    height_cm: Mapped[Decimal | None] = mapped_column(
        Numeric(5, 2),
        nullable=True,
    )
    chest_cm: Mapped[Decimal | None] = mapped_column(
        Numeric(5, 2),
        nullable=True,
    )

    measured_at: Mapped[date | None] = mapped_column(
        Date,
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