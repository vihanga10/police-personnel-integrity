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
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class OfficerAddressVersion(Base):
    """Versioned residential address information for an officer."""

    __tablename__ = "officer_address_version"
    __table_args__ = (
        CheckConstraint(
            """
            address_text IS NOT NULL
            OR local_station_reference IS NOT NULL
            """,
            name="officer_address_has_value",
        ),
        CheckConstraint(
            """
            address_type IN (
                'PRESENT',
                'PERMANENT',
                'OTHER'
            )
            """,
            name="officer_address_type",
        ),
        CheckConstraint(
            "version_number > 0",
            name="officer_address_positive_version",
        ),
        CheckConstraint(
            "valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from",
            name="officer_address_valid_period",
        ),
        CheckConstraint(
            """
            transaction_end IS NULL
            OR transaction_end > transaction_start
            """,
            name="officer_address_transaction_period",
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
            name="officer_address_record_state",
        ),
        UniqueConstraint(
            "officer_uid",
            "address_type",
            "version_number",
            name="uq_officer_address_type_version",
        ),
        Index(
            "ix_officer_address_valid_time",
            "officer_uid",
            "address_type",
            "valid_from",
            "valid_to",
        ),
    )

    address_version_id: Mapped[UUID] = mapped_column(
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
    supersedes_address_version_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "identity.officer_address_version.address_version_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    version_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    address_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )
    address_text: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    local_station_reference: Mapped[str | None] = mapped_column(
        String(100),
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