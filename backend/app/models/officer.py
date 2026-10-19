from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, String, func, text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Officer(Base):
    """Permanent master-registry identity for one officer."""

    __tablename__ = "officer"
    __table_args__ = (
        CheckConstraint(
            "registry_state IN ('REGISTERED', 'MERGED', 'ARCHIVED')",
            name="officer_registry_state",
        ),
    )

    officer_uid: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    registry_state: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="REGISTERED",
        server_default=text("'REGISTERED'"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )