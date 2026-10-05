"""SQLAlchemy metadata for protected incoming evidence."""

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

from app.db.base import NAMING_CONVENTION


class StagingBase(DeclarativeBase):
    """Base for encrypted intake tables in the staging schema."""

    # Reuse naming rules while keeping staging metadata separate.
    metadata = MetaData(
        schema="staging",
        naming_convention=NAMING_CONVENTION,
    )