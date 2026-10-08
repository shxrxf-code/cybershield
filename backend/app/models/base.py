"""SQLAlchemy declarative base, shared column types and mixins.

Design notes
------------
* **UUID primary keys** are generated in Python (``uuid4``) rather than by the
  database so that an object is addressable before it is flushed. They also mean
  an id in an API response never reveals how many objects exist, unlike a
  sequential integer.
* **``created_at``/``updated_at``** are server-defaulted *and* set by the ORM, so
  rows created by raw SQL migrations still carry sane timestamps.
* JSON columns are used for signal bundles because the shape of a finding is
  detector-defined; normalising every detector into its own table would couple
  the schema to the detection engine. Anything queried or sorted on is a real
  column, not JSON.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, MetaData, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON, TypeDecorator

#: Explicit constraint names so Alembic can autogenerate a stable, reviewable
#: migration history instead of database-chosen names.
NAMING_CONVENTION: dict[str, Any] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class JSONType(TypeDecorator):
    """JSON column that is ``JSONB`` on PostgreSQL and ``JSON`` elsewhere.

    SQLite has no JSONB. Rather than maintaining two migration branches, the
    logical type is ``JSONType`` and the dialect-specific storage is chosen at
    bind time, so the same models run on SQLite (tests, dev) and PostgreSQL
    (deployment) unchanged.
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


def utcnow() -> datetime:
    """Timezone-aware current time.

    Used instead of ``datetime.utcnow`` (naive, deprecated) so stored timestamps
    are unambiguous.
    """
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base for all CyberShield models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UUIDPrimaryKeyMixin:
    """Adds a random UUID primary key named ``id``."""

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )


class TimestampMixin:
    """Adds server-timestamped ``created_at``/``updated_at`` columns."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=utcnow,
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=utcnow,
        default=utcnow,
        nullable=False,
    )


class BaseModel(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Abstract base for tables that need both mixins."""

    __abstract__ = True


__all__ = [
    "Base",
    "BaseModel",
    "JSONType",
    "NAMING_CONVENTION",
    "String",
    "TimestampMixin",
    "UUIDPrimaryKeyMixin",
    "utcnow",
]