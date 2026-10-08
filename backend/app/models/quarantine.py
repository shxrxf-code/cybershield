"""Quarantine storage records.

Quarantine is the reason CyberShield may keep a copy of a dangerous file at all,
so the record is deliberately conservative:

* the file is stored under a random name inside a directory the process cannot
  be tricked into escaping (``storage_key`` is an opaque id, never user input);
* the original name is kept only as sanitised display metadata;
* an expiry is mandatory, and a reaper deletes the blob and the row;
* access is audited.

The bytes are **never executed, mounted, or extracted** by this service.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import BaseModel, JSONType
from app.schemas.common import Verdict

#: Quarantine is a temporary evidence locker, not an archive.
DEFAULT_QUARANTINE_RETENTION_DAYS = 14


class QuarantineItem(BaseModel):
    """A stored copy of a file the scanner was asked to inspect."""

    __tablename__ = "quarantine_items"
    __table_args__ = (
        Index("ix_quarantine_sha256", "sha256"),
        Index("ix_quarantine_expires", "expires_at"),
    )

    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    #: Opaque, server-generated identifier. Resolved against the quarantine
    #: directory with a containment check; it is never joined to a client string
    #: to form a path.
    storage_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)

    #: Sanitised for display only.
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sha1: Mapped[str | None] = mapped_column(String(40), nullable=True)
    md5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    detected_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    verdict: Mapped[Verdict | None] = mapped_column(String(16), nullable=True)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: SHA-256 of the stored blob, re-checked on read. If it no longer matches,
    #: the copy has been altered outside the service and must not be released.
    stored_integrity_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Set when the blob was stored encrypted at rest (production deployments).
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    encryption_algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)

    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    is_released: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @staticmethod
    def expiry(days: int = DEFAULT_QUARANTINE_RETENTION_DAYS) -> datetime:
        from app.models.base import utcnow

        return utcnow() + timedelta(days=days)

    def is_expired(self, now: datetime | None = None) -> bool:
        from app.models.base import utcnow

        if self.expires_at is None:
            return False
        reference = now or utcnow()
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=reference.tzinfo)
        return expires <= reference


class QuarantineAccessLog(BaseModel):
    """Immutable audit trail of every quarantine read, release or deletion."""

    __tablename__ = "quarantine_access_log"

    quarantine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("quarantine_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    #: ``read`` | ``release`` | ``delete`` | ``reap``
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    #: Client address and user agent as observed by the proxy, for attribution.
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)


__all__ = [
    "DEFAULT_QUARANTINE_RETENTION_DAYS",
    "QuarantineAccessLog",
    "QuarantineItem",
]