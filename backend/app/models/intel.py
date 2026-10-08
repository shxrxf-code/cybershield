"""Cached threat-intelligence lookups.

Why cache at all
----------------
Public reputation APIs are rate-limited, sometimes slow, and often the single
slowest part of a scan. Caching their answers both speeds up repeat scans and
keeps the service inside provider fair-use limits.

Cache entries are keyed by ``(provider, indicator_type, indicator)`` and store
the provider's own verdict plus the raw response needed to attribute the claim.
Entries expire, and a **negative** result is cached for a shorter window than a
positive one: a file that becomes malicious should start being reported quickly,
whereas a clean file staying clean for a few extra minutes costs nothing.

This table is a cache, not a database of truth. Losing it degrades latency, not
correctness, which is why ``metadata_json`` keeps enough provenance to explain a
stale answer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import BaseModel, JSONType


class ThreatIntelCache(BaseModel):
    """A memoised answer from one intelligence provider."""

    __tablename__ = "threat_intel_cache"
    __table_args__ = (
        Index("ix_threat_intel_lookup", "provider", "indicator_type", "indicator", unique=True),
        Index("ix_threat_intel_expires", "expires_at"),
    )

    provider: Mapped[str] = mapped_column(String(48), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False)
    #: Normalised indicator: hostname lowercased and defanged where relevant, so
    #: lookups of the same target from different entry points share a row.
    indicator: Mapped[str] = mapped_column(String(512), nullable=False)

    #: Provider-reported outcome, mapped onto CyberShield's vocabulary.
    is_malicious: Mapped[bool] = mapped_column(default=False, nullable=False)
    #: 0-1 provider confidence; ``None`` when the provider reports no score.
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    detection_ratio: Mapped[str | None] = mapped_column(String(32), nullable=True)
    categories: Mapped[str | None] = mapped_column(Text, nullable=True)
    threat_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reference: Mapped[str | None] = mapped_column(Text, nullable=True)

    hit_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def is_fresh(self, now: datetime | None = None) -> bool:
        from app.models.base import utcnow

        reference = now or utcnow()
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=reference.tzinfo)
        return expires > reference


__all__ = ["ThreatIntelCache"]