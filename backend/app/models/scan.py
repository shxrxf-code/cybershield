"""Scan persistence: one row per analysis request plus its findings.

What is stored
--------------
* **The report itself** - score, verdict, confidence, recommendation - as columns,
  because those are queried, sorted, filtered and charted.
* **The full signal bundle** as JSON, because it is detector-defined and
  write-only in practice (read as a blob with the report).
* **Metadata about the object**, never the object. Uploaded bytes and full
  message bodies are not persisted here; they live in quarantine storage with a
  retention deadline, or not at all.

Retention
---------
``expires_at`` is set at creation and a maintenance job deletes expired rows.
Keeping every scan forever would grow without bound and would hold URL and
filename metadata that has no ongoing defensive value once past the retention
window.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel, JSONType
from app.schemas.common import ObjectType, Recommendation, ScanStatus, ScanType, Verdict

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.models.user import User

#: Default retention for scan history, in days. Configurable per deployment via
#: ``SCAN_RETENTION_DAYS``.
DEFAULT_RETENTION_DAYS = 90


class Scan(BaseModel):
    """A single analysis of a URL, email, file or text blob."""

    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_user_created", "user_id", "created_at"),
        Index("ix_scans_verdict", "verdict"),
        Index("ix_scans_sha256", "sha256"),
        Index("ix_scans_object_hash_type", "object_hash", "scan_type"),
    )

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    scan_type: Mapped[ScanType] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[ScanStatus] = mapped_column(
        String(16), default=ScanStatus.QUEUED.value, nullable=False, index=True
    )
    #: Human-readable label for history/summary rows ("paypal.com", the sender,
    #: a filename, the first words of a text blob). Never used for any path.
    target_label: Mapped[str | None] = mapped_column(String(512), nullable=True)
    object_type: Mapped[ObjectType] = mapped_column(
        String(16), default=ObjectType.UNKNOWN.value, nullable=False
    )

    # ---- Subject identity ------------------------------------------
    #: URL as submitted, after normalisation. Stored so the user recognises
    #: their own history entry.
    target_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    target_email: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    email_subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    #: Sanitised display name of the analysed file. Never used to build a path.
    original_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Storage-relative identifier for the quarantined copy, never a filesystem path.
    storage_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    #: Hashes enable deduplication and cross-reference lookups.
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sha1: Mapped[str | None] = mapped_column(String(40), nullable=True)
    md5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    #: Subject + scan type, used to recognise a repeat submission.
    object_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # ---- Report -----------------------------------------------------
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    verdict: Mapped[Verdict | None] = mapped_column(String(16), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    recommendation: Mapped[Recommendation | None] = mapped_column(String(32), nullable=True)
    reasons: Mapped[list | None] = mapped_column(JSONType, nullable=True)
    signals: Mapped[list | None] = mapped_column(JSONType, nullable=True)
    #: The ``RiskBreakdown``, serialised, so a report can show its own maths.
    score_breakdown: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    #: Threat-intel results and scanner health, for audit and debugging.
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)

    # ---- Bookkeeping ------------------------------------------------
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    analyzers_run: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_quarantined: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    user: Mapped["User | None"] = relationship(back_populates="scans")

    @staticmethod
    def retention_deadline(days: int = DEFAULT_RETENTION_DAYS) -> datetime:
        """Timestamp at which a scan becomes eligible for deletion."""
        from app.models.base import utcnow

        return utcnow() + timedelta(days=days)

    def is_expired(self, now: datetime | None = None) -> bool:
        """Whether the retention window has elapsed."""
        from app.models.base import utcnow

        if self.expires_at is None:
            return False
        reference = now or utcnow()
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=reference.tzinfo)
        return expires <= reference

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<Scan id={self.id} type={self.scan_type} verdict={self.verdict} "
            f"score={self.score}>"
        )


class ScanFeedback(BaseModel):
    """User feedback on a verdict, used to measure real-world accuracy.

    Feedback is the only ground-truth channel available without a labelled
    corpus, so it is a first-class table rather than a log line. It is also the
    input to any future model retraining, and it is never used to silently flip
    a verdict: a report is immutable once written.
    """

    __tablename__ = "scan_feedback"
    __table_args__ = (
        Index("ix_scan_feedback_scan", "scan_id", unique=True),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    #: ``true_positive`` / ``false_positive`` / ``false_negative`` / ``unsure``
    label: Mapped[str] = mapped_column(String(32), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ScanFeedback scan={self.scan_id} label={self.label!r}>"


__all__ = ["DEFAULT_RETENTION_DAYS", "Scan", "ScanFeedback"]