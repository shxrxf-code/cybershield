"""Security audit log for privileged and irreversible actions.

What belongs here
-----------------
Authentication events, API-key lifecycle, quarantine release/deletion, user
administration and configuration changes - the actions that, if performed by an
attacker, would not be visible in ordinary scan history.

What does not
-------------
Routine reads. An audit log that records every request would be so noisy that it
would not be read, and it would retain the analysed objects' metadata far longer
than the retention policy allows.

Request and response bodies are never stored here: they contain the very content
(scanned URLs, message text, filenames) whose retention is bounded elsewhere.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import BaseModel, JSONType


class AuditEvent(BaseModel):
    """One immutable audit record.

    The table has no ``updated_at`` on purpose: an audit row that can be edited is
    not an audit trail. Corrections are made by appending a new event.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_action_created", "action", "created_at"),
        Index("ix_audit_events_actor", "actor_id", "created_at"),
    )

    #: ``auth.login_success`` | ``auth.login_failure`` | ``apikey.create`` | ...
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), default="success", nullable=False)

    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_label: Mapped[str | None] = mapped_column(String(255), nullable=True)

    target_type: Mapped[str | None] = mapped_column(String(48), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    #: Structured detail. Must not contain secrets or raw scanned content.
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)

    @property
    def occurred_at(self) -> datetime:
        return self.created_at


class RateLimitEvent(BaseModel):
    """Aggregated rate-limit rejections, kept separately for abuse analysis.

    Separating these from :class:`AuditEvent` avoids burying credential-stuffing
    patterns in routine admin activity, which is exactly the signal an operator
    needs to see when reviewing a log.
    """

    __tablename__ = "rate_limit_events"

    identifier: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    rule: Mapped[str] = mapped_column(String(64), nullable=False)
    limit: Mapped[int] = mapped_column(Integer, nullable=False)
    window_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


__all__ = ["AuditEvent", "RateLimitEvent"]