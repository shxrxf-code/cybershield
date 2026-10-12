"""Audit-log helper used across the API layer.

An :class:`~app.models.audit.AuditEvent` is written for security-relevant and
irreversible actions. Routine reads are excluded - an audit log that records
every request would be unreadable and would retain scanned-object metadata
beyond the retention policy.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEvent, RateLimitEvent
from app.models.base import utcnow

logger = logging.getLogger(__name__)


async def log_audit(
    db: AsyncSession,
    *,
    action: str,
    outcome: str = "success",
    actor_id: Any | None = None,
    actor_label: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    details: dict[str, Any] | None = None,
    message: str | None = None,
) -> AuditEvent | None:
    """Record one immutable audit event. Best effort: never raises.

    The insert runs inside a SAVEPOINT so a failure rolls back only the audit
    row and leaves the caller's transaction usable. A database-level failure is
    logged and swallowed — auditing must never take down the request it is
    recording.
    """
    try:
        async with db.begin_nested():
            event = AuditEvent(
                action=action,
                outcome=outcome,
                actor_id=actor_id,
                actor_label=actor_label,
                target_type=target_type,
                target_id=target_id,
                source_ip=source_ip,
                user_agent=user_agent,
                request_id=request_id,
                details=details,
                message=message,
            )
            db.add(event)
            await db.flush()
        return event
    except Exception:  # noqa: BLE001 - auditing must never break the request
        logger.exception("audit_log_failed", extra={"action": action})
        return None


async def record_rate_limit_event(
    db: AsyncSession,
    *,
    identifier: str,
    rule: str,
    limit: int,
    window_seconds: float,
    path: str | None = None,
) -> None:
    """Record a rate-limit rejection for abuse analysis. Best effort."""
    try:
        db.add(
            RateLimitEvent(
                identifier=identifier[:128],
                rule=rule,
                limit=limit,
                window_seconds=window_seconds,
                path=path,
                occurred_at=utcnow(),
            )
        )
        await db.flush()
    except Exception:  # noqa: BLE001
        logger.exception("rate_limit_event_log_failed", extra={"identifier": identifier[:64]})


async def purge_rate_limit_events(db: AsyncSession, older_than_days: int = 30) -> int:
    """Delete aggregated rate-limit records past the retention window."""
    from datetime import timedelta

    from app.models.base import utcnow

    cutoff = utcnow() - timedelta(days=older_than_days)
    rows = (await db.execute(select(RateLimitEvent).where(RateLimitEvent.occurred_at < cutoff))).scalars().all()
    for row in rows:
        await db.delete(row)
    return len(rows)


__all__ = ["log_audit", "purge_rate_limit_events", "record_rate_limit_event"]