"""Audit-log helper contract: best effort, and never raises.

An audit write must not be able to take down the request it records. The
helper wraps its insert in a SAVEPOINT and swallows failures; these tests pin
that contract in both directions (it writes normally, and a broken insert is
absorbed).
"""

from __future__ import annotations

from sqlalchemy import select


async def test_log_audit_writes_event(db) -> None:
    from app.models.audit import AuditEvent
    from app.services.audit import log_audit

    event = await log_audit(
        db,
        action="test.audit.write",
        outcome="success",
        actor_label="tester",
    )
    assert event is not None

    row = (
        await db.execute(
            select(AuditEvent).where(AuditEvent.action == "test.audit.write")
        )
    ).scalar_one_or_none()
    assert row is not None
    assert row.actor_label == "tester"


async def test_log_audit_never_raises_on_failure(monkeypatch, db) -> None:
    import app.services.audit as audit

    def _explode(*_args, **_kwargs):
        raise RuntimeError("simulated audit backend failure")

    # Force event construction to fail; the helper must absorb it.
    monkeypatch.setattr(audit, "AuditEvent", _explode)

    result = await audit.log_audit(db, action="test.audit.failure")
    assert result is None

    # The caller's session must still be usable after the swallowed failure.
    from app.services.audit import log_audit

    monkeypatch.undo()
    ok = await log_audit(db, action="test.audit.after_failure")
    assert ok is not None
