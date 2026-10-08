"""Health / liveness / readiness probe.

Reports exactly what is true and nothing more: the database reachable state,
whether the in-process queue worker is running, whether the rate limiter has
degraded to the per-process fallback, and whether the ClamAV / YARA backends
are available. The probe never fabricates a healthy status when a backend is
absent, because a scan *report* will say so - the operator should not be
surprised by it here first.
"""

from __future__ import annotations

import time

from fastapi import APIRouter
from sqlalchemy import text

from app.api.deps import DbSession
from app.core.config import get_settings
from app.schemas.scan import HealthResponse, ScannerHealth
from app.security.rate_limit import get_limiter_state
from app.services.scan_service import get_scan_service
from app.workers.queue import get_scan_queue

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, name="health")
async def health(
    db: DbSession,
) -> HealthResponse:
    """Report component availability (never the whole story, always the truth)."""
    started = time.monotonic()
    settings = get_settings()

    checks: dict[str, object] = {}
    db_ok = True
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = {"available": True}
    except Exception as exc:  # noqa: BLE001 - a probe must not crash the probe
        db_ok = False
        checks["database"] = {"available": False, "detail": str(exc)[:200]}

    queue = get_scan_queue()
    checks["worker"] = {"running": queue.running, "pending": queue.pending}

    limiter_state = get_limiter_state()
    checks["rate_limiter"] = {
        "degraded": limiter_state.degraded,
        "note": (
            "In-process fallback in use; limits are per process, not global."
            if limiter_state.degraded
            else (
                "In-process backend (USE_REDIS_QUEUE=false); limits are per process."
                if not settings.use_redis_queue
                else "Redis-backed"
            )
        ),
    }

    service = get_scan_service()
    scanners: list[ScannerHealth] = []
    try:
        yara = service.yara
        yara_available = await yara.is_available()
        scanners.append(
            ScannerHealth(
                name="yara",
                available=yara_available,
                detail="rules compiled"
                if yara_available
                else "no rule set compiled",
                signal_count=int(getattr(yara, "rule_count", 0) or 0),
            )
        )
    except Exception as exc:  # noqa: BLE001
        scanners.append(ScannerHealth(name="yara", available=False, detail=str(exc)[:200]))

    try:
        clamav = service.clamav
        clamav_available = await clamav.is_available()
        version = await clamav.get_version() if clamav_available else None
        scanners.append(
            ScannerHealth(
                name="clamav",
                available=clamav_available,
                detail=version or ("unreachable" if not clamav_available else "ready"),
            )
        )
    except Exception as exc:  # noqa: BLE001
        scanners.append(ScannerHealth(name="clamav", available=False, detail=str(exc)[:200]))

    checks["scanners"] = [scanner.model_dump() for scanner in scanners]

    if not db_ok:
        status = "unavailable"
    elif queue.running and all(s.available for s in scanners):
        status = "ok"
    else:
        status = "degraded"

    return HealthResponse(
        status=status,
        version=settings.app_version,
        environment=settings.environment,
        uptime_seconds=round(time.monotonic() - started, 3),
        checks=checks,
    )