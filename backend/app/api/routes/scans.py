"""Scan entry points and scan-history endpoints.

Five entry points share one pipeline contract (score, verdict, confidence,
reasons, signals, disclaimer) and support both a synchronous default and an
``?async=true`` mode that returns ``202`` with a ``poll_url`` pointing at the
usual detail endpoint. Uploaded bytes used by the async path are parked in
``upload_dir`` under an opaque key and deleted by the worker when the job runs;
the *report* never stores the bytes themselves.

Documented platform limits: file and APK analysis is **static only** - nothing
is executed, mounted, unpacked-to-run, or installed. Scanner availability
(ClamAV, YARA rule set) is reported per report so a verdict can be judged
knowing what actually ran.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.api.deps import (
    DbSession,
    UserPrincipal,
    rate_limit,
    require_scope,
)
from app.core.config import Settings, get_settings
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    PayloadTooLargeError,
    ValidationError,
)
from app.core.logging import request_id_ctx
from app.detection_engine.file.hashing import hash_bytes
from app.detection_engine.text import truncate_for_display
from app.detection_engine.url.parser import parse_url
from app.models.base import utcnow
from app.models.scan import Scan, ScanFeedback
from app.schemas.common import ObjectType, ScanType
from app.schemas.scan import (
    ApkScanOptions,
    ApkScanResponse,
    DashboardStats,
    EmailScanRequest,
    EmailScanResponse,
    FileScanOptions,
    FileScanResponse,
    PaginatedResponse,
    ScanDetail,
    ScanFilterParams,
    ScanSummary,
    SignalSearchHit,
    StatsBucket,
    SubmitFeedbackRequest,
    TextScanRequest,
    TextScanResponse,
    UrlScanRequest,
    UrlScanResponse,
)
from app.security.sanitize import generate_storage_key, safe_join, sanitize_filename
from app.services.audit import log_audit
from app.services.scan_service import get_scan_service

router = APIRouter(tags=["scans"])

WriteScope = Depends(require_scope("scan:write"))
ReadScope = Depends(require_scope("scan:read"))


class ScanAcceptedResponse(BaseModel):
    """Body of a ``202 Accepted`` reply for asynchronous scans."""

    scan_id: str
    status: Literal["QUEUED"] = "QUEUED"
    object_type: str | None = None
    poll_url: str = Field(description="GET this URL to fetch the finished report.")


def _accepted(scan: Scan) -> ScanAcceptedResponse:
    return ScanAcceptedResponse(
        scan_id=str(scan.id),
        object_type=scan.object_type,
        poll_url=f"/api/v1/scans/{scan.id}",
    )


async def _commit_then_enqueue(
    db: DbSession,
    scan: Scan,
    *,
    options: dict[str, Any],
    storage_key: str | None = None,
    payload: dict[str, Any] | None = None,
) -> None:
    """Persist the queued row before handing it to the worker.

    The worker opens its own transaction and immediately fetches the row by id;
    without the explicit commit here it could run before the row is visible and
    fail with ``NotFoundError``.
    """
    await db.commit()
    await get_scan_service().enqueue_scan_record(
        scan, options=options, storage_key=storage_key, payload=payload
    )


async def _read_upload(
    file: UploadFile, settings: Settings, *, max_bytes: int
) -> tuple[bytes, str | None]:
    """Read an upload, enforcing the configured size ceiling."""
    data = await file.read()
    if len(data) > max_bytes:
        raise PayloadTooLargeError(
            f"Upload exceeds the {max_bytes // (1024 * 1024)} MiB limit."
        )
    if not data:
        raise ValidationError("The uploaded file is empty.")
    return data, (file.content_type or None)


# ----------------------------------------------------------------------
# URL
# ----------------------------------------------------------------------


@router.post("/scan/url", response_model=UrlScanResponse | ScanAcceptedResponse, name="scan:url")
async def scan_url(
    body: UrlScanRequest,
    request: Request,
    principal: UserPrincipal,
    db: DbSession,
    async_mode: Annotated[bool, Query(alias="async")] = False,
    _limit: Annotated[None, Depends(rate_limit("scan"))] = None,
    __scope: Annotated[None, WriteScope] = None,
) -> UrlScanResponse | ScanAcceptedResponse:
    """Scan a URL without opening it in a browser (structural + safe fetch)."""
    service = get_scan_service()
    if async_mode:
        parsed = parse_url(body.url)
        scan = await service.create_queued_scan(
            db,
            scan_type=ScanType.URL,
            user_id=principal.user_id,
            object_type=ObjectType.URL,
            target_url=body.url,
            target_host=parsed.hostname,
            target_label=parsed.effective_host or parsed.hostname or truncate_for_display(body.url, 120),
        )
        await _commit_then_enqueue(
            db, scan, options=body.model_dump(mode="json")
        )
        await log_audit(
            db,
            action="scan.submit",
            outcome="success",
            actor_id=principal.user_id,
            actor_label=principal.user_email,
            target_type="scan",
            target_id=str(scan.id),
            source_ip=principal.source_ip,
            user_agent=request.headers.get("user-agent"),
            request_id=request_id_ctx.get(),
            details={"scan_type": "url", "mode": "async"},
        )
        return _accepted(scan)
    result = await service.scan_url(db, body, user_id=principal.user_id)
    await log_audit(
        db,
        action="scan.submit",
        outcome="success",
        actor_id=principal.user_id,
        actor_label=principal.user_email,
        target_type="scan",
        target_id=result.scan_id,
        source_ip=principal.source_ip,
        user_agent=request.headers.get("user-agent"),
        request_id=request_id_ctx.get(),
        details={"scan_type": "url", "mode": "sync"},
    )
    return result


# ----------------------------------------------------------------------
# Email
# ----------------------------------------------------------------------


@router.post(
    "/scan/email", response_model=EmailScanResponse | ScanAcceptedResponse, name="scan:email"
)
async def scan_email(
    body: EmailScanRequest,
    request: Request,
    principal: UserPrincipal,
    db: DbSession,
    async_mode: Annotated[bool, Query(alias="async")] = False,
    _limit: Annotated[None, Depends(rate_limit("scan"))] = None,
    __scope: Annotated[None, WriteScope] = None,
) -> EmailScanResponse | ScanAcceptedResponse:
    """Scan an RFC 5322 message (headers + body heuristics; nothing is sent)."""
    service = get_scan_service()
    if async_mode:
        label = truncate_for_display(
            body.subject or ("headers only" if body.analyse_headers_only else "(raw message)"),
            120,
        )
        scan = await service.create_queued_scan(
            db,
            scan_type=ScanType.EMAIL,
            user_id=principal.user_id,
            object_type=ObjectType.EMAIL,
            target_email=body.sender or None,
            email_subject=body.subject,
            target_label=label,
        )
        await _commit_then_enqueue(
            db, scan, options=body.model_dump(mode="json")
        )
        await log_audit(
            db,
            action="scan.submit",
            outcome="success",
            actor_id=principal.user_id,
            actor_label=principal.user_email,
            target_type="scan",
            target_id=str(scan.id),
            source_ip=principal.source_ip,
            user_agent=request.headers.get("user-agent"),
            request_id=request_id_ctx.get(),
            details={"scan_type": "email", "mode": "async"},
        )
        return _accepted(scan)
    result = await service.scan_email(db, body, user_id=principal.user_id)
    await log_audit(
        db,
        action="scan.submit",
        outcome="success",
        actor_id=principal.user_id,
        actor_label=principal.user_email,
        target_type="scan",
        target_id=result.scan_id,
        source_ip=principal.source_ip,
        user_agent=request.headers.get("user-agent"),
        request_id=request_id_ctx.get(),
        details={"scan_type": "email", "mode": "sync"},
    )
    return result


# ----------------------------------------------------------------------
# Free text
# ----------------------------------------------------------------------


@router.post(
    "/scan/text", response_model=TextScanResponse | ScanAcceptedResponse, name="scan:text"
)
async def scan_text(
    body: TextScanRequest,
    request: Request,
    principal: UserPrincipal,
    db: DbSession,
    async_mode: Annotated[bool, Query(alias="async")] = False,
    _limit: Annotated[None, Depends(rate_limit("scan"))] = None,
    __scope: Annotated[None, WriteScope] = None,
) -> TextScanResponse | ScanAcceptedResponse:
    """Scan pasted text with the phishing heuristics (local, nothing leaves)."""
    service = get_scan_service()
    if async_mode:
        scan = await service.create_queued_scan(
            db,
            scan_type=ScanType.QUICK,
            user_id=principal.user_id,
            object_type=ObjectType.TEXT,
            target_label=truncate_for_display(body.text, 120),
        )
        await _commit_then_enqueue(
            db, scan, options=body.model_dump(mode="json")
        )
        return _accepted(scan)
    result = await service.scan_text(db, body, user_id=principal.user_id)
    await log_audit(
        db,
        action="scan.submit",
        outcome="success",
        actor_id=principal.user_id,
        actor_label=principal.user_email,
        target_type="scan",
        target_id=result.scan_id,
        source_ip=principal.source_ip,
        user_agent=request.headers.get("user-agent"),
        request_id=request_id_ctx.get(),
        details={"scan_type": "text", "mode": "sync"},
    )
    return result


# ----------------------------------------------------------------------
# File (multipart)
# ----------------------------------------------------------------------


@router.post(
    "/scan/file", response_model=FileScanResponse | ScanAcceptedResponse, name="scan:file"
)
async def scan_file(
    request: Request,
    principal: UserPrincipal,
    db: DbSession,
    file: UploadFile,
    options: Annotated[str, Form()] = "{}",
    async_mode: Annotated[bool, Query(alias="async")] = False,
    _limit: Annotated[None, Depends(rate_limit("file_scan"))] = None,
    __scope: Annotated[None, WriteScope] = None,
) -> FileScanResponse | ScanAcceptedResponse:
    """Analyse a file's bytes. Static only - never executed or mounted."""
    settings = get_settings()
    data, declared_mime = await _read_upload(file, settings, max_bytes=settings.max_upload_bytes)
    opts = FileScanOptions.model_validate_json(options)
    safe_name = sanitize_filename(file.filename) or "untitled.unknown"
    service = get_scan_service()

    if async_mode:
        hashes = await asyncio.to_thread(hash_bytes, data)
        scan = await service.create_queued_scan(
            db,
            scan_type=ScanType.FILE,
            user_id=principal.user_id,
            object_type=ObjectType.FILE,
            original_filename=safe_name,
            target_label=safe_name,
            size_bytes=len(data),
            sha256=hashes.sha256,
            sha1=hashes.sha1,
            md5=hashes.md5,
            object_hash=hashes.sha256,
        )
        blob_key = generate_storage_key(suffix=".upload")
        blob_path = safe_join(settings.upload_dir, blob_key)
        await asyncio.to_thread(blob_path.write_bytes, data)
        await _commit_then_enqueue(
            db,
            scan,
            options=opts.model_dump(mode="json"),
            storage_key=blob_key,
            payload={"filename": safe_name, "declared_mime": declared_mime},
        )
        await log_audit(
            db,
            action="scan.submit",
            outcome="success",
            actor_id=principal.user_id,
            actor_label=principal.user_email,
            target_type="scan",
            target_id=str(scan.id),
            source_ip=principal.source_ip,
            user_agent=request.headers.get("user-agent"),
            request_id=request_id_ctx.get(),
            details={"scan_type": "file", "mode": "async", "size_bytes": len(data)},
        )
        return _accepted(scan)

    result = await service.scan_file(
        db,
        opts,
        data=data,
        filename=file.filename,
        declared_mime=declared_mime,
        user_id=principal.user_id,
    )
    await log_audit(
        db,
        action="scan.submit",
        outcome="success",
        actor_id=principal.user_id,
        actor_label=principal.user_email,
        target_type="scan",
        target_id=result.scan_id,
        source_ip=principal.source_ip,
        user_agent=request.headers.get("user-agent"),
        request_id=request_id_ctx.get(),
        details={"scan_type": "file", "mode": "sync", "size_bytes": len(data)},
    )
    return result


# ----------------------------------------------------------------------
# APK (multipart)
# ----------------------------------------------------------------------


@router.post(
    "/scan/apk", response_model=ApkScanResponse | ScanAcceptedResponse, name="scan:apk"
)
async def scan_apk(
    request: Request,
    principal: UserPrincipal,
    db: DbSession,
    file: UploadFile,
    options: Annotated[str, Form()] = "{}",
    async_mode: Annotated[bool, Query(alias="async")] = False,
    _limit: Annotated[None, Depends(rate_limit("file_scan"))] = None,
    __scope: Annotated[None, WriteScope] = None,
) -> ApkScanResponse | ScanAcceptedResponse:
    """Analyse an APK statically. Never installed, run, or instrumented."""
    settings = get_settings()
    data, declared_mime = await _read_upload(file, settings, max_bytes=settings.max_upload_bytes)
    opts = ApkScanOptions.model_validate_json(options)
    safe_name = sanitize_filename(file.filename) or "application.unknown"
    service = get_scan_service()

    if async_mode:
        hashes = await asyncio.to_thread(hash_bytes, data)
        scan = await service.create_queued_scan(
            db,
            scan_type=ScanType.APK,
            user_id=principal.user_id,
            object_type=ObjectType.APK,
            original_filename=safe_name,
            target_label=safe_name,
            size_bytes=len(data),
            sha256=hashes.sha256,
            sha1=hashes.sha1,
            md5=hashes.md5,
            object_hash=hashes.sha256,
        )
        blob_key = generate_storage_key(suffix=".upload")
        blob_path = safe_join(settings.upload_dir, blob_key)
        await asyncio.to_thread(blob_path.write_bytes, data)
        await _commit_then_enqueue(
            db,
            scan,
            options=opts.model_dump(mode="json"),
            storage_key=blob_key,
            payload={"filename": safe_name, "declared_mime": declared_mime},
        )
        await log_audit(
            db,
            action="scan.submit",
            outcome="success",
            actor_id=principal.user_id,
            actor_label=principal.user_email,
            target_type="scan",
            target_id=str(scan.id),
            source_ip=principal.source_ip,
            user_agent=request.headers.get("user-agent"),
            request_id=request_id_ctx.get(),
            details={"scan_type": "apk", "mode": "async", "size_bytes": len(data)},
        )
        return _accepted(scan)

    result = await service.scan_apk(
        db,
        opts,
        data=data,
        filename=file.filename,
        user_id=principal.user_id,
    )
    await log_audit(
        db,
        action="scan.submit",
        outcome="success",
        actor_id=principal.user_id,
        actor_label=principal.user_email,
        target_type="scan",
        target_id=result.scan_id,
        source_ip=principal.source_ip,
        user_agent=request.headers.get("user-agent"),
        request_id=request_id_ctx.get(),
        details={"scan_type": "apk", "mode": "sync", "size_bytes": len(data)},
    )
    return result


# ----------------------------------------------------------------------
# History / detail / feedback
# ----------------------------------------------------------------------


def _visible(scan: Scan, principal: UserPrincipal) -> bool:
    if principal.is_admin:
        return True
    return scan.user_id is not None and scan.user_id == principal.user_id


@router.get("/scans", response_model=PaginatedResponse, name="scans:list")
async def list_scans(
    principal: UserPrincipal,
    db: DbSession,
    filters: ScanFilterParams = Depends(),
    __scope: Annotated[None, ReadScope] = None,
) -> PaginatedResponse:
    """The caller's scan history with optional filters and paging."""
    service = get_scan_service()
    base = select(Scan).where(Scan.user_id == principal.user_id)
    if filters.scan_type is not None:
        base = base.where(Scan.scan_type == filters.scan_type.value)
    if filters.verdict is not None:
        base = base.where(Scan.verdict == filters.verdict.value)
    if filters.min_score is not None:
        base = base.where(Scan.score >= filters.min_score)
    if filters.max_score is not None:
        base = base.where(Scan.score <= filters.max_score)
    if filters.search:
        term = f"%{filters.search}%"
        base = base.where(
            Scan.target_label.ilike(term)
            | Scan.target_url.ilike(term)
            | Scan.target_host.ilike(term)
            | Scan.target_email.ilike(term)
            | Scan.original_filename.ilike(term)
        )
    if filters.since is not None:
        base = base.where(Scan.created_at >= filters.since)
    if filters.until is not None:
        base = base.where(Scan.created_at <= filters.until)

    total = (
        await db.execute(select(func.count()).select_from(base.subquery()))
    ).scalar_one()

    page = filters.page
    page_size = filters.page_size
    rows = (
        (await db.execute(
            base.order_by(Scan.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        ))
        .scalars()
        .all()
    )
    items: list[ScanSummary] = [service.summarise_scan(s) for s in rows]
    return PaginatedResponse.build(items, total, page, page_size)


@router.get("/scans/{scan_id}", response_model=ScanDetail, name="scans:get")
async def get_scan(
    scan_id: uuid.UUID,
    principal: UserPrincipal,
    db: DbSession,
    __scope: Annotated[None, ReadScope] = None,
) -> ScanDetail:
    """Full report for one scan."""
    scan = await db.get(Scan, scan_id)
    if scan is None or not _visible(scan, principal):
        raise NotFoundError("Scan not found.")
    return get_scan_service().scan_to_detail(scan)


@router.post(
    "/scans/{scan_id}/feedback", status_code=204, name="scans:feedback"
)
async def submit_feedback(
    scan_id: uuid.UUID,
    body: SubmitFeedbackRequest,
    request: Request,
    principal: UserPrincipal,
    db: DbSession,
    __scope: Annotated[None, WriteScope] = None,
) -> None:
    """Record one verdict on a finished report (one per scan)."""
    scan = await db.get(Scan, scan_id)
    if scan is None or not _visible(scan, principal):
        raise NotFoundError("Scan not found.")
    existing = (
        await db.execute(
            select(ScanFeedback).where(ScanFeedback.scan_id == scan_id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError("Feedback was already submitted for this scan.")

    db.add(ScanFeedback(scan_id=scan_id, label=body.label, comment=body.comment))
    try:
        await db.flush()
    except IntegrityError as exc:  # unique index raced another write
        raise ConflictError("Feedback was already submitted for this scan.") from exc
    await log_audit(
        db,
        action="scan.feedback",
        outcome="success",
        actor_id=principal.user_id,
        actor_label=principal.user_email,
        target_type="scan",
        target_id=str(scan_id),
        source_ip=principal.source_ip,
        user_agent=request.headers.get("user-agent"),
        details={"label": body.label},
    )
    return None


# ----------------------------------------------------------------------
# Dashboard
# ----------------------------------------------------------------------


@router.get("/dashboard", response_model=DashboardStats, name="scans:dashboard")
async def dashboard(
    principal: UserPrincipal,
    db: DbSession,
    __scope: Annotated[None, ReadScope] = None,
) -> DashboardStats:
    """Aggregate counters and trends for the caller's own scans."""
    total = (
        await db.execute(
            select(func.count()).where(Scan.user_id == principal.user_id)
        )
    ).scalar_one()

    grouped = (
        await db.execute(
            select(Scan.verdict, func.count())
            .where(Scan.user_id == principal.user_id)
            .group_by(Scan.verdict)
        )
    ).all()
    counts: dict[str, int] = {
        "SAFE": 0,
        "LOW_RISK": 0,
        "SUSPICIOUS": 0,
        "HIGH_RISK": 0,
        "MALICIOUS": 0,
        "UNKNOWN": 0,
    }
    for verdict, count in grouped:
        counts[str(verdict)] = int(count)

    stats = (
        await db.execute(
            select(
                func.avg(Scan.score),
                func.avg(Scan.confidence),
                func.count().filter(Scan.is_quarantined),
            ).where(Scan.user_id == principal.user_id)
        )
    ).one_or_none()
    average_score = float(stats[0] or 0.0) if stats else 0.0
    average_confidence = float(stats[1] or 0.0) if stats else 0.0
    quarantined = int(stats[2] or 0) if stats else 0

    timeline = await _build_timeline(db, principal.user_id)
    recent = (
        (await db.execute(
            select(Scan)
            .where(Scan.user_id == principal.user_id)
            .order_by(Scan.created_at.desc())
            .limit(200)
        ))
        .scalars()
        .all()
    )
    top_threat_types: dict[str, int] = {}
    detector_agreement = {"compared": 0, "rule_only": 0}
    for scan in recent:
        if not scan.signals:
            continue
        for signal in scan.signals:
            category = (signal.get("category") or "uncategorised").strip()
            if category not in ("uncategorised", ""):
                top_threat_types[category] = top_threat_types.get(category, 0) + 1
    top = [
        {"category": name, "count": count}
        for name, count in sorted(top_threat_types.items(), key=lambda kv: -kv[1])[:5]
    ]

    return DashboardStats(
        total_scans=total,
        safe_count=counts["SAFE"],
        low_risk_count=counts["LOW_RISK"],
        suspicious_count=counts["SUSPICIOUS"],
        high_risk_count=counts["HIGH_RISK"],
        malicious_count=counts["MALICIOUS"],
        unknown_count=counts["UNKNOWN"],
        average_score=round(average_score, 2),
        average_confidence=round(average_confidence, 3),
        quarantined_files=quarantined,
        timeline=timeline,
        top_threat_types=top,
        detector_agreement=detector_agreement,
        generated_at=utcnow(),
    )


async def _build_timeline(db: DbSession, user_id: uuid.UUID) -> list[StatsBucket]:
    """Per-day counts for the last 30 days (empty days included)."""
    from datetime import datetime as _datetime, timedelta

    cutoff = utcnow() - timedelta(days=29)
    rows = (
        await db.execute(
            select(
                func.date(Scan.created_at).label("day"),
                func.count().label("total"),
                func.count().filter(Scan.verdict.in_(["SAFE", "LOW_RISK"])).label("safe"),
                func.count().filter(
                    Scan.verdict.in_(["SUSPICIOUS", "HIGH_RISK"])
                ).label("suspicious"),
                func.count().filter(
                    Scan.verdict.in_(["MALICIOUS"])
                ).label("malicious"),
            )
            .where(Scan.user_id == user_id, Scan.created_at >= cutoff)
            .group_by(func.date(Scan.created_at))
        )
    ).all()
    by_day = {str(r[0]): r for r in rows}

    buckets: list[StatsBucket] = []
    for offset in range(30):
        day = (cutoff + timedelta(days=offset)).date()
        row = by_day.get(day.isoformat())
        buckets.append(
            StatsBucket(
                date=_datetime.combine(day, _datetime.min.time()),
                total=int(row[1]) if row else 0,
                safe=int(row[2]) if row else 0,
                suspicious=int(row[3]) if row else 0,
                malicious=int(row[4]) if row else 0,
            )
        )
    return buckets


# ----------------------------------------------------------------------
# Signal search (admin/read scope; community view of retained signals)
# ----------------------------------------------------------------------


@router.get("/signals/search", response_model=PaginatedResponse, name="scans:signals-search")
async def search_signals(
    q: Annotated[str, Query(min_length=2, max_length=200)],
    principal: UserPrincipal,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    __scope: Annotated[None, ReadScope] = None,
) -> PaginatedResponse:
    """Search findings across the caller's own scans by signal code/category."""
    term = f"%{q.lower()}%"
    rows = (
        (await db.execute(
            select(Scan)
            .where(Scan.user_id == principal.user_id)
            .order_by(Scan.created_at.desc())
            .limit(500)
        ))
        .scalars()
        .all()
    )
    hits: list[SignalSearchHit] = []
    for scan in rows:
        for signal in scan.signals or []:
            code = str(signal.get("code") or "")
            title = str(signal.get("title") or "")
            category = str(signal.get("category") or "")
            if q.lower() in (code + title + category).lower():
                hits.append(
                    SignalSearchHit(
                        scan_id=str(scan.id),
                        code=code,
                        title=title,
                        description=str(signal.get("description") or ""),
                        severity=signal.get("severity") or "INFO",
                        source=signal.get("source") or "heuristic",
                        category=category,
                        confidence=float(signal.get("confidence") or 0.0),
                        created_at=scan.created_at,
                    )
                )
                if len(hits) >= limit:
                    break
        if len(hits) >= limit:
            break
    return PaginatedResponse.build(hits, len(hits), 1, limit)