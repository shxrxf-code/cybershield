"""In-process background scan job queue.

Design
------
A single asyncio worker task drains a bounded :class:`asyncio.Queue`. Each
``ScanJob`` carries everything the worker needs to rebuild the original request
schema and, for file/APK scans, where the uploaded blob lives on disk
(``storage_key`` under the settings-controlled upload directory).

Two backends are supported conceptually:

* **In-process** (this module) - used for development and single-container
  deployments. Jobs are lost on restart, which is fine: a structured job should
  be re-submittable.
* **Redis** - a deployment that needs durable, multi-replica queues swaps
  :class:`ScanQueue` for a Redis-backed implementation with the same
  ``enqueue/start/stop`` surface.

Failure handling
----------------
``run_scan_job`` is the worker's last line of defence: any exception raised by
the pipeline marks the ``Scan`` row ``FAILED`` with a sanitised error message and
the job is consumed (never retried here - a defensive scanner must not hammer
providers with an unbounded retry loop). Uploaded temp blobs are always removed
afterwards unless ``KEEP_FILES_AFTER_SCAN`` is set.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.exceptions import ScanFailedError
from app.core.logging import request_id_ctx
from app.security.sanitize import safe_join

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ScanJob:
    """One unit of background work, fully self-describing."""

    scan_id: str
    scan_type: str  # url | email | file | apk | quick
    user_id: str | None = None
    options: dict[str, Any] = field(default_factory=dict)
    #: Temporary blob key under ``settings.upload_dir`` for file/APK payloads.
    storage_key: str | None = None
    #: Extra worker context (e.g. ``filename``, ``declared_mime`` for uploads).
    payload: dict[str, Any] = field(default_factory=dict)


def request_from_options(scan_type: str, options: dict[str, Any]) -> Any:
    """Rebuild the exact request schema the pipeline expects."""
    if scan_type == "url":
        from app.schemas.scan import UrlScanRequest

        return UrlScanRequest.model_validate(options)
    if scan_type == "email":
        from app.schemas.scan import EmailScanRequest

        return EmailScanRequest.model_validate(options)
    if scan_type == "file":
        from app.schemas.scan import FileScanOptions

        return FileScanOptions.model_validate(options)
    if scan_type == "apk":
        from app.schemas.scan import ApkScanOptions

        return ApkScanOptions.model_validate(options)
    from app.schemas.scan import TextScanRequest

    return TextScanRequest.model_validate(options)


def _safe_error_message(exc: BaseException) -> str:
    """Bounded, loggable rendering of a pipeline failure."""
    return str(exc)[:2000]


async def run_scan_job(job: ScanJob) -> None:
    """Run one queued scan to completion, marking the row FAILED on error."""
    from app.db.session import session_scope
    from app.models.scan import Scan
    from app.schemas.common import ScanStatus
    from app.services.scan_service import get_scan_service

    settings = get_settings()
    service = get_scan_service()
    scan_uuid = uuid.UUID(job.scan_id)
    user_id = uuid.UUID(job.user_id) if job.user_id else None

    logger.info(
        "scan_job_start",
        extra={"scan_id": job.scan_id, "scan_type": job.scan_type, "request_id": request_id_ctx.get()},
    )

    blob_path: Path | None = None
    if job.storage_key:
        blob_path = safe_join(settings.upload_dir, job.storage_key)

    async with session_scope() as db:
        try:
            if blob_path is not None and not blob_path.is_file():
                raise ScanFailedError("The uploaded payload could not be found.")
            data = blob_path.read_bytes() if blob_path is not None else b""

            request = request_from_options(job.scan_type, dict(job.options))
            if job.scan_type == "url":
                await service.scan_url(db, request, user_id=user_id, scan_id=job.scan_id)
            elif job.scan_type == "email":
                await service.scan_email(db, request, user_id=user_id, scan_id=job.scan_id)
            elif job.scan_type == "quick":
                await service.scan_text(db, request, user_id=user_id, scan_id=job.scan_id)
            elif job.scan_type == "file":
                await service.scan_file(
                    db,
                    request,
                    data=data,
                    filename=job.payload.get("filename"),
                    declared_mime=job.payload.get("declared_mime"),
                    user_id=user_id,
                    scan_id=job.scan_id,
                )
            elif job.scan_type == "apk":
                await service.scan_apk(
                    db,
                    request,
                    data=data,
                    filename=job.payload.get("filename"),
                    user_id=user_id,
                    scan_id=job.scan_id,
                )
            else:
                raise ScanFailedError(f"Unsupported scan type: {job.scan_type}")
        except Exception as exc:  # noqa: BLE001 - the worker's error boundary
            logger.exception(
                "scan_job_failed",
                extra={"scan_id": job.scan_id, "scan_type": job.scan_type, "request_id": request_id_ctx.get()},
            )
            scan = await db.get(Scan, scan_uuid)
            if scan is not None:
                scan.status = ScanStatus.FAILED.value
                scan.error_message = _safe_error_message(exc)
        finally:
            if blob_path is not None and not settings.keep_files_after_scan:
                blob_path.unlink(missing_ok=True)


class ScanQueue:
    """Process-local asyncio queue; start with :meth:`start` at app boot."""

    def __init__(self, max_size: int = 256) -> None:
        self._queue: asyncio.Queue[ScanJob] = asyncio.Queue(maxsize=max_size)
        self._worker: asyncio.Task[None] | None = None

    @property
    def running(self) -> bool:
        return self._worker is not None and not self._worker.done()

    @property
    def pending(self) -> int:
        return self._queue.qsize()

    async def enqueue(self, job: ScanJob) -> None:
        """Push a job; blocks when the queue is full (back-pressure)."""
        await self._queue.put(job)

    def start(self) -> None:
        if self.running:
            return
        self._worker = asyncio.create_task(self._consume(), name="cybershield-scan-queue")

    async def stop(self) -> None:
        worker, self._worker = self._worker, None
        if worker is None:
            return
        worker.cancel()
        try:
            await worker
        except asyncio.CancelledError:  # pragma: no cover - expected on cancel
            pass

    async def _consume(self) -> None:
        while True:
            job = await self._queue.get()
            try:
                await run_scan_job(job)
            except Exception:  # noqa: BLE001 - run_scan_job has its own boundary
                logger.exception(
                    "scan job crashed outside its error boundary", extra={"scan_id": job.scan_id}
                )
            finally:
                self._queue.task_done()


_queue: ScanQueue | None = None


def get_scan_queue() -> ScanQueue:
    """Return the process-wide queue, started on first use."""
    global _queue
    if _queue is None:
        _queue = ScanQueue()
        _queue.start()
    return _queue


def set_scan_queue(queue: ScanQueue | None) -> None:
    """Replace the queue, for tests."""
    global _queue
    _queue = queue


async def shutdown_scan_queue() -> None:
    """Cancel the shared worker, called at application shutdown."""
    global _queue
    if _queue is not None:
        await _queue.stop()
        _queue = None


__all__ = [
    "ScanJob",
    "ScanQueue",
    "get_scan_queue",
    "request_from_options",
    "run_scan_job",
    "set_scan_queue",
    "shutdown_scan_queue",
]