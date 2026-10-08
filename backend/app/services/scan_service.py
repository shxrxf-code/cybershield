"""Scan orchestration: runs every analysis pipeline and persists the report.

This is the only module that knows how the pieces fit together - the light
detectors (:mod:`app.detection_engine`), the SSRF-protected fetcher, the
threat-intelligence fan-out, the advisory ML opinion, the external scanners and
the quarantine store. Routes and workers both call the same entry points:

* a **synchronous** route calls ``scan_*`` directly; the service creates the
  ``Scan`` row, runs the pipeline and returns the typed report;
* an **asynchronous** route creates the row with
  :meth:`ScanService.create_queued_scan`, enqueues a job, and the worker calls
  the same ``scan_*`` method with ``scan_id=`` so the existing row is fetched and
  completed instead of duplicated.

Coverage and honesty
--------------------
Every pipeline tracks which checks were *expected* and which actually produced
an answer (:class:`_Coverage`). An unavailable scanner or an unparseable blob
reduces coverage; ``coverage < 0.5`` marks the analysis incomplete, which forces
an ``UNKNOWN`` verdict rather than implying an all-clear. A scanner that cannot
answer is **never** recorded as a clean result.

The ML layer is advisory: it only ever adds a low-budget
``ml.risk_underestimate`` signal when it disagrees strongly with a SAFE/LOW
rule-based verdict, and the inverse disagreement is recorded in metadata for
calibration without changing the verdict.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.exceptions import NotFoundError, QuarantineError, ValidationError
from app.detection_engine.apk.analyzer import analyse_apk, summarise_apk
from app.detection_engine.email.analyzer import analyse_email, summarise_parsed
from app.detection_engine.entropy import normalised_entropy
from app.detection_engine.file.analyzer import analyse_file
from app.detection_engine.file.analyzer_types import FileKind
from app.detection_engine.file.hashing import FileHashes, hash_bytes
from app.detection_engine.phishing.heuristics import analyse_text_content
from app.detection_engine.text import (
    extract_email_addresses,
    extract_urls,
    truncate_for_display,
)
from app.detection_engine.url.analyzer import analyse_url_structure
from app.detection_engine.url.parser import ParsedUrl, parse_url
from app.ml.features import extract_features
from app.models.scan import Scan
from app.scanners.base import ScanResult
from app.schemas.common import (
    IndicatorType,
    ObjectType,
    RECOMMENDATION_TEXT,
    Recommendation,
    ScanStatus,
    ScanType,
    Severity,
    SignalSource,
    Verdict,
)
from app.schemas.intel import to_signal
from app.schemas.scan import (
    ApkScanOptions,
    ApkScanResponse,
    EmailScanRequest,
    EmailScanResponse,
    FileScanOptions,
    FileScanResponse,
    ScanDetail,
    ScanSummary,
    TextScanRequest,
    TextScanResponse,
    UrlScanRequest,
    UrlScanResponse,
)
from app.schemas.signal import DetectionSignal, Indicator, SignalBundle
from app.security.sanitize import sanitize_filename
from app.services.quarantine import QuarantineService
from app.services.risk_engine import RiskAssessment, assess_risk
from app.services.url_fetcher import UrlFetcher, UrlFetchResult

logger = logging.getLogger(__name__)

#: ML probability (as a risk model) above which a disagreement with a SAFE/LOW
#: rule-based verdict is surfaced as a low-budget signal.
ML_UNDERESTIMATE_PROBABILITY = 0.7
#: ML probability below which a disagreement with a risky rule-based verdict is
#: recorded in metadata only (for calibration) and never changes the verdict.
ML_OVERESTIMATE_PROBABILITY = 0.3

#: Map a content-derived file kind onto the report's object type.
_OBJECT_TYPE_FOR_KIND: dict[FileKind, ObjectType] = {
    FileKind.PDF: ObjectType.DOCUMENT,
    FileKind.DOCUMENT: ObjectType.DOCUMENT,
    FileKind.OLE2: ObjectType.DOCUMENT,
    FileKind.TEXT: ObjectType.DOCUMENT,
    FileKind.ZIP: ObjectType.ARCHIVE,
    FileKind.ARCHIVE: ObjectType.ARCHIVE,
    FileKind.IMAGE: ObjectType.IMAGE,
    FileKind.APK: ObjectType.APK,
}
_FALLBACK_OBJECT_TYPE = ObjectType.FILE

#: Static-analysis failures emit this so a scan can never mistake "could not
#: analyse" for a clean pass.
_SCAN_INCOMPLETE_SIGNAL = DetectionSignal(
    code="scan.static_analysis_failed",
    title="The object could not be fully analysed",
    description=(
        "The static analysis pass failed on this input, so the findings below are "
        "based on partial evidence. No reliable conclusion is possible; manual "
        "review is recommended."
    ),
    severity=Severity.LOW,
    category="scanner_health",
    source=SignalSource.POLICY,
    confidence=0.9,
    evidence={"reason_type": "static_analysis_failed"},
)


def _cap(value: str | None, limit: int) -> str | None:
    """Truncate a display string to a column limit."""
    if value is None:
        return None
    return value[:limit]


@dataclass
class _Coverage:
    """Tracks which checks were expected and which produced an answer.

    ``availability != cleanliness``: a check that could not run is simply not
    completed, and ``ratio < 0.5`` marks the whole analysis incomplete so the
    risk engine returns ``UNKNOWN`` instead of a false all-clear.
    """

    _expected: int = 0
    _completed: int = 0

    def unit(self, count: int = 1) -> None:
        """Declare one expected check, regardless of whether it will run."""
        self._expected += count

    def done(self, count: int = 1) -> None:
        """Mark completed checks (never more than declared units)."""
        self._completed = min(self._expected, self._completed + count)

    @property
    def ratio(self) -> float:
        return (self._completed / self._expected) if self._expected else 1.0

    @property
    def incomplete(self) -> bool:
        return self.ratio < 0.5


class ScanService:
    """Orchestrates every scan type; one process-wide instance."""

    def __init__(  # noqa: PLR0913 - dependency wiring is this module's job
        self,
        settings: Settings | None = None,
        *,
        fetcher: UrlFetcher | None = None,
        intel: Any | None = None,
        ml: Any | None = None,
        clamav: Any | None = None,
        yara: Any | None = None,
        quarantine: QuarantineService | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self.fetcher = fetcher or UrlFetcher(self._settings)

        # Imported lazily to keep this module's import graph acyclic and cheap.
        from app.threat_intelligence.aggregator import get_threat_intel_service
        from app.ml.model import get_opinion_service
        from app.scanners.clamav import get_clamav_scanner
        from app.scanners.yara_scanner import get_yara_scanner

        self.intel = intel if intel is not None else get_threat_intel_service()
        self.ml = ml if ml is not None else get_opinion_service()
        self.clamav = clamav if clamav is not None else get_clamav_scanner()
        self.yara = yara if yara is not None else get_yara_scanner()

        # Quarantine fails closed when the encryption key is set but the
        # cryptography package is missing; that is a storage-rate problem, never a
        # reason to abort a scan, so it is recorded in metadata instead.
        try:
            self.quarantine = (
                quarantine if quarantine is not None else QuarantineService(self._settings)
            )
        except QuarantineError as exc:  # pragma: no cover - exercised via config
            logger.warning("Quarantine is unavailable: %s", exc)
            self.quarantine = None

    # ------------------------------------------------------------------
    # Pipelines
    # ------------------------------------------------------------------

    async def scan_url(  # noqa: C901 - the pipeline is linear, just documented
        self,
        db: AsyncSession,
        request: UrlScanRequest,
        *,
        user_id: uuid.UUID | None = None,
        scan_id: str | None = None,
    ) -> UrlScanResponse:
        """Run the URL pipeline: parse -> structural -> fetch -> intel -> score."""
        started = _now_ms()
        parsed = parse_url(request.url)
        label = (
            parsed.effective_host
            or parsed.hostname
            or truncate_for_display(request.url, 120)
        )

        scan = await self._get_or_create_scan(
            db,
            scan_id=scan_id,
            scan_type=ScanType.URL,
            user_id=user_id,
            target_url=request.url,
            target_host=_cap(parsed.hostname, 255) or None,
            target_label=label,
        )

        coverage = _Coverage()
        bundle = SignalBundle()
        analyzers: list[str] = []

        # ---- 1. Structural (always) ----------------------------------
        bundle.extend(analyse_url_structure(parsed))
        coverage.unit()
        coverage.done()
        analyzers.append("structural")

        # ---- 2. Protected fetch (unless quick; skipped with no host) ---
        fetch_result: UrlFetchResult | None = None
        if not request.quick and parsed.hostname:
            coverage.unit()
            fetch_result = await self.fetcher.fetch(
                request.url,
                active_fetch=request.consent.active_fetch,
                dns_lookup=request.consent.dns_lookup,
            )
            # A blocked or refused fetch is still a completed check: the scanner
            # answered "no". Only genuine unavailability reduces coverage.
            coverage.done()
            bundle.extend(fetch_result.signals)
            analyzers.append("fetch")

        # ---- 3. Reputation (unless quick or declined) ------------------
        intel_meta: dict[str, Any] | None = None
        if (
            not request.quick
            and request.consent.third_party_lookup
            and (parsed.effective_host or parsed.normalized)
        ):
            coverage.unit()
            indicators: list[tuple[IndicatorType, str]] = []
            if parsed.effective_host:
                indicators.append((IndicatorType.DOMAIN, parsed.effective_host))
            if parsed.normalized:
                indicators.append((IndicatorType.URL, parsed.normalized))
            if fetch_result and fetch_result.resolved_ips:
                indicators.append((IndicatorType.IP_ADDRESS, fetch_result.resolved_ips[0]))
            if indicators:
                intel_signals, intel_meta = await self._intel_signals(
                    indicators, consent=request.consent.third_party_lookup
                )
                bundle.extend(intel_signals)
            coverage.done()
            analyzers.append("intel")

        metadata: dict[str, Any] = {
            "url": {
                "scheme": parsed.scheme,
                "host": parsed.hostname,
                "effective_host": parsed.effective_host,
                "registered_domain": parsed.registered_domain,
                "tld": parsed.tld,
                "port": parsed.port,
                "is_https": parsed.is_https,
                "normalised_url": parsed.normalized,
            },
            "fetch": {
                "status": fetch_result.status if fetch_result else None,
                "page_title": fetch_result.page_title if fetch_result else None,
                "resolved_ips": list(fetch_result.resolved_ips) if fetch_result else [],
                "final_url": fetch_result.final_url if fetch_result else None,
                "fetch_blocked_reason": (
                    fetch_result.fetch_blocked_reason if fetch_result else None
                ),
                "dns_skipped_reason": fetch_result.dns_skipped_reason if fetch_result else None,
                "latency_ms": fetch_result.latency_ms if fetch_result else None,
            },
            "reputation": intel_meta,
            "client_label": request.client_label,
            "quick": request.quick,
            "scanner_coverage": coverage.ratio,
            "analysis_incomplete": coverage.incomplete,
        }

        assessment, final_signals = self._apply_ml(
            bundle,
            object_type=ObjectType.URL,
            coverage=coverage.ratio,
            incomplete=coverage.incomplete,
            metadata=metadata,
        )
        self._finalise_scan(
            scan,
            assessment=assessment,
            signals=final_signals,
            metadata=metadata,
            object_type=ObjectType.URL,
            analyzers_run=",".join(analyzers),
            duration_ms=int((_now_ms() - started)),
            target_label=label,
        )
        return self._build_url_response(scan)

    async def scan_email(  # noqa: C901
        self,
        db: AsyncSession,
        request: EmailScanRequest,
        *,
        user_id: uuid.UUID | None = None,
        scan_id: str | None = None,
    ) -> EmailScanResponse:
        """Parse and statically analyse an RFC 5322 message. No third-party
        submission and no network contact, ever."""
        started = _now_ms()
        scan = await self._get_or_create_scan(
            db, scan_id=scan_id, scan_type=ScanType.EMAIL, user_id=user_id
        )

        headers_only = request.quick or request.analyse_headers_only
        raw = request.raw_message.encode("utf-8", errors="replace")
        if len(raw) > self._settings.max_email_bytes:
            raise ValidationError(
                f"The message exceeds the {self._settings.max_email_bytes} byte limit."
            )

        result = await asyncio.to_thread(
            analyse_email,
            raw,
            subject_override=request.subject,
            sender_override=str(request.sender) if request.sender else None,
            headers_only=headers_only,
            max_bytes=self._settings.max_email_bytes,
        )

        coverage = _Coverage()
        coverage.unit()
        coverage.done()  # parse + headers
        analyzers = ["parse", "headers"]
        if not headers_only:
            coverage.unit()
            coverage.done()  # body + URLs
            analyzers.append("body")
            if result.urls:
                analyzers.append("urls")

        email_md = summarise_parsed(result.parsed)
        metadata: dict[str, Any] = {
            "scanner_coverage": coverage.ratio,
            "analysis_incomplete": False,
            "headers_only": headers_only,
            "email": email_md,
            "phishing_score_hint": result.phishing_score_hint,
            "client_label": request.client_label,
            "quick": request.quick,
        }

        assessment, final_signals = self._apply_ml(
            result.bundle,
            object_type=ObjectType.EMAIL,
            coverage=coverage.ratio,
            incomplete=False,
            metadata=metadata,
        )
        label = email_md.get("sender") or email_md.get("subject") or "email"
        scan.target_email = _cap(email_md.get("sender"), 320)
        scan.email_subject = _cap(email_md.get("subject"), 512)
        self._finalise_scan(
            scan,
            assessment=assessment,
            signals=final_signals,
            metadata=metadata,
            object_type=ObjectType.EMAIL,
            analyzers_run=",".join(analyzers),
            duration_ms=int((_now_ms() - started)),
            target_label=label,
        )
        return self._build_email_response(scan)

    async def scan_text(
        self,
        db: AsyncSession,
        request: TextScanRequest,
        *,
        user_id: uuid.UUID | None = None,
        scan_id: str | None = None,
    ) -> TextScanResponse:
        """Analyse free text with the phishing heuristics.

        Extracted URLs and addresses are reported for visibility but are **not**
        recursively URL-analysed or submitted anywhere.
        """
        started = _now_ms()
        label = truncate_for_display(request.text, 120)
        scan = await self._get_or_create_scan(
            db,
            scan_id=scan_id,
            scan_type=ScanType.QUICK,
            user_id=user_id,
            target_label=label,
        )

        signals = analyse_text_content(request.text)
        metadata: dict[str, Any] = {
            "scanner_coverage": 1.0,
            "analysis_incomplete": False,
            "text": {
                "character_count": len(request.text),
                "extracted_urls": extract_urls(request.text),
                "extracted_emails": extract_email_addresses(request.text),
            },
            "client_label": request.client_label,
            "quick": request.quick,
        }

        assessment, final_signals = self._apply_ml(
            SignalBundle(signals=signals),
            object_type=ObjectType.TEXT,
            coverage=1.0,
            incomplete=False,
            metadata=metadata,
        )
        self._finalise_scan(
            scan,
            assessment=assessment,
            signals=final_signals,
            metadata=metadata,
            object_type=ObjectType.TEXT,
            analyzers_run="heuristics",
            duration_ms=int((_now_ms() - started)),
            target_label=label,
        )
        return self._build_text_response(scan)

    async def scan_file(  # noqa: C901 - the pipeline is linear, just documented
        self,
        db: AsyncSession,
        request: FileScanOptions,
        *,
        data: bytes,
        filename: str | None = None,
        declared_mime: str | None = None,
        user_id: uuid.UUID | None = None,
        scan_id: str | None = None,
    ) -> FileScanResponse:
        """Analyse a file's bytes; never executed, never mounted."""
        started = _now_ms()
        safe_name = sanitize_filename(filename) or "untitled.unknown"
        hashes = await asyncio.to_thread(hash_bytes, data)

        scan = await self._get_or_create_scan(
            db,
            scan_id=scan_id,
            scan_type=ScanType.FILE,
            user_id=user_id,
            original_filename=_cap(safe_name, 255),
            target_label=_cap(safe_name, 512),
            size_bytes=len(data),
            sha256=hashes.sha256,
            sha1=hashes.sha1,
            md5=hashes.md5,
            object_hash=hashes.sha256,
        )

        coverage = _Coverage()
        bundle = SignalBundle()
        analyzers: list[str] = []
        static_failed = False

        # ---- 1. Static structural analysis ----------------------------
        coverage.unit()
        try:
            analysis = await asyncio.to_thread(
                analyse_file,
                data,
                filename=filename,
                declared_mime=declared_mime,
                deep=bool(request.inspect_archives or request.extract_text),
            )
            coverage.done()
            bundle.extend(analysis.signals)
            kind = analysis.content_type.kind
        except Exception as exc:  # noqa: BLE001 - any failure is reported, never fatal
            logger.warning("Static file analysis failed: %s", exc)
            static_failed = True
            bundle.add(_SCAN_INCOMPLETE_SIGNAL)
            analysis = None
            kind = FileKind.UNKNOWN
        analyzers.append("static")
        object_type = _OBJECT_TYPE_FOR_KIND.get(kind, _FALLBACK_OBJECT_TYPE)

        metadata: dict[str, Any] = {
            "content": self._file_content_meta(analysis),
            "entropy": analysis.entropy if analysis else None,
            "entropy_by_region": (
                {k: round(v, 4) for k, v in analysis.entropy_by_region.items()}
                if analysis
                else {}
            ),
            "embedded_urls": (analysis.embedded_urls[:50] if analysis else []),
            "embedded_domains": (analysis.embedded_domains[:50] if analysis else []),
            "strings_of_interest": (analysis.strings_of_interest[:50] if analysis else []),
            "reputation": None,
            "scanners": {},
            "client_label": request.client_label,
            "quick": request.quick,
        }

        # ---- 2. ClamAV (unless quick or explicitly skipped) -------------
        if not request.quick and not request.skip_antivirus:
            coverage.unit()
            clamav = await self._run_external(self.clamav, data)
            if clamav.available:
                coverage.done()
                bundle.extend(clamav.signals)
            metadata["scanners"]["clamav"] = self._scanner_meta(clamav)
            analyzers.append("clamav")

        # ---- 3. YARA (kept even in quick scans: it is local and fast) ----
        if not request.skip_yara:
            coverage.unit()
            yara = await self._run_external(self.yara, data)
            if yara.available:
                coverage.done()
                bundle.extend(yara.signals)
            metadata["scanners"]["yara"] = self._scanner_meta(yara)
            analyzers.append("yara")

        # ---- 4. Reputation by SHA-256 (unless quick or declined) ---------
        intel_meta: dict[str, Any] | None = None
        if not request.quick and request.consent.third_party_lookup:
            coverage.unit()
            intel_signals, intel_meta = await self._intel_signals(
                [(IndicatorType.HASH_SHA256, hashes.sha256)],
                consent=request.consent.third_party_lookup,
            )
            bundle.extend(intel_signals)
            coverage.done()
            analyzers.append("intel")

        incomplete = coverage.incomplete or static_failed
        metadata["scanner_coverage"] = coverage.ratio
        metadata["analysis_incomplete"] = incomplete
        metadata["reputation"] = intel_meta

        assessment, final_signals = self._apply_ml(
            bundle,
            object_type=object_type,
            coverage=coverage.ratio,
            incomplete=incomplete,
            metadata=metadata,
        )

        if not request.quick and request.quarantine:
            await self._maybe_quarantine(
                db,
                data=data,
                scan=scan,
                filename=safe_name,
                hashes=hashes,
                detected_type=analysis.content_type.label if analysis else None,
                assessment=assessment,
                metadata=metadata,
            )

        self._finalise_scan(
            scan,
            assessment=assessment,
            signals=final_signals,
            metadata=metadata,
            object_type=object_type,
            analyzers_run=",".join(analyzers),
            duration_ms=int((_now_ms() - started)),
            target_label=scan.target_label,
        )
        return self._build_file_response(scan)

    async def scan_apk(  # noqa: C901
        self,
        db: AsyncSession,
        request: ApkScanOptions,
        *,
        data: bytes,
        filename: str | None = None,
        user_id: uuid.UUID | None = None,
        scan_id: str | None = None,
    ) -> ApkScanResponse:
        """Statically analyse an APK. Never installed, run, or instrumented."""
        started = _now_ms()
        safe_name = sanitize_filename(filename) or "application.unknown"
        hashes = await asyncio.to_thread(hash_bytes, data)

        scan = await self._get_or_create_scan(
            db,
            scan_id=scan_id,
            scan_type=ScanType.APK,
            user_id=user_id,
            original_filename=_cap(safe_name, 255),
            target_label=_cap(safe_name, 512),
            size_bytes=len(data),
            sha256=hashes.sha256,
            sha1=hashes.sha1,
            md5=hashes.md5,
            object_hash=hashes.sha256,
        )

        coverage = _Coverage()
        bundle = SignalBundle()
        analyzers: list[str] = []
        static_failed = False
        apk_summary: dict[str, Any] | None = None

        # ---- 1. Static package analysis --------------------------------
        coverage.unit()
        try:
            result = await asyncio.to_thread(
                analyse_apk, data, include_dex_strings=request.inspect_dex
            )
            coverage.done()
            bundle.extend(result.bundle.signals)
            apk_summary = summarise_apk(result)
        except Exception as exc:  # noqa: BLE001 - an unparseable APK is a finding
            logger.warning("APK static analysis failed: %s", exc)
            static_failed = True
            bundle.add(_SCAN_INCOMPLETE_SIGNAL)
            result = None
        analyzers.append("static")

        metadata: dict[str, Any] = {
            "content": {"label": "APK (Android application)"}
            if apk_summary is not None
            else {"label": None},
            "entropy": round(normalised_entropy(data), 4),
            "reputation": None,
            "apk": apk_summary,
            "scanners": {},
            "client_label": request.client_label,
            "quick": request.quick,
        }

        # ---- 2. ClamAV / YARA / intel: identical to the file pipeline ----
        if not request.quick and not request.skip_antivirus:
            coverage.unit()
            clamav = await self._run_external(self.clamav, data)
            if clamav.available:
                coverage.done()
                bundle.extend(clamav.signals)
            metadata["scanners"]["clamav"] = self._scanner_meta(clamav)
            analyzers.append("clamav")

        if not request.skip_yara:
            coverage.unit()
            yara = await self._run_external(self.yara, data)
            if yara.available:
                coverage.done()
                bundle.extend(yara.signals)
            metadata["scanners"]["yara"] = self._scanner_meta(yara)
            analyzers.append("yara")

        intel_meta: dict[str, Any] | None = None
        if not request.quick and request.consent.third_party_lookup:
            coverage.unit()
            intel_signals, intel_meta = await self._intel_signals(
                [(IndicatorType.HASH_SHA256, hashes.sha256)],
                consent=request.consent.third_party_lookup,
            )
            bundle.extend(intel_signals)
            coverage.done()
            analyzers.append("intel")

        incomplete = coverage.incomplete or static_failed
        metadata["scanner_coverage"] = coverage.ratio
        metadata["analysis_incomplete"] = incomplete
        metadata["reputation"] = intel_meta

        assessment, final_signals = self._apply_ml(
            bundle,
            object_type=ObjectType.APK,
            coverage=coverage.ratio,
            incomplete=incomplete,
            metadata=metadata,
        )

        if not request.quick and request.quarantine:
            await self._maybe_quarantine(
                db,
                data=data,
                scan=scan,
                filename=safe_name,
                hashes=hashes,
                detected_type="Android application (APK)",
                assessment=assessment,
                metadata=metadata,
            )

        self._finalise_scan(
            scan,
            assessment=assessment,
            signals=final_signals,
            metadata=metadata,
            object_type=ObjectType.APK,
            analyzers_run=",".join(analyzers),
            duration_ms=int((_now_ms() - started)),
            target_label=scan.target_label,
        )
        return self._build_apk_response(scan)

    # ------------------------------------------------------------------
    # Async path helpers
    # ------------------------------------------------------------------

    async def create_queued_scan(
        self,
        db: AsyncSession,
        *,
        scan_type: ScanType,
        user_id: uuid.UUID | None = None,
        object_type: ObjectType = ObjectType.UNKNOWN,
        target_label: str | None = None,
        target_url: str | None = None,
        target_host: str | None = None,
        target_email: str | None = None,
        email_subject: str | None = None,
        original_filename: str | None = None,
        size_bytes: int | None = None,
        sha256: str | None = None,
        sha1: str | None = None,
        md5: str | None = None,
        object_hash: str | None = None,
        retention_days: int | None = None,
    ) -> Scan:
        """Create a ``QUEUED`` row that a worker will complete.

        Used by asynchronous routes: the 202 points at this record, and the
        worker fetches it by ``scan_id`` before running the pipeline.
        """
        scan = Scan(
            user_id=user_id,
            scan_type=scan_type.value,
            status=ScanStatus.QUEUED.value,
            object_type=object_type.value,
            target_label=_cap(target_label, 512),
            target_url=target_url,
            target_host=_cap(target_host, 255),
            target_email=target_email,
            email_subject=_cap(email_subject, 512),
            original_filename=_cap(original_filename, 255),
            size_bytes=size_bytes,
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            object_hash=object_hash,
            expires_at=Scan.retention_deadline(retention_days or self._settings.scan_retention_days),
        )
        db.add(scan)
        await db.flush()
        return scan

    async def enqueue_scan_record(
        self,
        scan: Scan,
        *,
        options: dict[str, Any],
        storage_key: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        """Enqueue the record for the background worker.

        Imported lazily so this module never participates in an import cycle with
        the worker package.
        """
        from app.workers.queue import ScanJob, get_scan_queue

        job = ScanJob(
            scan_id=str(scan.id),
            scan_type=scan.scan_type,
            user_id=str(scan.user_id) if scan.user_id else None,
            options=dict(options),
            storage_key=storage_key,
            payload=dict(payload or {}),
        )
        await get_scan_queue().enqueue(job)

    # ------------------------------------------------------------------
    # Report builders (read back from the persisted row)
    # ------------------------------------------------------------------

    def _build_url_response(self, scan: Scan) -> UrlScanResponse:
        metadata = scan.metadata_json or {}
        url_md = metadata.get("url") or {}
        fetch_md = metadata.get("fetch") or {}
        signals, indicators = self._report_core(scan)

        return UrlScanResponse(
            scan_id=str(scan.id),
            scan_type=ScanType.URL,
            object_type=ObjectType(scan.object_type or ObjectType.URL.value),
            status=ScanStatus(scan.status or ScanStatus.COMPLETED.value),
            url=scan.target_url or "",
            normalised_url=url_md.get("normalised_url"),
            host=scan.target_host,
            resolved_ips=list(fetch_md.get("resolved_ips") or []),
            fetch_blocked_reason=fetch_md.get("fetch_blocked_reason"),
            page_title=fetch_md.get("page_title"),
            http_status=fetch_md.get("status"),
            score=_score(scan),
            verdict=_verdict(scan),
            confidence=_confidence(scan),
            recommendation=_recommendation(scan),
            recommendation_text=self._recommendation_text(scan.recommendation),
            signals=signals,
            reasons=scan.reasons or [],
            indicators=indicators,
            score_breakdown=scan.score_breakdown,
            reputation=metadata.get("reputation"),
            duration_ms=scan.duration_ms,
            created_at=scan.created_at,
        )

    def _build_email_response(self, scan: Scan) -> EmailScanResponse:
        metadata = scan.metadata_json or {}
        email_md = metadata.get("email") or {}
        reply_to = (email_md.get("reply_to") or [None])[0]
        signals, indicators = self._report_core(scan)

        return EmailScanResponse(
            scan_id=str(scan.id),
            scan_type=ScanType.EMAIL,
            object_type=ObjectType.EMAIL,
            status=ScanStatus(scan.status or ScanStatus.COMPLETED.value),
            subject=email_md.get("subject") or scan.email_subject,
            sender=email_md.get("sender") or scan.target_email,
            sender_domain=email_md.get("sender_domain"),
            reply_to=reply_to,
            return_path=email_md.get("return_path"),
            authentication=email_md.get("authentication") or {},
            headers_of_interest={
                "originating_ip": email_md.get("originating_ip"),
                "mail_client": email_md.get("mail_client"),
                "received_hops": email_md.get("received_hops", 0),
                "parse_errors": email_md.get("parse_errors") or [],
                "truncated": bool(email_md.get("truncated")),
            },
            attachment_count=email_md.get("attachment_count", 0),
            score=_score(scan),
            verdict=_verdict(scan),
            confidence=_confidence(scan),
            recommendation=_recommendation(scan),
            recommendation_text=self._recommendation_text(scan.recommendation),
            signals=signals,
            reasons=scan.reasons or [],
            indicators=indicators,
            score_breakdown=scan.score_breakdown,
            duration_ms=scan.duration_ms,
            created_at=scan.created_at,
        )

    def _build_text_response(self, scan: Scan) -> TextScanResponse:
        metadata = scan.metadata_json or {}
        text_md = metadata.get("text") or {}
        signals, indicators = self._report_core(scan)

        return TextScanResponse(
            scan_id=str(scan.id),
            scan_type=ScanType.QUICK,
            object_type=ObjectType.TEXT,
            status=ScanStatus(scan.status or ScanStatus.COMPLETED.value),
            character_count=text_md.get("character_count", 0),
            extracted_urls=list(text_md.get("extracted_urls") or []),
            extracted_emails=list(text_md.get("extracted_emails") or []),
            score=_score(scan),
            verdict=_verdict(scan),
            confidence=_confidence(scan),
            recommendation=_recommendation(scan),
            recommendation_text=self._recommendation_text(scan.recommendation),
            signals=signals,
            reasons=scan.reasons or [],
            indicators=indicators,
            score_breakdown=scan.score_breakdown,
            duration_ms=scan.duration_ms,
            created_at=scan.created_at,
        )

    def _build_file_response(self, scan: Scan) -> FileScanResponse:
        metadata = scan.metadata_json or {}
        content = metadata.get("content") or {}
        signals, indicators = self._report_core(scan)

        return FileScanResponse(
            scan_id=str(scan.id),
            scan_type=ScanType(scan.scan_type or ScanType.FILE.value),
            object_type=ObjectType(scan.object_type or _FALLBACK_OBJECT_TYPE.value),
            status=ScanStatus(scan.status or ScanStatus.COMPLETED.value),
            filename=scan.original_filename,
            size_bytes=scan.size_bytes,
            detected_type=content.get("label"),
            sha256=scan.sha256 or "",
            sha1=scan.sha1,
            md5=scan.md5,
            entropy=metadata.get("entropy"),
            score=_score(scan),
            verdict=_verdict(scan),
            confidence=_confidence(scan),
            recommendation=_recommendation(scan),
            recommendation_text=self._recommendation_text(scan.recommendation),
            signals=signals,
            reasons=scan.reasons or [],
            indicators=indicators,
            score_breakdown=scan.score_breakdown,
            quarantined=bool(scan.is_quarantined),
            duration_ms=scan.duration_ms,
            created_at=scan.created_at,
        )

    def _build_apk_response(self, scan: Scan) -> ApkScanResponse:
        metadata = scan.metadata_json or {}
        apk_md = metadata.get("apk") or {}
        signals, indicators = self._report_core(scan)

        dangerous_permissions: list[str] = []
        exported_components: list[str] = []
        for signal in signals:
            evidence = signal.evidence or {}
            for name in evidence.get("permissions") or []:
                if isinstance(name, str) and name not in dangerous_permissions:
                    dangerous_permissions.append(name)
            if (
                isinstance(evidence.get("permission"), str)
                and evidence["permission"] not in dangerous_permissions
            ):
                dangerous_permissions.append(evidence["permission"])
            if (
                signal.code == "apk.exported_unprotected"
                and (evidence.get("components") or [])
            ):
                exported_components = list(evidence["components"])

        declared_components: dict[str, Any] = {
            "entry_count": apk_md.get("entry_count", 0),
            "native_lib_count": apk_md.get("native_lib_count", 0),
            "exported_unprotected": exported_components,
            "issues": apk_md.get("issues") or [],
        }

        return ApkScanResponse(
            scan_id=str(scan.id),
            scan_type=ScanType.APK,
            object_type=ObjectType.APK,
            status=ScanStatus(scan.status or ScanStatus.COMPLETED.value),
            filename=scan.original_filename,
            size_bytes=scan.size_bytes,
            detected_type="Android application (APK)",
            sha256=scan.sha256 or "",
            sha1=scan.sha1,
            md5=scan.md5,
            entropy=metadata.get("entropy"),
            score=_score(scan),
            verdict=_verdict(scan),
            confidence=_confidence(scan),
            recommendation=_recommendation(scan),
            recommendation_text=self._recommendation_text(scan.recommendation),
            signals=signals,
            reasons=scan.reasons or [],
            indicators=indicators,
            score_breakdown=scan.score_breakdown,
            quarantined=bool(scan.is_quarantined),
            duration_ms=scan.duration_ms,
            created_at=scan.created_at,
            package_name=apk_md.get("package_name"),
            version_name=apk_md.get("version_name"),
            version_code=str(apk_md["version_code"]) if apk_md.get("version_code") is not None else None,
            min_sdk=apk_md.get("min_sdk"),
            target_sdk=apk_md.get("target_sdk"),
            permissions_requested=list(apk_md.get("permissions") or []),
            dangerous_permissions=dangerous_permissions,
            declared_components=declared_components,
            signature={
                "schemes": apk_md.get("signature_schemes") or [],
                "v1_present": bool(apk_md.get("v1_present")),
                "v2_present": bool(apk_md.get("v2_present")),
                "v3_present": bool(apk_md.get("v3_present")),
                "certificates": apk_md.get("certificates") or [],
                "debuggable": bool(apk_md.get("debuggable")),
                "allow_backup": apk_md.get("allow_backup"),
                "cleartext_traffic": bool(apk_md.get("cleartext_traffic")),
            },
            dynamically_analysed=False,
        )

    def summarise_scan(self, scan: Scan) -> ScanSummary:
        """Compact row for history and list views."""
        return ScanSummary(
            scan_id=str(scan.id),
            scan_type=ScanType(scan.scan_type or ScanType.QUICK.value),
            object_type=ObjectType(scan.object_type or ObjectType.UNKNOWN.value),
            status=ScanStatus(scan.status or ScanStatus.QUEUED.value),
            target=scan.target_label or self._describe_target(scan),
            score=scan.score,
            verdict=Verdict(scan.verdict) if scan.verdict else None,
            created_at=scan.created_at,
        )

    def scan_to_detail(self, scan: Scan) -> ScanDetail:
        """Full persisted report for ``GET /scans/{scan_id}``."""
        signals, _ = self._report_core(scan)
        return ScanDetail(
            scan_id=str(scan.id),
            scan_type=ScanType(scan.scan_type or ScanType.QUICK.value),
            object_type=ObjectType(scan.object_type or ObjectType.UNKNOWN.value),
            status=ScanStatus(scan.status or ScanStatus.QUEUED.value),
            target=scan.target_label or self._describe_target(scan),
            score=scan.score,
            verdict=Verdict(scan.verdict) if scan.verdict else None,
            confidence=scan.confidence,
            recommendation=Recommendation(scan.recommendation) if scan.recommendation else None,
            reasons=scan.reasons or [],
            signals=signals,
            score_breakdown=scan.score_breakdown,
            metadata_json=scan.metadata_json,
            target_url=scan.target_url,
            target_host=scan.target_host,
            target_email=scan.target_email,
            email_subject=scan.email_subject,
            original_filename=scan.original_filename,
            storage_key=scan.storage_key,
            sha256=scan.sha256,
            size_bytes=scan.size_bytes,
            is_quarantined=bool(scan.is_quarantined),
            duration_ms=scan.duration_ms,
            analyzers_run=scan.analyzers_run,
            error_message=scan.error_message,
            created_at=scan.created_at,
            expires_at=scan.expires_at,
        )

    # ------------------------------------------------------------------
    # Shared internals
    # ------------------------------------------------------------------

    async def _get_or_create_scan(  # noqa: PLR0913
        self,
        db: AsyncSession,
        *,
        scan_id: str | None,
        scan_type: ScanType,
        user_id: uuid.UUID | None,
        **defaults: Any,
    ) -> Scan:
        """Fetch the existing row on the async path, else create one.

        The row is marked ``SCANNING`` either way so concurrent readers see a
        non-terminal status while the pipeline runs.
        """
        if scan_id is not None:
            scan = await db.get(Scan, uuid.UUID(scan_id))
            if scan is None:
                raise NotFoundError("The scan record to complete was not found.")
            scan.status = ScanStatus.SCANNING.value
            return scan
        scan = Scan(
            status=ScanStatus.SCANNING.value,
            scan_type=scan_type.value,
            user_id=user_id,
            expires_at=Scan.retention_deadline(self._settings.scan_retention_days),
            **defaults,
        )
        db.add(scan)
        await db.flush()
        return scan

    def _finalise_scan(  # noqa: PLR0913
        self,
        scan: Scan,
        *,
        assessment: RiskAssessment,
        signals: list[DetectionSignal],
        metadata: dict[str, Any],
        object_type: ObjectType,
        analyzers_run: str,
        duration_ms: int,
        target_label: str | None = None,
    ) -> None:
        """Write the finished report onto the row."""
        scan.status = ScanStatus.COMPLETED.value
        scan.object_type = object_type.value
        scan.score = round(assessment.score, 2)
        scan.verdict = assessment.verdict.value
        scan.confidence = round(assessment.confidence, 3)
        scan.recommendation = assessment.recommendation.value
        scan.reasons = assessment.reasons
        scan.signals = [signal.model_dump(mode="json") for signal in signals]
        scan.score_breakdown = asdict(assessment.breakdown)
        scan.metadata_json = metadata
        scan.analyzers_run = analyzers_run
        scan.duration_ms = duration_ms
        if target_label:
            scan.target_label = _cap(target_label, 512)
        scan.error_message = None

    def _apply_ml(
        self,
        bundle: SignalBundle,
        *,
        object_type: ObjectType,
        coverage: float,
        incomplete: bool,
        metadata: dict[str, Any],
    ) -> tuple[RiskAssessment, list[DetectionSignal]]:
        """Score the bundle, then let the (advisory) ML layer update it.

        The ML opinion is computed after the rule-based verdict so that the
        disagreement is meaningful. When it disagrees strongly in the *risky*
        direction the extra ``ml.risk_underestimate`` signal is added and the
        bundle is re-scored; the inverse disagreement only lands in metadata.
        """
        pre = assess_risk(
            bundle,
            object_type=object_type,
            scanner_coverage=coverage,
            analysis_incomplete=incomplete,
        )
        try:
            ml_meta, extra = self._ml_opinion(
                bundle.deduplicate(),
                object_type=object_type,
                coverage=coverage,
                pre_ml_verdict=pre.verdict,
            )
        except Exception as exc:  # noqa: BLE001 - an opinion is never mandatory
            logger.warning("ML opinion failed; continuing rule-based: %s", exc)
            ml_meta, extra = {"ml_opinion": {"error": "model_unavailable"}}, []
        metadata["ml"] = ml_meta

        if extra:
            bundle.extend(extra)
            assessment = assess_risk(
                bundle,
                object_type=object_type,
                scanner_coverage=coverage,
                analysis_incomplete=incomplete,
            )
        else:
            assessment = pre
        return assessment, bundle.deduplicate()

    def _ml_opinion(
        self,
        signals: list[DetectionSignal],
        *,
        object_type: ObjectType,
        coverage: float,
        pre_ml_verdict: Verdict,
    ) -> tuple[dict[str, Any], list[DetectionSignal]]:
        """Compute the advisory model opinion and any underestimate signal."""
        vector = extract_features(signals, object_type=object_type, coverage=coverage)
        opinion = self.ml.predict_risk(vector)

        metadata: dict[str, Any] = {
            "ml_opinion": opinion.as_metadata(),
            "feature_vector": vector.as_dict(),
        }
        extra: list[DetectionSignal] = []
        disagreement = "agreement"

        if opinion.probability >= ML_UNDERESTIMATE_PROBABILITY and pre_ml_verdict.is_safe_enough:
            disagreement = "model_more_risky"
            extra.append(
                DetectionSignal(
                    code="ml.risk_underestimate",
                    title="Statistical model disagrees with the rule-based verdict",
                    description=(
                        f"The {opinion.model} model estimated risk at "
                        f"{opinion.probability:.0%}, above the rule-based assessment. "
                        "This raises suspicion but is not a detection on its own."
                    ),
                    severity=Severity.MEDIUM,
                    category="machine_learning",
                    source=SignalSource.MACHINE_LEARNING,
                    confidence=round(min(0.8, opinion.probability), 3),
                    evidence={
                        "probability": round(opinion.probability, 4),
                        "model": opinion.model,
                    },
                )
            )
        elif (
            opinion.probability < ML_OVERESTIMATE_PROBABILITY
            and not pre_ml_verdict.is_safe_enough
        ):
            # Recorded for calibration only: the model is more optimistic than
            # the rules and must never dilute an evidence-backed verdict.
            disagreement = "model_more_optimistic"

        metadata["disagreement"] = disagreement
        return metadata, extra

    async def _intel_signals(
        self,
        indicators: Sequence[tuple[IndicatorType, str]],
        *,
        consent: bool,
    ) -> tuple[list[DetectionSignal], dict[str, Any]]:
        """Query every applicable provider for each indicator.

        Only *positive* results become signals; ERROR/UNKNOWN answers never
        count toward a clean bill of health, which the per-indicator summary
        encodes in ``all_clean``.
        """
        signals: list[DetectionSignal] = []
        entries: list[dict[str, Any]] = []
        for indicator_type, value in indicators:
            summary = await self.intel.lookup_all(value, indicator_type, consent=consent)
            entries.append(
                {
                    "type": indicator_type.value,
                    "value": value,
                    "consensus": summary.consensus,
                    "providers_queried": summary.providers_queried,
                    "providers_failed": summary.providers_failed,
                    "any_positive": summary.any_positive,
                    "all_clean": summary.all_clean,
                }
            )
            for result in summary.results:
                if not result.is_positive:
                    continue
                kwargs = to_signal(result)
                indicator = Indicator(
                    type=indicator_type,
                    value=value,
                    context="queried against third-party reputation services",
                )
                kwargs["indicators"] = (indicator,)
                signals.append(DetectionSignal(**kwargs))

        metadata: dict[str, Any] = {
            "indicators": entries,
            "any_positive": any(entry["any_positive"] for entry in entries),
            "all_clean": bool(entries) and all(entry["all_clean"] for entry in entries),
            "providers_queried": sum(entry["providers_queried"] for entry in entries),
            "providers_failed": sum(entry["providers_failed"] for entry in entries),
        }
        return signals, metadata

    async def _run_external(self, scanner: Any, data: bytes) -> ScanResult:
        """Invoke an external scanner without letting it fail the scan."""
        started = _now_ms()
        try:
            result = await scanner.scan_bytes(data)
            result.latency_ms = int((_now_ms() - started))
            return result
        except Exception as exc:  # noqa: BLE001 - availability must not crash a scan
            logger.warning("Scanner %s unavailable: %s", scanner.name, exc)
            return ScanResult(
                scanner=scanner.name,
                available=False,
                error=f"{type(exc).__name__}: {exc}",
                latency_ms=int((_now_ms() - started)),
            )

    @staticmethod
    def _scanner_meta(result: ScanResult) -> dict[str, Any]:
        """Serialise scanner health for the report's metadata."""
        return {
            "available": result.available,
            "detections": list(result.detections),
            "engine_verdict": result.engine_verdict,
            "engine_version": result.engine_version,
            "scanned_bytes": result.scanned_bytes,
            "latency_ms": result.latency_ms,
            "signal_count": len(result.signals),
            "error": result.error,
        }

    @staticmethod
    def _file_content_meta(analysis: Any) -> dict[str, Any]:
        if analysis is None:
            return {"label": None, "kind": "unknown"}
        content = analysis.content_type
        return {
            "label": content.label,
            "description": content.description,
            "kind": content.kind.value,
            "mimetype": content.mimetype,
            "confidence": round(content.confidence, 4),
            "is_text": content.is_text,
        }

    async def _maybe_quarantine(  # noqa: PLR0913
        self,
        db: AsyncSession,
        *,
        data: bytes,
        scan: Scan,
        filename: str,
        hashes: FileHashes,
        detected_type: str | None,
        assessment: RiskAssessment,
        metadata: dict[str, Any],
    ) -> None:
        """Store a defensible copy of the sample after assessment.

        Failures are recorded in metadata, never fatal: quarantine is an
        evidence locker, and losing it must not hide the scan result.
        """
        if self.quarantine is None:
            metadata["quarantine"] = {
                "stored": False,
                "error": "Quarantine is unavailable (encryption key missing or not installed).",
            }
            return
        try:
            item = await self.quarantine.store_blob(
                db,
                data=data,
                scan_id=scan.id,
                user_id=scan.user_id,
                original_filename=filename,
                size_bytes=hashes.size_bytes,
                sha256=hashes.sha256,
                sha1=hashes.sha1,
                md5=hashes.md5,
                detected_type=detected_type,
                verdict=assessment.verdict.value,
                score=round(assessment.score, 2),
                reason=assessment.reasons[0] if assessment.reasons else None,
                metadata={
                    "scan_verdict": assessment.verdict.value,
                    "scan_score": round(assessment.score, 2),
                    "analyzers": scan.analyzers_run,
                },
            )
            scan.is_quarantined = True
            scan.storage_key = item.storage_key
            metadata["quarantine"] = {"stored": True, "item_id": str(item.id)}
        except QuarantineError as exc:
            metadata["quarantine"] = {"stored": False, "error": exc.message}

    # ------------------------------------------------------------------
    # Small report helpers
    # ------------------------------------------------------------------

    def _report_core(self, scan: Scan) -> tuple[list[DetectionSignal], list[dict[str, Any]]]:
        """Decode stored signals once and derive the deduplicated indicators."""
        signals = self._signals_from_json(scan.signals)
        return signals, self._extract_indicators(signals)

    @classmethod
    def _signals_from_json(cls, rows: list[dict[str, Any]] | None) -> list[DetectionSignal]:
        """Reconstruct stored signals, skipping any that no longer validate."""
        signals: list[DetectionSignal] = []
        for row in rows or []:
            try:
                signals.append(DetectionSignal.model_validate(row))
            except Exception:  # noqa: BLE001 - a stale row must not break history
                logger.debug("Skipping a stored signal that failed validation.")
                continue
        return signals

    @staticmethod
    def _extract_indicators(signals: list[DetectionSignal]) -> list[dict[str, Any]]:
        """Flatten and deduplicate every signal's indicators by fingerprint."""
        seen: set[str] = set()
        indicators: list[dict[str, Any]] = []
        for signal in signals:
            for indicator in signal.indicators:
                fp = indicator.fingerprint
                if fp in seen:
                    continue
                seen.add(fp)
                indicators.append(
                    {
                        "type": indicator.type.value,
                        "value": indicator.value,
                        "context": indicator.context,
                        "fingerprint": fp,
                    }
                )
        return indicators

    @staticmethod
    def _recommendation_text(recommendation: str | None) -> str:
        try:
            key = Recommendation(recommendation or Recommendation.MANUAL_REVIEW.value)
            return RECOMMENDATION_TEXT[key]
        except (ValueError, KeyError):  # pragma: no cover - defensive
            return RECOMMENDATION_TEXT[Recommendation.MANUAL_REVIEW]

    @staticmethod
    def _describe_target(scan: Scan) -> str:
        for value in (scan.target_url, scan.target_email, scan.original_filename):
            if value:
                return value
        return "unknown"


def _score(scan: Scan) -> float:
    return round(float(scan.score or 0.0), 2)


def _confidence(scan: Scan) -> float:
    return round(float(scan.confidence or 0.0), 3)


def _verdict(scan: Scan) -> Verdict:
    try:
        return Verdict(scan.verdict or Verdict.UNKNOWN.value)
    except ValueError:  # pragma: no cover - defensive against legacy data
        return Verdict.UNKNOWN


def _recommendation(scan: Scan) -> Recommendation:
    try:
        return Recommendation(scan.recommendation or Recommendation.MANUAL_REVIEW.value)
    except ValueError:  # pragma: no cover - defensive against legacy data
        return Recommendation.MANUAL_REVIEW


def _now_ms() -> int:
    import time

    return int(time.perf_counter() * 1000)


_service: ScanService | None = None


def get_scan_service() -> ScanService:
    """Return the process-wide scan service."""
    global _service
    if _service is None:
        _service = ScanService()
    return _service


def set_scan_service(service: ScanService | None) -> None:
    """Replace the service, for tests."""
    global _service
    _service = service


__all__ = [
    "ML_OVERESTIMATE_PROBABILITY",
    "ML_UNDERESTIMATE_PROBABILITY",
    "ScanService",
    "get_scan_service",
    "set_scan_service",
]