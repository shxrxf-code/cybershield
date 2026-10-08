"""Scan request and report schemas for every scan entry point.

A report always carries the same shape, whatever was analysed: score, verdict,
confidence, the individual signals, the reasoning, and an explicit disclaimer.
Clients can therefore render one widget for all five scan types.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.schemas.common import (
    DISCLAIMER,
    ObjectType,
    Recommendation,
    ScanStatus,
    ScanType,
    Severity,
    SignalSource,
    Verdict,
)
from app.schemas.signal import DetectionSignal

MAX_URL_LENGTH = 2048
MAX_TEXT_LENGTH = 100_000
MAX_SUBJECT_LENGTH = 998  # RFC 5322 header line limit


class ConsentOptions(BaseModel):
    """Explicit consent for outbound actions.

    Each flag defaults to ``True`` for an authenticated user who has already
    accepted the terms, but the client must be able to turn any of them off -
    particularly active fetching, which contacts a host the user named.
    """

    model_config = ConfigDict(extra="forbid")

    #: Submit hashes/URLs to third-party reputation services.
    third_party_lookup: bool = True
    #: Resolve the hostname (a DNS query is observable by the resolver).
    dns_lookup: bool = True
    #: Fetch the URL's content over the network.
    active_fetch: bool = True


class BaseScanRequest(BaseModel):
    """Fields shared by all scan requests."""

    model_config = ConfigDict(extra="forbid")

    consent: ConsentOptions = Field(default_factory=ConsentOptions)
    #: Ask for a fast pass that skips the slowest checks.
    quick: bool = False
    #: Free-form client label recorded in metadata (device name, screen, ...).
    client_label: str | None = Field(default=None, max_length=64)


class UrlScanRequest(BaseScanRequest):
    """Scan a link without opening it in a browser."""

    url: Annotated[str, Field(min_length=1, max_length=MAX_URL_LENGTH)]
    #: Resolve DNS and report what the host resolves to.
    resolve_dns: bool = True

    @field_validator("url")
    @classmethod
    def _trim(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def _require_scheme_or_host(self) -> "UrlScanRequest":
        """Require at least a scheme or a dotted host.

        Validation is intentionally permissive about *what* the URL is - that is
        the detector's job, and a scan must be able to report that a suspicious
        scheme is suspicious. This only rejects input with no scannable target.
        """
        candidate = self.url
        if "://" not in candidate:
            if "." not in candidate and candidate.lower() != "localhost":
                raise ValueError(
                    "Provide a full URL including the scheme, or a hostname containing a dot."
                )
        return self


class TextScanRequest(BaseScanRequest):
    """Scan free text: an email body, a message, pasted content."""

    text: Annotated[str, Field(min_length=1, max_length=MAX_TEXT_LENGTH)]

    @field_validator("text")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Text to scan must not be blank.")
        return value


class EmailScanRequest(BaseScanRequest):
    """Scan a raw RFC 5322 message.

    ``raw_message`` is accepted as the full source rather than only a body,
    because header-level authentication results (SPF, DKIM, DMARC) are often the
    most decisive evidence available for a phishing message.
    """

    raw_message: Annotated[str, Field(min_length=1, max_length=2_000_000)]
    subject: str | None = Field(default=None, max_length=MAX_SUBJECT_LENGTH)
    sender: EmailStr | None = None
    #: Only parse and analyse; never submit to reputation services.
    analyse_headers_only: bool = False


class FileScanOptions(BaseScanRequest):
    """File-specific switches."""

    #: Move a copy of the file into quarantine after analysis.
    quarantine: bool = True
    #: Skip ClamAV, e.g. when the daemon is known to be down.
    skip_antivirus: bool = False
    #: Skip YARA rule matching.
    skip_yara: bool = False
    #: Inspect nested archives (bounded by depth and expansion limits).
    inspect_archives: bool = True
    #: Extract text from documents for phishing analysis (OCR is separate).
    extract_text: bool = True


class ApkScanOptions(FileScanOptions):
    """APK-specific switches.

    Static analysis only: the application is never installed, run, or
    instrumented. Anything requiring execution is out of scope by design.
    """

    inspect_dex: bool = True
    inspect_manifest: bool = True
    verify_signature: bool = True


class FileScanResponse(BaseModel):
    """Result of a file scan."""

    scan_id: str
    scan_type: ScanType = ScanType.FILE
    object_type: ObjectType
    status: ScanStatus = ScanStatus.COMPLETED

    filename: str | None = None
    size_bytes: int | None = None
    detected_type: str | None = Field(
        default=None, description="Type identified from content, not from the filename."
    )
    sha256: str
    sha1: str | None = None
    md5: str | None = None
    entropy: float | None = None

    score: float = Field(ge=0.0, le=100.0)
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    recommendation: Recommendation
    recommendation_text: str

    signals: list[DetectionSignal] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    score_breakdown: dict[str, Any] | None = None

    quarantined: bool = False
    duration_ms: int | None = None
    disclaimer: str = DISCLAIMER
    created_at: datetime


class UrlScanResponse(BaseModel):
    """Result of a URL scan."""

    scan_id: str
    scan_type: ScanType = ScanType.URL
    object_type: ObjectType = ObjectType.URL
    status: ScanStatus = ScanStatus.COMPLETED

    url: str
    normalised_url: str | None = None
    host: str | None = None
    resolved_ips: list[str] = Field(default_factory=list)
    #: Why the scanner refused to fetch this URL, when it refused.
    fetch_blocked_reason: str | None = None
    page_title: str | None = None
    http_status: int | None = None

    score: float = Field(ge=0.0, le=100.0)
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    recommendation: Recommendation
    recommendation_text: str

    signals: list[DetectionSignal] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    score_breakdown: dict[str, Any] | None = None
    reputation: dict[str, Any] | None = Field(
        default=None, description="Per-provider reputation results, when looked up."
    )

    duration_ms: int | None = None
    disclaimer: str = DISCLAIMER
    created_at: datetime


class EmailScanResponse(BaseModel):
    """Result of an email scan."""

    scan_id: str
    scan_type: ScanType = ScanType.EMAIL
    object_type: ObjectType = ObjectType.EMAIL
    status: ScanStatus = ScanStatus.COMPLETED

    subject: str | None = None
    sender: str | None = None
    sender_domain: str | None = None
    reply_to: str | None = None
    return_path: str | None = None

    authentication: dict[str, Any] = Field(
        default_factory=dict, description="SPF, DKIM and DMARC evaluation results."
    )
    headers_of_interest: dict[str, Any] = Field(
        default_factory=dict, description="Received chain, originating IP, mail client."
    )
    attachment_count: int = 0

    score: float = Field(ge=0.0, le=100.0)
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    recommendation: Recommendation
    recommendation_text: str

    signals: list[DetectionSignal] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    score_breakdown: dict[str, Any] | None = None

    duration_ms: int | None = None
    disclaimer: str = DISCLAIMER
    created_at: datetime


class ApkScanResponse(FileScanResponse):
    """Result of an APK scan, extending the file report with Android detail."""

    scan_type: ScanType = ScanType.APK
    object_type: ObjectType = ObjectType.APK

    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    permissions_requested: list[str] = Field(default_factory=list)
    dangerous_permissions: list[str] = Field(default_factory=list)
    declared_components: dict[str, Any] = Field(default_factory=dict)
    signature: dict[str, Any] = Field(default_factory=dict)
    #: Always False. Stated explicitly so the client cannot imply otherwise.
    dynamically_analysed: bool = False


class TextScanResponse(BaseModel):
    """Result of a free-text scan."""

    scan_id: str
    scan_type: ScanType = ScanType.QUICK
    object_type: ObjectType = ObjectType.TEXT
    status: ScanStatus = ScanStatus.COMPLETED

    character_count: int
    extracted_urls: list[str] = Field(default_factory=list)
    extracted_emails: list[str] = Field(default_factory=list)

    score: float = Field(ge=0.0, le=100.0)
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    recommendation: Recommendation
    recommendation_text: str

    signals: list[DetectionSignal] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    score_breakdown: dict[str, Any] | None = None

    duration_ms: int | None = None
    disclaimer: str = DISCLAIMER
    created_at: datetime


class ScanSummary(BaseModel):
    """Compact row for history and list views."""

    model_config = ConfigDict(from_attributes=True)

    scan_id: str
    scan_type: ScanType
    object_type: ObjectType
    status: ScanStatus
    target: str = Field(description="URL, sender, filename or a short descriptor.")
    score: float | None
    verdict: Verdict | None
    created_at: datetime


class ScanDetail(BaseModel):
    """Full persisted report for one scan history entry.

    This is the generic envelope returned by ``GET /scans/{scan_id}``. The
    type-specific response models carry exactly the same core fields, so a client
    can render either from one widget; ``metadata_json`` holds the
    scan-type-specific detail (reputation answers, fetch state, parsed email
    fields, APK manifest facts).
    """

    scan_id: str
    scan_type: ScanType
    object_type: ObjectType
    status: ScanStatus
    target: str

    score: float | None = None
    verdict: Verdict | None = None
    confidence: float | None = None
    recommendation: Recommendation | None = None
    reasons: list[str] = Field(default_factory=list)
    signals: list[Any] = Field(default_factory=list)
    score_breakdown: dict[str, Any] | None = None
    metadata_json: dict[str, Any] | None = None

    target_url: str | None = None
    target_host: str | None = None
    target_email: str | None = None
    email_subject: str | None = None
    original_filename: str | None = None
    storage_key: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    is_quarantined: bool = False
    duration_ms: int | None = None
    analyzers_run: str | None = None
    error_message: str | None = None

    created_at: datetime
    expires_at: datetime | None = None


class PaginatedResponse(BaseModel):
    """Envelope for list endpoints."""

    items: list[Any]
    total: int
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    pages: int = Field(ge=0)

    @classmethod
    def build(cls, items: list[Any], total: int, page: int, page_size: int) -> "PaginatedResponse":
        pages = (total + page_size - 1) // page_size if page_size else 0
        return cls(items=items, total=total, page=page, page_size=page_size, pages=pages)


class ScanFilterParams(BaseModel):
    """Query parameters for scan history."""

    scan_type: ScanType | None = None
    verdict: Verdict | None = None
    min_score: float | None = Field(default=None, ge=0, le=100)
    max_score: float | None = Field(default=None, ge=0, le=100)
    search: str | None = Field(default=None, max_length=200)
    since: datetime | None = None
    until: datetime | None = None
    page: int = Field(default=1, ge=1, le=10_000)
    page_size: int = Field(default=20, ge=1, le=100)

    @model_validator(mode="after")
    def _check_range(self) -> "ScanFilterParams":
        if (
            self.min_score is not None
            and self.max_score is not None
            and self.min_score > self.max_score
        ):
            raise ValueError("min_score must be less than or equal to max_score.")
        if self.since and self.until and self.since > self.until:
            raise ValueError("since must be earlier than until.")
        return self


class SubmitFeedbackRequest(BaseModel):
    """User verdict on a report, used to measure real-world accuracy."""

    model_config = ConfigDict(extra="forbid")

    label: Literal["true_positive", "false_positive", "false_negative", "unsure"]
    comment: str | None = Field(default=None, max_length=1000)


class StatsBucket(BaseModel):
    """One point in a time series."""

    date: datetime
    total: int = 0
    safe: int = 0
    suspicious: int = 0
    malicious: int = 0


class DashboardStats(BaseModel):
    """Aggregate counters for the home screen."""

    total_scans: int
    safe_count: int
    low_risk_count: int
    suspicious_count: int
    high_risk_count: int
    malicious_count: int
    unknown_count: int
    average_score: float
    average_confidence: float
    quarantined_files: int
    timeline: list[StatsBucket] = Field(default_factory=list)
    top_threat_types: list[dict[str, Any]] = Field(default_factory=list)
    detector_agreement: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime


class ScannerHealth(BaseModel):
    """Availability and freshness of one detector backend."""

    name: str
    available: bool
    detail: str | None = None
    latency_ms: int | None = None
    signal_count: int = 0


class HealthResponse(BaseModel):
    """Liveness and readiness."""

    status: Literal["ok", "degraded", "unavailable"]
    version: str
    environment: str
    uptime_seconds: float
    checks: dict[str, Any] = Field(default_factory=dict)
    disclaimer: str = DISCLAIMER


class SignalSearchHit(BaseModel):
    """One search result over stored signals."""

    scan_id: str
    code: str
    title: str
    description: str
    severity: Severity
    source: SignalSource
    category: str
    confidence: float
    created_at: datetime


__all__ = [
    "ApkScanOptions",
    "ApkScanResponse",
    "ConsentOptions",
    "DashboardStats",
    "EmailScanRequest",
    "EmailScanResponse",
    "FileScanOptions",
    "FileScanResponse",
    "HealthResponse",
    "PaginatedResponse",
    "ScanDetail",
    "ScanFilterParams",
    "ScanSummary",
    "ScannerHealth",
    "SignalSearchHit",
    "StatsBucket",
    "SubmitFeedbackRequest",
    "TextScanRequest",
    "TextScanResponse",
    "UrlScanRequest",
    "UrlScanResponse",
]