"""Core, dependency-free data types shared by every CyberShield analysis engine.

The detection engine is intentionally implemented as a standalone package with no
web-framework or database dependencies.  This keeps the security logic pure,
deterministic and trivially unit-testable, and lets the same code be embedded in
the FastAPI backend, in offline CLI tooling, or in a future desktop helper.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

__all__ = [
    "Severity",
    "Verdict",
    "SignalSource",
    "ObjectType",
    "ScanStatus",
    "Finding",
    "AnalysisResult",
    "Indicator",
    "Recommendation",
    "utcnow",
]


def utcnow() -> datetime:
    """Return an aware UTC timestamp.

    A single helper keeps timestamps consistent and makes them easy to monkeypatch
    in tests.
    """
    return datetime.now(tz=timezone.utc)


class Severity(str, Enum):
    """How serious an individual finding is.

    The ordering matters: ``max()`` over severities is used when collapsing many
    findings into a single verdict.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Verdict(str, Enum):
    """Final security verdict for a scanned object."""

    SAFE = "SAFE"
    LOW_RISK = "LOW RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


#: Inclusive ``(lower_bound, verdict)`` pairs.  Anything >= 80 is MALICIOUS.
VERDICT_THRESHOLDS: tuple[tuple[int, Verdict], ...] = (
    (80, Verdict.MALICIOUS),
    (60, Verdict.HIGH_RISK),
    (40, Verdict.SUSPICIOUS),
    (20, Verdict.LOW_RISK),
    (0, Verdict.SAFE),
)


def verdict_for_score(score: float) -> Verdict:
    """Map a 0-100 risk score onto a :class:`Verdict`."""
    value = max(0, min(100.0, float(score)))
    for threshold, verdict in VERDICT_THRESHOLDS:
        if value >= threshold:
            return verdict
    return Verdict.SAFE  # pragma: no cover - unreachable, 0 threshold catches all


class SignalSource(str, Enum):
    """Which engine produced a finding.

    Kept as an enum so the UI can group evidence by engine and so the risk engine
    can apply per-source reliability factors.
    """

    URL_SYNTAX = "url_syntax"
    URL_DOMAIN = "url_domain"
    URL_DNS = "url_dns"
    URL_TLS = "url_tls"
    URL_REDIRECT = "url_redirect"
    URL_REPUTATION = "url_reputation"
    PHISHING = "phishing"
    EMAIL_STRUCTURE = "email_structure"
    EMAIL_AUTH = "email_auth"
    FILE_INTEGRITY = "file_integrity"
    FILE_STRUCTURE = "file_structure"
    FILE_METADATA = "file_metadata"
    FILE_ENTROPY = "file_entropy"
    OFFICE_DOCUMENT = "office_document"
    PDF_DOCUMENT = "pdf_document"
    IMAGE_ANALYSIS = "image_analysis"
    ARCHIVE = "archive"
    APK_MANIFEST = "apk_manifest"
    APK_PERMISSIONS = "apk_permissions"
    APK_CODE = "apk_code"
    APK_CERTIFICATE = "apk_certificate"
    #: A credential matching a named vendor's exact shape.  Distinct from
    #: ``APK_CODE`` because a vendor-issued key format is a deterministic match,
    #: not an interpretation of what code *might* do.
    APK_SECRET = "apk_secret"
    CLAMAV = "clamav"
    YARA = "yara"
    THREAT_INTEL = "threat_intel"
    ML_MODEL = "ml_model"
    HASH = "hash"
    ENGINE = "engine"


#: Per-source reliability multiplier.  Deterministic signatures (ClamAV, YARA,
#: reputation feeds) carry more weight than heuristic observations, which are the
#: main source of false positives.
SOURCE_RELIABILITY: dict[SignalSource, float] = {
    SignalSource.CLAMAV: 1.0,
    SignalSource.YARA: 0.95,
    SignalSource.THREAT_INTEL: 0.95,
    SignalSource.HASH: 0.9,
    SignalSource.URL_REPUTATION: 0.9,
    SignalSource.FILE_INTEGRITY: 0.85,
    SignalSource.EMAIL_AUTH: 0.85,
    SignalSource.URL_REDIRECT: 0.8,
    SignalSource.APK_CERTIFICATE: 0.8,
    SignalSource.URL_DOMAIN: 0.8,
    SignalSource.URL_SYNTAX: 0.75,
    SignalSource.URL_DNS: 0.75,
    SignalSource.URL_TLS: 0.7,
    SignalSource.OFFICE_DOCUMENT: 0.7,
    SignalSource.PDF_DOCUMENT: 0.7,
    SignalSource.FILE_STRUCTURE: 0.65,
    SignalSource.FILE_ENTROPY: 0.6,
    SignalSource.ARCHIVE: 0.6,
    SignalSource.APK_CODE: 0.6,
    SignalSource.APK_PERMISSIONS: 0.6,
    # A credential matching a vendor's exact published key format is about as
    # reliable as a signature match.  It is not authoritative - the credential
    # may be long dead - but it is certainly *present*.
    SignalSource.APK_SECRET: 0.95,
    SignalSource.EMAIL_STRUCTURE: 0.6,
    SignalSource.PHISHING: 0.55,
    SignalSource.APK_MANIFEST: 0.55,
    SignalSource.ML_MODEL: 0.55,
    SignalSource.IMAGE_ANALYSIS: 0.5,
    SignalSource.FILE_METADATA: 0.5,
    SignalSource.ENGINE: 0.5,
}


class ObjectType(str, Enum):
    """Types of objects CyberShield knows how to analyse."""

    URL = "url"
    EMAIL = "email"
    IMAGE = "image"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    APK = "apk"
    TEXT = "text"
    BINARY = "binary"
    UNKNOWN = "unknown"


class ScanStatus(str, Enum):
    """Lifecycle of an asynchronous scan job."""

    QUEUED = "QUEUED"
    SCANNING = "SCANNING"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


#: Default base weight applied to a finding, derived from its severity.  Individual
#: findings may override this with a measured value.
SEVERITY_BASE_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 2.0,
    Severity.LOW: 8.0,
    Severity.MEDIUM: 16.0,
    Severity.HIGH: 26.0,
    Severity.CRITICAL: 45.0,
}


@dataclass(slots=True)
class Finding:
    """A single, explainable security observation.

    A finding is the atomic unit of CyberShield's explainability: every point of
    risk in a :class:`AnalysisResult` can be traced back to one of these, and each
    carries a human-readable justification plus the raw evidence that produced it.
    """

    code: str
    title: str
    detail: str
    severity: Severity = Severity.MEDIUM
    source: SignalSource = SignalSource.ENGINE
    category: str = "general"
    #: Base risk contribution before source-reliability damping (0-100).
    weight: float | None = None
    #: Extra structured data (offending substring, header value, byte offset...).
    evidence: dict[str, Any] = field(default_factory=dict)
    #: When True the risk engine treats this as an authoritative positive
    #: detection and applies a score floor (used for confirmed malware matches).
    authoritative: bool = False

    @property
    def effective_weight(self) -> float:
        """Weight after applying the source reliability multiplier."""
        base = self.weight if self.weight is not None else SEVERITY_BASE_WEIGHT[self.severity]
        reliability = SOURCE_RELIABILITY.get(self.source, 0.6)
        return max(0.0, min(100.0, base * reliability))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity.value,
            "source": self.source.value,
            "category": self.category,
            "weight": round(self.effective_weight, 2),
            "evidence": self.evidence,
            "authoritative": self.authoritative,
        }


@dataclass(slots=True)
class Indicator:
    """An observable artifact extracted from the scanned object.

    Indicators are the "detected indicators" list in a security report: domains,
    IPs, URLs, hashes, file paths, permission names, API names and so on.
    """

    kind: str
    value: str
    #: True when the indicator is itself considered malicious.
    malicious: bool = False
    #: Where it was found ("manifest", "strings", "header", ...).
    context: str = ""
    first_seen: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "malicious": self.malicious,
            "context": self.context,
            "first_seen": self.first_seen.isoformat(),
        }


@dataclass(slots=True)
class Recommendation:
    """A concrete, user-facing next step."""

    action: str
    priority: str = "normal"
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"action": self.action, "priority": self.priority, "rationale": self.rationale}


@dataclass(slots=True)
class AnalysisResult:
    """The complete output of analysing one object.

    Assembled by the scanner orchestrators, then passed through
    :class:`detection_engine.scoring.RiskEngine` to produce the final score,
    verdict and confidence.
    """

    object_type: ObjectType
    object_name: str = ""
    findings: list[Finding] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    recommendations: list[Recommendation] = field(default_factory=list)
    #: Names of engines that actually ran (used to lower confidence when coverage
    #: is poor).
    engines_ran: list[str] = field(default_factory=list)
    #: Set to True when analysis could not be completed meaningfully.
    incomplete: bool = False
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=utcnow)

    # Filled in by the risk engine.
    score: float = 0.0
    verdict: Verdict = Verdict.UNKNOWN
    confidence: float = 0.0
    #: Ordered (code, contribution) pairs explaining the score.
    score_breakdown: list[dict[str, Any]] = field(default_factory=list)
    #: Plain-language caveat shown in every report.
    disclaimer: str = ""

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def add_indicator(self, kind: str, value: str, **kwargs: Any) -> Indicator:
        indicator = Indicator(kind=kind, value=value, **kwargs)
        self.indicators.append(indicator)
        return indicator

    @property
    def top_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.effective_weight, reverse=True)

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "object_type": self.object_type.value,
            "object_name": self.object_name,
            "score": round(self.score, 1),
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 3),
            "incomplete": self.incomplete,
            "engines_ran": self.engines_ran,
            "findings": [f.to_dict() for f in self.top_findings],
            "indicators": [i.to_dict() for i in self.indicators],
            "metadata": self.metadata,
            "recommendations": [r.to_dict() for r in self.recommendations],
            "score_breakdown": self.score_breakdown,
            "disclaimer": self.disclaimer,
            "created_at": self.created_at.isoformat(),
        }