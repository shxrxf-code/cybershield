"""Core domain vocabulary: verdicts, severities, signal sources and scan status."""

from __future__ import annotations

from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """Security verdict returned for every analysed object.

    ``UNKNOWN`` is a first-class outcome: it means the analysis could not reach a
    defensible conclusion (unsupported type, scanner unavailable, inconclusive
    evidence). It is never silently downgraded to ``SAFE``.
    """

    SAFE = "SAFE"
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"

    @property
    def is_safe_enough(self) -> bool:
        return self in (Verdict.SAFE, Verdict.LOW_RISK)


# Score bands. Evaluated as half-open intervals (low <= score < next low) so a
# fractional score stays in its own band; the boundaries are the published ones.
VERDICT_BANDS: tuple[tuple[int, int, Verdict], ...] = (
    (0, 19, Verdict.SAFE),
    (20, 39, Verdict.LOW_RISK),
    (40, 59, Verdict.SUSPICIOUS),
    (60, 79, Verdict.HIGH_RISK),
    (80, 100, Verdict.MALICIOUS),
)


def verdict_for_score(score: float) -> Verdict:
    """Map a 0-100 risk score onto its published verdict band.

    >>> verdict_for_score(0), verdict_for_score(19.9), verdict_for_score(20)
    (<Verdict.SAFE: 'SAFE'>, <Verdict.SAFE: 'SAFE'>, <Verdict.LOW_RISK: 'LOW_RISK'>)
    >>> verdict_for_score(80), verdict_for_score(100)
    (<Verdict.MALICIOUS: 'MALICIOUS'>, <Verdict.MALICIOUS: 'MALICIOUS'>)

    Bands are evaluated as half-open intervals ``low <= score < next_low`` so a
    fractional score such as 19.9 stays in the SAFE band instead of falling
    through every range.
    """
    clamped = max(0.0, min(100.0, float(score)))
    for index, (low, high, verdict) in enumerate(VERDICT_BANDS):
        upper = VERDICT_BANDS[index + 1][0] if index + 1 < len(VERDICT_BANDS) else high + 1
        if low <= clamped < upper:
            return verdict
    return Verdict.MALICIOUS


class Severity(str, Enum):
    """Severity of an individual detection signal."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def default_weight(self) -> float:
        """Nominal contribution of this severity to the risk score (0-1)."""
        return _SEVERITY_WEIGHT[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

#: Nominal share of a category's budget that one signal of this severity may
#: claim when fully corroborated. These are calibrated so that a single
#: HIGH-severity finding corroborated by independent evidence reaches the
#: SUSPICIOUS band, and corroboration is required to reach HIGH_RISK or
#: MALICIOUS. See docs/project-report/detection-methodology.md.
_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.04,
    Severity.LOW: 0.16,
    Severity.MEDIUM: 0.38,
    Severity.HIGH: 0.62,
    Severity.CRITICAL: 0.88,
}


class SignalSource(str, Enum):
    """Provenance of a detection signal.

    Provenance is preserved end-to-end so that a report can distinguish an
    authoritative threat-intelligence match from a machine-learned hint.
    """

    ANTIVIRUS = "antivirus"
    YARA = "yara"
    THREAT_INTELLIGENCE = "threat_intelligence"
    REPUTATION = "reputation"
    STRUCTURAL = "structural"
    HEURISTIC = "heuristic"
    AUTHENTICATION = "authentication"
    MACHINE_LEARNING = "machine_learning"
    STATIC_ANALYSIS = "static_analysis"
    POLICY = "policy"


class IndicatorType(str, Enum):
    """Types of indicators extracted during analysis."""

    URL = "url"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL_ADDRESS = "email_address"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    PERMISSION = "permission"
    CERTIFICATE = "certificate"
    SUSPICIOUS_TOKEN = "suspicious_token"
    RAW_INDICATOR = "raw_indicator"


class ScanType(str, Enum):
    """Supported scan entry points."""

    URL = "url"
    EMAIL = "email"
    FILE = "file"
    APK = "apk"
    QUICK = "quick"


class ScanStatus(str, Enum):
    """Lifecycle of an asynchronous scan job."""

    QUEUED = "QUEUED"
    SCANNING = "SCANNING"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

    @property
    def is_terminal(self) -> bool:
        return self in (ScanStatus.COMPLETED, ScanStatus.FAILED)


class ObjectType(str, Enum):
    """Nature of the analysed object."""

    URL = "url"
    DOMAIN = "domain"
    EMAIL = "email"
    FILE = "file"
    IMAGE = "image"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    APK = "apk"
    TEXT = "text"
    UNKNOWN = "unknown"


class Recommendation(str, Enum):
    """Standard, human-actionable response for a verdict."""

    NONE = "none"
    MONITOR = "monitor"
    VERIFY_SENDER = "verify_sender"
    DO_NOT_OPEN = "do_not_open"
    DO_NOT_DOWNLOAD = "do_not_download"
    DO_NOT_INSTALL = "do_not_install"
    QUARANTINE = "quarantine"
    DELETE = "delete"
    BLOCK = "block"
    REPORT = "report"
    MANUAL_REVIEW = "manual_review"


RECOMMENDATION_TEXT: dict[Recommendation, str] = {
    Recommendation.NONE: "No action required. This object showed no significant risk indicators.",
    Recommendation.MONITOR: "No immediate action required. This object will be re-checked if it changes.",
    Recommendation.VERIFY_SENDER: (
        "Verify the sender through a known-good channel before acting on this message. "
        "Do not use any contact details or links contained in it."
    ),
    Recommendation.DO_NOT_OPEN: (
        "Do not open or preview this file. Prefer obtaining it from a trusted, verified source."
    ),
    Recommendation.DO_NOT_DOWNLOAD: (
        "Do not download or run the referenced content. Remove it from your downloads folder."
    ),
    Recommendation.DO_NOT_INSTALL: (
        "Do not install this application. Remove the installer and review the permissions it requests."
    ),
    Recommendation.QUARANTINE: (
        "Move this file to quarantine, or delete it if it is not required. Do not execute it."
    ),
    Recommendation.DELETE: "Delete this file and any copies of it from your device.",
    Recommendation.BLOCK: (
        "Block this destination at your network or browser layer and report it to your security team."
    ),
    Recommendation.REPORT: (
        "Report this object to your security team or to the relevant abuse contact for the target domain."
    ),
    Recommendation.MANUAL_REVIEW: (
        "Escalate this object for manual analysis by a security analyst before it is trusted."
    ),
}


DISCLAIMER: str = (
    "CyberShield produces automated, evidence-based risk assessments. It cannot guarantee "
    "that an object is safe or malicious: false positives and false negatives are possible. "
    "Treat the verdict as one input into your security decision, alongside user judgement and "
    "other controls."
)


def json_safe(value: Any) -> Any:
    """Recursively coerce a value into something JSON-serialisable."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(v) for v in value]
    if isinstance(value, bytes):
        return value[:64].hex()
    return str(value)