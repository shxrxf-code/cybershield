"""Exception hierarchy for the detection engine.

Every exception carries a stable ``code`` so the API layer can translate engine
failures into consistent HTTP responses without leaking internals.
"""

from __future__ import annotations

__all__ = [
    "DetectionEngineError",
    "UnsupportedObjectError",
    "MalformedObjectError",
    "AnalysisTimeoutError",
    "ThreatIntelError",
    "ScannerUnavailableError",
    "ParserError",
    "NameResolutionError",
]


class DetectionEngineError(Exception):
    """Base class for all detection-engine failures."""

    code = "engine_error"
    status_code = 422

    def __init__(self, message: str, *, detail: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def to_dict(self) -> dict[str, str]:
        payload = {"code": self.code, "message": self.message}
        if self.detail:
            payload["detail"] = self.detail
        return payload


class UnsupportedObjectError(DetectionEngineError):
    """The submitted object type has no registered analyzer."""

    code = "unsupported_object"
    status_code = 415


class MalformedObjectError(DetectionEngineError):
    """The object could be parsed but is structurally invalid."""

    code = "malformed_object"
    status_code = 422


class ParserError(DetectionEngineError):
    """A format-specific parser failed on well-typed input."""

    code = "parse_error"
    status_code = 422


class AnalysisTimeoutError(DetectionEngineError):
    """An analyzer exceeded its time budget."""

    code = "analysis_timeout"
    status_code = 504


class ThreatIntelError(DetectionEngineError):
    """A threat-intelligence provider failed or misbehaved."""

    code = "threat_intel_error"
    status_code = 502


class ScannerUnavailableError(DetectionEngineError):
    """An external scanner (ClamAV, YARA runtime, ...) is not reachable."""

    code = "scanner_unavailable"
    status_code = 503


class NameResolutionError(DetectionEngineError):
    """A hostname could not be resolved to any address.

    This is deliberately a *different* type from an SSRF block.  A host that
    does not exist is evidence about the link (it may be a dead campaign
    domain, or a typo), not evidence that the target tried to reach internal
    infrastructure.  Conflating the two makes every dead phishing domain
    escalate to an authoritative SSRF finding.
    """

    code = "name_resolution_failed"
    status_code = 502