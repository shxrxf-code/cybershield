"""Threat-intelligence schemas.

Every provider is wrapped into :class:`IntelResult` so the aggregation layer and
the risk engine see one shape regardless of which service answered. Provenance
is mandatory: a report must be able to say *which* service concluded what, and
whether that conclusion was a positive detection or a clean result.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import IndicatorType, Severity, SignalSource


class IntelVerdict(str, Enum):
    """Normalised provider outcome."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"
    ERROR = "error"


class IntelResult(BaseModel):
    """One provider's answer about one indicator."""

    model_config = ConfigDict(frozen=True)

    provider: str = Field(description="Provider identifier, e.g. 'virustotal'.")
    indicator: str
    indicator_type: IndicatorType
    verdict: IntelVerdict = IntelVerdict.UNKNOWN

    #: How many engines/feeds flagged it, and how many were asked. ``None``
    #: when the provider does not publish per-engine detail.
    detections: int | None = None
    total_engines: int | None = None

    #: Provider-reported score, normalised to 0-1. Not comparable between
    #: providers, so it is reported alongside the provider name, never merged.
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    categories: list[str] = Field(default_factory=list)
    threat_type: str | None = None
    source_name: str | None = None
    reference_url: str | None = None
    malware_families: list[str] = Field(default_factory=list)

    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[str] = Field(default_factory=list)

    #: True when served from cache rather than a live provider call.
    from_cache: bool = False
    #: Set when the provider could not be reached. A timeout is never silently
    #: converted into a clean verdict.
    error: str | None = None
    latency_ms: int | None = None
    #: Extra provider-specific detail (community votes, reputation score, ...).
    #: Never contains credentials.
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_positive(self) -> bool:
        return self.verdict in (IntelVerdict.MALICIOUS, IntelVerdict.SUSPICIOUS)

    @property
    def is_definitive_clean(self) -> bool:
        """True only for a clean answer from a provider that actually answered."""
        return self.verdict is IntelVerdict.CLEAN and self.error is None


class IntelSummary(BaseModel):
    """Aggregated view across all providers that were consulted."""

    results: list[IntelResult] = Field(default_factory=list)
    providers_queried: int = 0
    providers_failed: int = 0
    #: True when at least one provider reported a positive detection.
    any_positive: bool = False
    #: True when every queried provider returned a clean answer with no error.
    all_clean: bool = False
    consensus: str = Field(
        default="unknown",
        description="'malicious' | 'suspicious' | 'clean' | 'mixed' | 'unknown'.",
    )
    scanned_at: datetime


def to_signal(result: IntelResult) -> dict[str, Any]:
    """Convert a positive lookup into signal-field arguments.

    Returned as a dict rather than a constructed :class:`DetectionSignal` to keep
    this module free of a dependency on the detection engine; the caller builds
    the signal with the right severity mapping for the scan type.
    """
    detections = result.detections
    total = result.total_engines or 0
    return {
        "code": f"intel.{result.provider}_{result.indicator_type.value}",
        "title": f"{result.provider} reports this {result.indicator_type.value.replace('_', ' ')} as malicious",
        "description": (
            f"{result.provider} lists this indicator as malicious"
            + (f" ({detections}/{total} detections)" if detections is not None and total else "")
            + (f" [{result.threat_type}]" if result.threat_type else "")
            + "."
        ),
        "severity": Severity.HIGH if result.verdict is IntelVerdict.MALICIOUS else Severity.MEDIUM,
        "category": "threat_intelligence",
        "source": SignalSource.THREAT_INTELLIGENCE,
        "confidence": result.confidence if result.confidence is not None else 0.9,
        "evidence": {
            "provider": result.provider,
            "detections": detections,
            "total_engines": total,
            "threat_type": result.threat_type,
            "categories": result.categories,
            "from_cache": result.from_cache,
        },
    }


__all__ = [
    "IntelResult",
    "IntelSummary",
    "IntelVerdict",
    "to_signal",
]