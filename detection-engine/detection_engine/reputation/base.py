"""Provider-agnostic threat-intelligence interface.

Every external feed is implemented behind :class:`ThreatIntelProvider` so that

* providers are independently replaceable and individually disableable,
* the aggregation logic (and therefore the risk scoring) is identical regardless
  of which feeds are configured,
* the engine degrades gracefully: a provider that times out, returns garbage or
  is switched off simply contributes nothing instead of failing the scan.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "IndicatorType",
    "ProviderStatus",
    "IndicatorVerdict",
    "ProviderResult",
    "ThreatIntelProvider",
]


class IndicatorType(str, Enum):
    """Kinds of indicator a provider can be asked about."""

    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    CERTIFICATE = "certificate"
    EMAIL = "email"


class ProviderStatus(str, Enum):
    OK = "ok"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"
    DISABLED = "disabled"
    TIMEOUT = "timeout"


@dataclass(slots=True)
class IndicatorVerdict:
    """Normalised reputation verdict from one provider."""

    indicator: str
    indicator_type: IndicatorType
    #: True only when the provider positively reports the indicator as harmful.
    malicious: bool = False
    #: Provider confidence 0..1, when the provider supplies one.
    confidence: float = 0.0
    #: Number of independent reports the provider attributes to the indicator.
    report_count: int = 0
    categories: list[str] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)
    source: str = ""
    status: ProviderStatus = ProviderStatus.OK
    error: str | None = None
    cache_age_seconds: float = 0.0

    @property
    def suspicious(self) -> bool:
        """Reported as harmful or explicitly called out by the provider."""
        return self.malicious or self.report_count > 0

    def to_dict(self) -> dict[str, object]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type.value,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "confidence": round(self.confidence, 3),
            "report_count": self.report_count,
            "categories": self.categories,
            "source": self.source,
            "status": self.status.value,
            "error": self.error,
        }


@dataclass(slots=True)
class ProviderResult:
    """Aggregate outcome of querying every configured provider for one object."""

    indicator: str
    indicator_type: IndicatorType
    verdicts: list[IndicatorVerdict] = field(default_factory=list)
    #: How many providers were queried successfully.
    providers_queried: int = 0
    #: How many providers were configured but unavailable.
    providers_failed: int = 0

    @property
    def confirming_providers(self) -> list[IndicatorVerdict]:
        return [v for v in self.verdicts if v.suspicious]

    @property
    def any_malicious(self) -> bool:
        return any(v.malicious for v in self.verdicts)

    @property
    def any_suspicious(self) -> bool:
        return any(v.suspicious for v in self.verdicts)

    @property
    def total_reports(self) -> int:
        return sum(v.report_count for v in self.verdicts)

    @property
    def categories(self) -> list[str]:
        merged: set[str] = set()
        for verdict in self.verdicts:
            merged.update(verdict.categories)
        return sorted(merged)

    @property
    def mean_confidence(self) -> float:
        confirmed = self.confirming_providers
        if not confirmed:
            return 0.0
        return sum(v.confidence for v in confirmed) / len(confirmed)

    @property
    def degraded(self) -> bool:
        """True when no provider answered, so absence of evidence is not evidence."""
        return self.providers_queried == 0 and self.providers_failed > 0

    def to_dict(self) -> dict[str, object]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type.value,
            "providers_queried": self.providers_queried,
            "providers_failed": self.providers_failed,
            "any_malicious": self.any_malicious,
            "any_suspicious": self.any_suspicious,
            "total_reports": self.total_reports,
            "categories": self.categories,
            "mean_confidence": round(self.mean_confidence, 3),
            "degraded": self.degraded,
            "verdicts": [v.to_dict() for v in self.verdicts],
        }


class ThreatIntelProvider(abc.ABC):
    """Base class for every threat-intelligence feed.

    Subclasses must never raise out of :meth:`check_url`/:meth:`check_hash`:
    network failures are reported as :class:`ProviderStatus` values so one broken
    feed cannot fail a scan.
    """

    #: Stable machine name used in configuration and audit logs.
    name: str = "unnamed"
    #: Indicator types this provider supports.
    supported_types: frozenset[IndicatorType] = frozenset({IndicatorType.URL})
    #: Whether the provider requires an API key.
    requires_api_key: bool = False
    #: Whether a positive answer is treated as authoritative.
    authoritative: bool = False

    async def check_url(self, url: str) -> IndicatorVerdict:
        raise NotImplementedError

    async def check_hash(self, sha256: str) -> IndicatorVerdict:
        raise NotImplementedError

    async def check_domain(self, domain: str) -> IndicatorVerdict:
        raise NotImplementedError

    async def check_ip(self, ip: str) -> IndicatorVerdict:
        raise NotImplementedError

    async def aclose(self) -> None:
        """Release any network resources.  Safe to call unconditionally."""
        return None

    # -- helpers ------------------------------------------------------- #

    def disabled_verdict(
        self, indicator: str, indicator_type: IndicatorType, reason: str
    ) -> IndicatorVerdict:
        return IndicatorVerdict(
            indicator=indicator,
            indicator_type=indicator_type,
            status=ProviderStatus.DISABLED,
            source=self.name,
            error=reason,
        )

    def error_verdict(
        self, indicator: str, indicator_type: IndicatorType, reason: str
    ) -> IndicatorVerdict:
        return IndicatorVerdict(
            indicator=indicator,
            indicator_type=indicator_type,
            status=ProviderStatus.ERROR,
            source=self.name,
            error=reason,
        )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<{type(self).__name__} name={self.name!r}>"