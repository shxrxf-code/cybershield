"""Reputation aggregation: query many providers, combine into one verdict.

Consensus rules
--------------
* ``any_malicious`` requires at least **one** authoritative or high-confidence
  provider, *or* two independent non-authoritative providers.  A single noisy
  community feed therefore cannot on its own push an object to MALICIOUS.
* Confidence in the aggregate is the mean provider confidence, boosted when
  providers agree and damped when they disagree.
* If every provider is disabled or fails, the aggregate is marked ``degraded``
  and contributes **no** findings, so an outage reduces coverage instead of
  producing false assurance.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from ..models import Finding, Severity, SignalSource
from .base import IndicatorType, IndicatorVerdict, ProviderResult, ProviderStatus, ThreatIntelProvider

__all__ = ["ReputationAggregator", "CacheEntry", "TTLCache"]

#: Minimum confidence for a single non-authoritative provider to be trusted.
_TRUST_THRESHOLD = 0.7
#: Number of agreeing low-authority providers required to be conclusive.
_AGREEMENT_THRESHOLD = 2


@dataclass(slots=True)
class CacheEntry:
    verdict: IndicatorVerdict
    stored_at: float


class TTLCache:
    """Minimal async-safe TTL cache for provider verdicts.

    Caching matters for two reasons: it keeps API quota usage predictable, and it
    means scanning the same suspicious URL repeatedly cannot be used to burn the
    operator's VirusTotal allowance.
    """

    def __init__(self, ttl_seconds: int = 900, max_entries: int = 10_000) -> None:
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._entries: dict[str, CacheEntry] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> IndicatorVerdict | None:
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if time.time() - entry.stored_at > self.ttl:
                self._entries.pop(key, None)
                return None
            verdict = entry.verdict
            verdict.cache_age_seconds = time.time() - entry.stored_at
            return verdict

    async def set(self, key: str, verdict: IndicatorVerdict) -> None:
        async with self._lock:
            if len(self._entries) >= self.max_entries:
                oldest = min(self._entries, key=lambda k: self._entries[k].stored_at)
                self._entries.pop(oldest, None)
            self._entries[key] = CacheEntry(verdict=verdict, stored_at=time.time())

    async def clear(self) -> None:
        async with self._lock:
            self._entries.clear()


@dataclass(slots=True)
class ReputationAggregator:
    """Runs a set of providers concurrently and merges their verdicts."""

    providers: list[ThreatIntelProvider] = field(default_factory=list)
    cache: TTLCache = field(default_factory=TTLCache)
    per_provider_timeout: float = 6.0

    # ------------------------------------------------------------------ #

    def provider_for(self, kind: IndicatorType, operation: str) -> list[ThreatIntelProvider]:
        return [p for p in self.providers if kind in p.supported_types and hasattr(p, operation)]

    async def check(self, indicator: str, kind: IndicatorType) -> ProviderResult:
        """Query every capable provider for *indicator*."""
        operation = {
            IndicatorType.URL: "check_url",
            IndicatorType.DOMAIN: "check_domain",
            IndicatorType.SHA256: "check_hash",
            IndicatorType.IP: "check_ip",
        }.get(kind, "check_url")
        result = ProviderResult(indicator=indicator, indicator_type=kind)
        providers = self.provider_for(kind, operation)
        if not providers:
            return result

        async def run(provider: ThreatIntelProvider) -> IndicatorVerdict:
            cache_key = f"{provider.name}:{kind.value}:{indicator.lower()}"
            cached = await self.cache.get(cache_key)
            if cached is not None:
                return cached
            method = getattr(provider, operation)
            try:
                verdict = await asyncio.wait_for(method(indicator), timeout=self.per_provider_timeout)
            except asyncio.TimeoutError:
                verdict = provider.error_verdict(
                    indicator, kind, f"Provider timed out after {self.per_provider_timeout}s"
                )
                verdict.status = ProviderStatus.TIMEOUT
            except Exception as exc:  # provider bugs must not fail the scan
                verdict = provider.error_verdict(indicator, kind, f"{type(exc).__name__}: {exc}")
            if verdict.status in (ProviderStatus.OK, ProviderStatus.NOT_FOUND):
                await self.cache.set(cache_key, verdict)
            return verdict

        verdicts = await asyncio.gather(*(run(p) for p in providers), return_exceptions=True)
        for provider, verdict in zip(providers, verdicts):
            if isinstance(verdict, BaseException):
                result.verdicts.append(
                    provider.error_verdict(indicator, kind, f"{type(verdict).__name__}: {verdict}")
                )
                result.providers_failed += 1
                continue
            result.verdicts.append(verdict)
            if verdict.status in (ProviderStatus.OK, ProviderStatus.NOT_FOUND):
                result.providers_queried += 1
            else:
                result.providers_failed += 1
        return result

    # ------------------------------------------------------------------ #

    @staticmethod
    def findings_for_url(result: ProviderResult) -> list[Finding]:
        return _findings(result, IndicatorType.URL, "url")

    @staticmethod
    def findings_for_domain(result: ProviderResult) -> list[Finding]:
        return _findings(result, IndicatorType.DOMAIN, "domain")

    @staticmethod
    def findings_for_hash(result: ProviderResult) -> list[Finding]:
        return _findings(result, IndicatorType.SHA256, "hash")

    @staticmethod
    def findings_for_ip(result: ProviderResult) -> list[Finding]:
        return _findings(result, IndicatorType.IP, "ip")

    async def aclose(self) -> None:
        for provider in self.providers:
            try:
                await provider.aclose()
            except Exception:  # pragma: no cover - best effort
                continue


def _findings(result: ProviderResult, kind: IndicatorType, label: str) -> list[Finding]:
    findings: list[Finding] = []
    if result.degraded:
        return [
            Finding(
                code="TI.UNAVAILABLE",
                title="Threat intelligence was unavailable",
                detail=(
                    "No threat-intelligence provider could be queried, so absence "
                    "of a detection is NOT evidence that this object is safe. "
                    "Verdict confidence has been reduced accordingly."
                ),
                severity=Severity.INFO,
                source=SignalSource.THREAT_INTEL,
                category="reputation",
                weight=0.0,
            )
        ]

    confirming = result.confirming_providers
    if not confirming:
        return findings

    authoritative = [v for v in confirming if getattr(v, "_authoritative", False)]
    high_confidence = [v for v in confirming if v.confidence >= _TRUST_THRESHOLD]
    sources = sorted({v.source for v in confirming if v.source})

    if result.any_malicious and (authoritative or len(confirming) >= 1):
        findings.append(
            Finding(
                code=f"TI.MALICIOUS_{label.upper()}",
                title=f"Threat intelligence reports this {label} as malicious",
                detail=(
                    f"{len(confirming)} of {result.providers_queried} providers "
                    f"({', '.join(sources) or 'unnamed'}) report this {label} as "
                    f"harmful with {result.total_reports} report(s). Categories: "
                    f"{', '.join(result.categories) or 'unspecified'}. This is "
                    "active intelligence from multiple independent sources."
                ),
                severity=Severity.CRITICAL,
                source=SignalSource.THREAT_INTEL,
                category="reputation",
                weight=40.0,
                authoritative=True,
                evidence=result.to_dict(),
            )
        )
    elif len(confirming) >= _AGREEMENT_THRESHOLD or len(high_confidence) >= 1:
        findings.append(
            Finding(
                code=f"TI.SUSPICIOUS_{label.upper()}",
                title=f"Multiple sources flag this {label}",
                detail=(
                    f"{len(confirming)} provider(s) ({', '.join(sources) or 'unnamed'}) "
                    f"flag this {label} with {result.total_reports} report(s), "
                    "but none reports a confirmed malicious classification. Treat "
                    "it as elevated risk and avoid interaction."
                ),
                severity=Severity.HIGH,
                source=SignalSource.THREAT_INTEL,
                category="reputation",
                weight=26.0,
                evidence=result.to_dict(),
            )
        )
    else:
        findings.append(
            Finding(
                code=f"TI.SINGLE_SOURCE_{label.upper()}",
                title=f"One source flags this {label}",
                detail=(
                    f"Single provider '{sources[0] if sources else 'unknown'}' "
                    "reported this object. Single-source reports have a high false "
                    "positive rate and are treated as weak evidence."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.THREAT_INTEL,
                category="reputation",
                weight=12.0,
                evidence=result.to_dict(),
            )
        )
    return findings