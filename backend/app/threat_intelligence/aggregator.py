"""Fan-out across providers, consensus computation and caching.

Why parallel
------------
Provider latency dominates a scan. With four providers at a few seconds each,
sequential lookups would make every request take the sum. They run concurrently
with a per-provider timeout, and a slow provider degrades one data point rather
than the whole scan.

Consensus
---------
The aggregator does **not** average provider verdicts. They are not measuring
the same thing: Safe Browsing lists confirmed abuse, AbuseIPDB scores historical
reports, VirusTotal aggregates ~70 engines. Averaging would let a long,
reputation-only history cancel out a single authoritative malware listing.
Instead:

* any ``MALICIOUS`` answer wins;
* any ``SUSPICIOUS`` answer is next;
* ``clean`` only means clean when every provider that answered said clean and
  none errored.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Final

from app.core.config import get_settings
from app.schemas.common import IndicatorType
from app.schemas.intel import IntelResult, IntelSummary, IntelVerdict
from app.threat_intelligence.base import IntelProvider
from app.threat_intelligence.providers.abuseipdb import AbuseIPDBProvider
from app.threat_intelligence.providers.google_safebrowsing import (
    GoogleSafeBrowsingProvider,
)
from app.threat_intelligence.providers.urlhaus import URLhausProvider
from app.threat_intelligence.providers.virustotal import VirusTotalProvider

logger = logging.getLogger(__name__)

#: Negative results are cached for less time than positive ones: a file that has
#: just been submitted elsewhere should start being reported quickly, while a
#: clean file staying clean costs nothing to re-check occasionally.
POSITIVE_TTL_SECONDS: Final[int] = 900
NEGATIVE_TTL_SECONDS: Final[int] = 300
UNKNOWN_TTL_SECONDS: Final[int] = 120


def cache_key(provider: str, indicator_type: IndicatorType, indicator: str) -> str:
    """Stable cache key for one lookup."""
    digest = hashlib.sha256(f"{indicator_type.value}:{indicator}".encode()).hexdigest()
    return f"{provider}:{indicator_type.value}:{digest[:32]}"


class InMemoryCache:
    """Process-local TTL cache used when no database is configured.

    Deliberately bounded so a long-running process cannot accumulate unbounded
    keys from attacker-controlled indicators.
    """

    def __init__(self, max_entries: int = 10_000) -> None:
        self._entries: dict[str, tuple[IntelResult, datetime]] = {}
        self._max = max_entries

    def get(self, key: str) -> IntelResult | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        result, expires = entry
        if expires <= datetime.now(timezone.utc):
            self._entries.pop(key, None)
            return None
        return result.model_copy(update={"from_cache": True})

    def set(self, key: str, result: IntelResult, ttl: int) -> None:
        if len(self._entries) >= self._max:
            self._evict_expired()
        if len(self._entries) >= self._max:
            # Drop the oldest quarter rather than refusing new entries; a stale
            # entry is far better than a permanently empty cache.
            ordered = sorted(self._entries.items(), key=lambda kv: kv[1][1])
            for stale_key, _ in ordered[: max(1, len(ordered) // 4)]:
                self._entries.pop(stale_key, None)
        self._entries[key] = (result, datetime.now(timezone.utc) + timedelta(seconds=ttl))

    def _evict_expired(self) -> None:
        now = datetime.now(timezone.utc)
        self._entries = {k: v for k, v in self._entries.items() if v[1] > now}

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


class ThreatIntelligenceService:
    """Queries every applicable provider and produces one summary."""

    def __init__(self, providers: list[IntelProvider] | None = None) -> None:
        settings = get_settings()
        self._settings = settings
        self._timeout = settings.threat_intel_timeout_seconds
        self._providers: list[IntelProvider] = providers or self._default_providers()
        self._cache = InMemoryCache()

    @staticmethod
    def _default_providers() -> list[IntelProvider]:
        return [
            VirusTotalProvider(),
            URLhausProvider(),
            GoogleSafeBrowsingProvider(),
            AbuseIPDBProvider(),
        ]

    @property
    def providers(self) -> list[IntelProvider]:
        return list(self._providers)

    def providers_for(self, indicator_type: IndicatorType) -> list[IntelProvider]:
        """Configured providers that support this indicator type."""
        return [
            provider
            for provider in self._providers
            if indicator_type in provider.supported_types and provider.is_configured()
        ]

    async def lookup_all(
        self,
        indicator: str,
        indicator_type: IndicatorType,
        *,
        consent: bool = True,
        use_cache: bool = True,
    ) -> IntelSummary:
        """Query all applicable providers concurrently and summarise."""
        candidates = self.providers_for(indicator_type)
        if not candidates:
            return IntelSummary(
                results=[],
                providers_queried=0,
                providers_failed=0,
                any_positive=False,
                all_clean=False,
                consensus="unknown",
                scanned_at=datetime.now(timezone.utc),
            )

        tasks = [
            asyncio.create_task(
                self._lookup_one(provider, indicator, indicator_type, consent, use_cache),
                name=f"intel:{provider.name}",
            )
            for provider in candidates
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        collected: list[IntelResult] = []
        for provider, outcome in zip(candidates, results, strict=True):
            if isinstance(outcome, BaseException):
                # safe_lookup already catches provider bugs; this is the last
                # line of defence for a cancellation or a bug in the wrapper.
                collected.append(
                    IntelResult(
                        provider=provider.name,
                        indicator=indicator,
                        indicator_type=indicator_type,
                        verdict=IntelVerdict.ERROR,
                        error=f"provider raised {type(outcome).__name__}",
                    )
                )
                continue
            collected.append(outcome)

        return self.summarise(collected)

    async def _lookup_one(
        self,
        provider: IntelProvider,
        indicator: str,
        indicator_type: IndicatorType,
        consent: bool,
        use_cache: bool,
    ) -> IntelResult:
        """Look up one provider, with a timeout and an optional cache."""
        key = cache_key(provider.name, indicator_type, indicator)
        if use_cache:
            cached = self._cache.get(key)
            if cached is not None:
                return cached

        try:
            result = await asyncio.wait_for(
                provider.safe_lookup(indicator, indicator_type, consent=consent),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            result = IntelResult(
                provider=provider.name,
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=IntelVerdict.ERROR,
                error=f"provider did not respond within {self._timeout:.0f}s",
            )

        if use_cache and result.verdict in (IntelVerdict.MALICIOUS, IntelVerdict.SUSPICIOUS):
            self._cache.set(key, result, POSITIVE_TTL_SECONDS)
        elif use_cache and result.verdict is IntelVerdict.CLEAN:
            self._cache.set(key, result, NEGATIVE_TTL_SECONDS)
        elif use_cache and result.verdict is IntelVerdict.UNKNOWN:
            self._cache.set(key, result, UNKNOWN_TTL_SECONDS)

        return result

    # ------------------------------------------------------------------
    # Consensus
    # ------------------------------------------------------------------
    @staticmethod
    def summarise(results: list[IntelResult]) -> IntelSummary:
        """Compute the consensus across provider results."""
        answered = [r for r in results if r.verdict not in (IntelVerdict.UNKNOWN, IntelVerdict.ERROR)]
        failed = [r for r in results if r.verdict in (IntelVerdict.UNKNOWN, IntelVerdict.ERROR)]

        verdicts = {r.verdict for r in answered}
        if IntelVerdict.MALICIOUS in verdicts:
            consensus = "malicious"
        elif IntelVerdict.SUSPICIOUS in verdicts:
            consensus = "suspicious"
        elif verdicts == {IntelVerdict.CLEAN}:
            consensus = "clean"
        elif verdicts:
            consensus = "mixed"
        else:
            consensus = "unknown"

        return IntelSummary(
            results=results,
            providers_queried=len(answered),
            providers_failed=len(failed),
            any_positive=any(r.is_positive for r in results),
            # "All clean" requires that nothing failed: a provider that never
            # answered cannot be counted as agreeing.
            all_clean=bool(answered) and not failed and verdicts == {IntelVerdict.CLEAN},
            consensus=consensus,
            scanned_at=datetime.now(timezone.utc),
        )

    def summary_as_metadata(self, summary: IntelSummary) -> dict[str, Any]:
        """Serialise a summary for storage in a scan's metadata column."""
        return {
            "consensus": summary.consensus,
            "any_positive": summary.any_positive,
            "all_clean": summary.all_clean,
            "providers_queried": summary.providers_queried,
            "providers_failed": summary.providers_failed,
            "results": [result.model_dump(mode="json") for result in summary.results],
        }

    async def close(self) -> None:
        for provider in self._providers:
            await provider.close()
        self._cache.clear()


_service: ThreatIntelligenceService | None = None


def get_threat_intel_service() -> ThreatIntelligenceService:
    """Return the process-wide threat-intelligence service."""
    global _service
    if _service is None:
        _service = ThreatIntelligenceService()
    return _service


def set_threat_intel_service(service: ThreatIntelligenceService | None) -> None:
    """Replace the service, for tests."""
    global _service
    _service = service


__all__ = [
    "NEGATIVE_TTL_SECONDS",
    "POSITIVE_TTL_SECONDS",
    "InMemoryCache",
    "ThreatIntelligenceService",
    "cache_key",
    "get_threat_intel_service",
    "set_threat_intel_service",
]