"""VirusTotal v3 provider.

Covers URLs, domains, file hashes and IP addresses. Free-tier limits are
generous in request count but strict about sustained throughput, so the provider
enforces a minimum interval between calls and the aggregator caches results.

API-key handling
----------------
The key is read from settings and sent as a header. It never appears in a
:class:`IntelResult`, and provider error bodies are scrubbed by
:func:`app.threat_intelligence.base.scrub_secrets` before being surfaced.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from app.core.config import get_settings
from app.schemas.common import IndicatorType
from app.schemas.intel import IntelResult, IntelVerdict
from app.threat_intelligence.base import IntelProvider

logger = logging.getLogger(__name__)

API_BASE = "https://www.virustotal.com/api/v3"

#: Endpoint per indicator type. Hash endpoints are content-addressed, so a hash
#: lookup reveals nothing new to VirusTotal - it cannot leak browsing history the
#: way a URL submission does.
_ENDPOINTS: dict[IndicatorType, str] = {
    IndicatorType.URL: "/urls/{value}",
    IndicatorType.DOMAIN: "/domains/{value}",
    IndicatorType.IP_ADDRESS: "/ip_addresses/{value}",
    IndicatorType.HASH_MD5: "/files/{value}",
    IndicatorType.HASH_SHA1: "/files/{value}",
    IndicatorType.HASH_SHA256: "/files/{value}",
}

#: A lookup that VirusTotal has never seen is ``NotFoundError``, not a clean
#: verdict. Reporting "clean" for an unknown file would be actively misleading.
#: The threshold below is the fraction of engines that must agree before a
#: result is called malicious rather than suspicious.
_MALICIOUS_RATIO = 0.5
_SUSPICIOUS_RATIO = 0.1

_HASH_TYPES = frozenset(
    {IndicatorType.HASH_MD5, IndicatorType.HASH_SHA1, IndicatorType.HASH_SHA256}
)


class VirusTotalProvider(IntelProvider):
    """Look up indicators against the VirusTotal v3 API."""

    name = "virustotal"
    supported_types = frozenset(_ENDPOINTS)
    transmits_indicator = True
    rate_limit_seconds = 0.25

    def __init__(self, client: Any | None = None) -> None:
        super().__init__(client)
        self._api_key = get_settings().virustotal_api_key

    def is_configured(self) -> bool:
        settings = get_settings()
        return bool(self._api_key) and settings.virustotal_enabled

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self._api_key or "", "accept": "application/json"}

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType, *, consent: bool = True
    ) -> IntelResult:
        settings = get_settings()
        if not settings.virustotal_enabled:
            return self._result(
                indicator, indicator_type, IntelVerdict.UNKNOWN, error="VirusTotal is disabled."
            )

        value = self.normalise_hash(indicator) if indicator_type in _HASH_TYPES else indicator.strip()
        if not value:
            return self._result(indicator, indicator_type, IntelVerdict.UNKNOWN, error="empty indicator")

        endpoint = _ENDPOINTS[indicator_type]
        url = f"{API_BASE}{endpoint.format(value=_quote(value))}"

        started = time.perf_counter()
        try:
            payload = await self._get_json(url, headers=self._headers())
        except Exception as exc:  # noqa: BLE001 - handled by safe_lookup too
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status == 404:
                return self._result(
                    indicator,
                    indicator_type,
                    IntelVerdict.UNKNOWN,
                    latency_ms=int((time.perf_counter() - started) * 1000),
                    error="VirusTotal has never seen this indicator.",
                )
            raise

        latency = int((time.perf_counter() - started) * 1000)
        return self._interpret(payload, indicator, indicator_type, latency)

    def _interpret(
        self,
        payload: dict[str, Any],
        indicator: str,
        indicator_type: IndicatorType,
        latency: int,
    ) -> IntelResult:
        """Map a VirusTotal v3 response onto an :class:`IntelResult`."""
        data = payload.get("data") or {}
        attributes = data.get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        total = malicious + suspicious + harmless + undetected
        # "timeout" engines failed to return a verdict; excluding them keeps the
        # ratio honest rather than inflating confidence.
        timed_out = int(stats.get("timeout") or 0)
        considered = max(1, total)

        detections = malicious + suspicious
        ratio = detections / considered

        if malicious == 0 and detections == 0:
            verdict = IntelVerdict.CLEAN if total > 0 else IntelVerdict.UNKNOWN
        elif ratio >= _MALICIOUS_RATIO or malicious >= 3:
            verdict = IntelVerdict.MALICIOUS
        elif ratio >= _SUSPICIOUS_RATIO or suspicious > 0:
            verdict = IntelVerdict.SUSPICIOUS
        else:
            verdict = IntelVerdict.CLEAN

        if verdict is IntelVerdict.CLEAN and total == 0:
            verdict = IntelVerdict.UNKNOWN

        tags = [str(tag) for tag in attributes.get("tags") or []]
        families = [
            str(item.get("description"))
            for item in (attributes.get("last_analysis_results") or {}).values()
            if isinstance(item, dict) and item.get("category") == "undetected"
            and item.get("result")
        ]

        votes = attributes.get("total_votes") or {}

        return self._result(
            indicator,
            indicator_type,
            verdict,
            latency_ms=latency,
            detections=detections,
            total_engines=considered,
            confidence=round(ratio, 3),
            categories=tags,
            source_name=attributes.get("meaningful_name"),
            reference_url=attributes.get("permalink"),
            malware_families=families[:10],
            first_seen=_parse_timestamp(attributes.get("first_submission_date")),
            last_seen=_parse_timestamp(attributes.get("last_submission_date")),
            tags=tags,
            metadata={
                "reputation": attributes.get("reputation"),
                "times_submitted": attributes.get("times_submitted"),
                "community_votes": {
                    "harmless": votes.get("harmless"),
                    "malicious": votes.get("malicious"),
                },
                "timeout_engines": timed_out,
                "names": [str(name) for name in (attributes.get("names") or [])][:5],
            },
        )


def _quote(value: str) -> str:
    """Percent-encode a path component."""
    from urllib.parse import quote

    return quote(value, safe="")


def _parse_timestamp(value: Any) -> Any:
    """Convert a VirusTotal epoch value into an aware datetime."""
    if not value:
        return None
    from datetime import datetime, timezone

    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


__all__ = ["VirusTotalProvider"]