"""Google Safe Browsing provider.

Safe Browsing is the most reliable *consumer* phishing signal available: the
lists cover credential-harvesting and malware pages across multiple browsers and
apps. Its list types are not interchangeable, so they are queried separately and
each is reported:

* ``MALWARE``: malware distribution.
* ``SOCIAL_ENGINEERING``: credential harvesting and deceptive pages.
* ``UNWANTED_SOFTWARE``: bundled unwanted programs.
* ``PHISHING``: the classic phishing list.

A URL matching a list is ``MALICIOUS``. A URL on no list is ``CLEAN`` **only**
because Safe Browsing has not seen it - the API returns no match rather than an
explicit "safe" verdict, so the distinction is recorded in the result metadata
and the risk engine does not treat it as positive proof of legitimacy.
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

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

#: Ordered so the most severe list is reported first when several match.
THREAT_TYPES: dict[str, str] = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "social_engineering",
    "PHISHING": "phishing",
    "UNWANTED_SOFTWARE": "unwanted_software",
}


class GoogleSafeBrowsingProvider(IntelProvider):
    """Check a URL against the Safe Browsing threat lists."""

    name = "google_safebrowsing"
    supported_types = frozenset({IndicatorType.URL})
    transmits_indicator = True
    rate_limit_seconds = 0.3

    def is_configured(self) -> bool:
        return bool(get_settings().google_safebrowsing_api_key)

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType, *, consent: bool = True
    ) -> IntelResult:
        url = indicator.strip()
        if not url:
            return self._result(indicator, indicator_type, IntelVerdict.UNKNOWN, error="empty URL")

        body = {
            "client": {
                "clientId": "cybershield",
                "clientVersion": get_settings().app_version,
            },
            "threatInfo": {
                "threatTypes": list(THREAT_TYPES),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        started = time.perf_counter()
        payload = await self._post_json(
            API_URL,
            json=body,
            params={"key": get_settings().google_safebrowsing_api_key or ""},
        )
        latency = int((time.perf_counter() - started) * 1000)

        matches = payload.get("matches") or []
        if not matches:
            return self._result(
                indicator,
                indicator_type,
                IntelVerdict.CLEAN,
                latency_ms=latency,
                source_name="Google Safe Browsing",
                reference_url="https://transparencyreport.google.com/safe-browsing/search",
                metadata={
                    "note": (
                        "Not present on any Safe Browsing threat list. Safe Browsing "
                        "only lists confirmed abuse, so absence of a listing is not a "
                        "guarantee of safety."
                    )
                },
            )

        matched_types: list[str] = []
        cache_state: str | None = None
        for match in matches:
            threat = match.get("threatType") or ""
            if threat:
                matched_types.append(THREAT_TYPES.get(threat, threat.lower()))
            cache_state = match.get("cacheState") or cache_state

        # SOCIAL_ENGINEERING and PHISHING are credential-theft oriented; both are
        # treated as malicious. Anything else is suspicious.
        severe = bool({"malware", "social_engineering", "phishing"} & set(matched_types))

        return self._result(
            indicator,
            indicator_type,
            IntelVerdict.MALICIOUS if severe else IntelVerdict.SUSPICIOUS,
            latency_ms=latency,
            detections=len(matches),
            total_engines=len(THREAT_TYPES),
            confidence=0.93 if severe else 0.7,
            categories=sorted(set(matched_types)),
            threat_type=",".join(sorted(set(matched_types))) or None,
            source_name="Google Safe Browsing",
            reference_url="https://transparencyreport.google.com/safe-browsing/search",
            tags=[t for t in (threat for threat in map(_raw_type, matches)) if t],
            metadata={
                "cache_state": cache_state,
                "raw_threat_types": [str(m.get("threatType")) for m in matches],
                "platform_types": [str(m.get("platformType")) for m in matches],
            },
        )


def _raw_type(match: dict[str, Any]) -> str:
    return str(match.get("threatType") or "")


__all__ = ["GoogleSafeBrowsingProvider"]