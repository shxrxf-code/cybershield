"""AbuseIPDB provider - IP address reputation.

Only meaningful for IP-literal URLs and for the address a domain resolves to.
A high abuse-confidence score says the *address* has a history of abuse, which is
a risk factor rather than proof of a current threat, so results are capped at
``SUSPICIOUS`` unless the score is extreme.

Reporting an IP to AbuseIPDB counts as third-party submission, so it respects
the user's consent flag like any other transmitting provider.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any

from app.core.config import get_settings
from app.schemas.common import IndicatorType
from app.schemas.intel import IntelResult, IntelVerdict
from app.threat_intelligence.base import IntelProvider

logger = logging.getLogger(__name__)

API_BASE = "https://api.abuseipdb.com/api/v2/check"

#: abuse-confidence is 0-100. Anything at or above this is treated as a
#: deliberate abuse source rather than incidental.
MALICIOUS_THRESHOLD = 90
SUSPICIOUS_THRESHOLD = 60


class AbuseIPDBProvider(IntelProvider):
    """Query AbuseIPDB for an address's abuse history."""

    name = "abuseipdb"
    supported_types = frozenset({IndicatorType.IP_ADDRESS})
    transmits_indicator = True
    rate_limit_seconds = 1.0

    def is_configured(self) -> bool:
        return bool(get_settings().abuseipdb_api_key)

    def _headers(self) -> dict[str, str]:
        return {
            "Key": get_settings().abuseipdb_api_key or "",
            "accept": "application/json",
        }

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType, *, consent: bool = True
    ) -> IntelResult:
        address = indicator.strip()
        # Reject anything that is not an IP address. Sending a hostname here
        # would leak it to the provider for no benefit.
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return self._result(
                indicator, indicator_type, IntelVerdict.UNKNOWN, error="not an IP address"
            )
        address = parsed.compressed

        started = time.perf_counter()
        payload = await self._get_json(
            API_BASE,
            params={"ipAddress": address, "maxAgeInDays": 90},
            headers=self._headers(),
        )
        latency = int((time.perf_counter() - started) * 1000)

        data = payload.get("data") or {}
        score = int(data.get("abuseConfidenceScore") or 0)
        total_reports = int(data.get("totalReports") or 0)

        if score >= MALICIOUS_THRESHOLD:
            verdict = IntelVerdict.MALICIOUS
            confidence = min(0.9, 0.5 + score / 200)
        elif score >= SUSPICIOUS_THRESHOLD:
            verdict = IntelVerdict.SUSPICIOUS
            confidence = 0.45
        elif total_reports == 0:
            # No reports at all is a genuinely clean answer from this source.
            verdict = IntelVerdict.CLEAN
            confidence = 0.3
        else:
            verdict = IntelVerdict.SUSPICIOUS
            confidence = 0.3

        reports = data.get("reports") or []
        categories = sorted({str(r.get("abuseConfidenceCategory") or "") for r in reports if r.get("category")})

        return self._result(
            indicator,
            indicator_type,
            verdict,
            latency_ms=latency,
            detections=total_reports,
            total_engines=None,
            confidence=confidence,
            categories=[c for c in categories if c],
            source_name=str(data.get("isp") or "") or None,
            reference_url=(
                f"https://www.abuseipdb.com/check/{address}" if total_reports else None
            ),
            tags=[str(data.get("domain") or "")] if data.get("domain") else [],
            last_seen=_parse_timestamp(data.get("lastReportedAt")),
            metadata={
                "abuse_confidence_score": score,
                "total_reports": total_reports,
                "num_distinct_users": data.get("numDistinctUsers"),
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "is_whitelisted": data.get("isWhitelisted"),
                "report_categories": [
                    {
                        "category": r.get("category"),
                        "reporter_country": r.get("reporterCountryCode"),
                    }
                    for r in reports[:5]
                ],
            },
        )


def _parse_timestamp(value: Any) -> Any:
    if not value:
        return None
    from datetime import datetime, timezone

    try:
        cleaned = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(cleaned)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


__all__ = ["AbuseIPDBProvider"]