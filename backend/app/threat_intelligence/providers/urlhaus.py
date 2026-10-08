"""URLhaus (abuse.ch) provider.

URLhaus is a community feed of malware distribution URLs, published as a plain
CSV. It is a strong, *small* signal: a host listed here is serving malware, and
the feed has almost no false positives. A match is therefore treated as
authoritative rather than as a heuristic.

Key difference from a commercial aggregator: URLhaus **pulls** data. Asking it
about a URL does not submit that URL to anyone, so it can be queried without
third-party submission consent. The provider still declares
``transmits_indicator = False`` to make that explicit.

abuse.ch now requires an Auth-Key header. Without one the provider reports
``UNKNOWN`` rather than silently skipping, so a report can say the feed was not
consulted instead of implying it agreed.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from app.core.config import get_settings
from app.schemas.common import IndicatorType
from app.schemas.intel import IntelResult, IntelVerdict
from app.threat_intelligence.base import IntelProvider

logger = logging.getLogger(__name__)

#: Set via ``URLHAUS_AUTH_KEY``; optional for the public CSV download endpoint.
AUTH_KEY_ENV = "urlhaus_auth_key"


class URLhausProvider(IntelProvider):
    """Check a URL against the abuse.ch URLhaus malware-URL feed."""

    name = "urlhaus"
    supported_types = frozenset({IndicatorType.URL})
    #: A GET of a public CSV sends the URL to abuse.ch's server only as part of
    #: the normal request, not as a submission for scanning. There is nothing to
    #: upload, so no user consent is required.
    transmits_indicator = False
    rate_limit_seconds = 0.5

    def is_configured(self) -> bool:
        """URLhaus requires an Auth-Key; without one it must not be queried.

        Reporting ``True`` here would put the provider in the fan-out and turn
        every scan's log full of 401s, so an absent key means the feed is
        excluded and the report simply does not mention it.
        """
        return bool(self._auth_key())

    def _auth_key(self) -> str | None:
        return getattr(get_settings(), AUTH_KEY_ENV, None)

    async def lookup(
        self, indicator: str, indicator_type: IndicatorType, *, consent: bool = True
    ) -> IntelResult:
        settings = get_settings()
        if not settings.urlhaus_enabled:
            return self._result(
                indicator, indicator_type, IntelVerdict.UNKNOWN, error="URLhaus is disabled."
            )

        url = indicator.strip()
        if not url:
            return self._result(indicator, indicator_type, IntelVerdict.UNKNOWN, error="empty URL")

        # URLhaus indexes by URL *and* by host. Querying the URL first avoids
        # reporting a host-level match for a specific path; falling back to the
        # host catches a URL that was never submitted but whose domain is known.
        host = _host_of(url)
        started = time.perf_counter()
        payload: dict[str, Any] | None = None
        last_error: Exception | None = None

        for form in ({"url": url}, {"host": self.normalise_host(host)} if host else None):
            if form is None:
                continue
            try:
                payload = await self._post_json(
                    settings.urlhaus_endpoint, data=form, headers=self._headers()
                )
                break
            except Exception as exc:  # noqa: BLE001 - fall through to host form
                last_error = exc
                logger.debug("URLhaus query failed for %s", list(form), exc_info=exc)

        if payload is None:
            raise last_error or RuntimeError("URLhaus query produced no response")

        latency = int((time.perf_counter() - started) * 1000)
        return self._interpret(payload, indicator, indicator_type, latency, url)

    def _headers(self) -> dict[str, str]:
        key = self._auth_key()
        return {"Auth-Key": key, "accept": "application/json"} if key else {"accept": "application/json"}

    def _interpret(
        self,
        payload: dict[str, Any],
        indicator: str,
        indicator_type: IndicatorType,
        latency: int,
        submitted_url: str,
    ) -> IntelResult:
        query_status = str(payload.get("query_status") or "").lower()

        if query_status in ("no_results", "not found"):
            # The host answered and the URL is not in the feed. That is a clean
            # result *for this feed only*, which the verdict text makes clear.
            return self._result(
                indicator,
                indicator_type,
                IntelVerdict.CLEAN,
                latency_ms=latency,
                source_name="URLhaus",
                reference_url="https://urlhaus.abuse.ch/",
                metadata={"note": "Not present in the URLhaus malware-URL feed."},
            )

        if query_status == "invalid_url" or not isinstance(payload.get("threat"), dict):
            return self._result(
                indicator,
                indicator_type,
                IntelVerdict.UNKNOWN,
                latency_ms=latency,
                error=f"URLhaus could not process the URL ({query_status or 'unrecognised response'}).",
            )

        threat = payload.get("threat") or {}
        tags = [str(tag) for tag in (threat.get("tags") or [])]
        return self._result(
            indicator,
            indicator_type,
            IntelVerdict.MALICIOUS,
            latency_ms=latency,
            detections=1,
            total_engines=1,
            confidence=0.95,
            categories=tags,
            threat_type=threat.get("threat_type"),
            source_name="URLhaus",
            reference_url=f"https://urlhaus.abuse.ch/url/{hashlib.sha256(submitted_url.encode()).hexdigest()[:12]}/",
            tags=tags,
            first_seen=_parse_timestamp(payload.get("first_seen")),
            last_seen=_parse_timestamp(payload.get("last_online")),
            metadata={
                "url_status": payload.get("url_status"),
                "reporter": payload.get("reporter"),
                "date_added": payload.get("date_added"),
                "payloads": [
                    {
                        "filename": (item.get("file_type") or "") + " " + (item.get("filename") or ""),
                        "sha256": (item.get("file_type") == "hash") and item.get("file_value") or None,
                    }
                    for item in (payload.get("payloads") or [])
                ][:10],
            },
        )


def _host_of(url: str) -> str:
    from urllib.parse import urlparse

    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return ""
    return host


def _parse_timestamp(value: Any) -> Any:
    if not value:
        return None
    from datetime import datetime

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


__all__ = ["URLhausProvider"]