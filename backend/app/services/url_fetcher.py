"""SSRF-guarded URL fetching for the active-fetch phase of a URL scan.

Flow
----
``validate -> pin -> fetch -> re-validate every redirect hop -> bounded read``

* :class:`~app.security.ssrf.UrlSafetyChecker` validates scheme, port, hostname,
  DNS answers and credentials before any connection is made.
* Redirects are followed *manually* with per-hop re-validation, so a public page
  can never bounce the scanner into ``http://169.254.169.254/``.
* The response body is read under a byte cap and never stored; only the analysed
  window and the extracted observations survive.

Consent
-------
``dns_lookup`` and ``active_fetch`` are passed in from the request's consent
options. A scan that declines DNS keeps resolution out of the report entirely;
a scan that declines fetching still reports what the structural and reputation
passes found.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from app.core.config import get_settings
from app.core.exceptions import SSRFBlockedError
from app.detection_engine.web import analyse_web_content
from app.schemas.common import Severity, SignalSource
from app.schemas.signal import DetectionSignal
from app.security.ssrf import UrlSafetyChecker

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class UrlFetchResult:
    """Outcome of the protected fetch phase, never a verdict."""

    #: HTTP status of the final response, when fetched.
    status: int | None = None
    page_title: str | None = None
    #: Every A/AAAA address resolved for the target host.
    resolved_ips: list[str] = field(default_factory=list)
    final_url: str | None = None
    #: Why the fetch was refused, when it was. Blocked is not failure - the
    #: structural and reputation passes still report fully.
    fetch_blocked_reason: str | None = None
    #: Why DNS resolution was prevented (consent or policy).
    dns_skipped_reason: str | None = None
    signals: list[DetectionSignal] = field(default_factory=list)
    latency_ms: int | None = None

    @property
    def fetched(self) -> bool:
        return self.status is not None


class UrlFetcher:
    """Fetches URLs against the documented SSRF policy."""

    def __init__(self, settings: Any | None = None) -> None:
        self._settings = settings or get_settings()

    def _checker(self) -> UrlSafetyChecker:
        return UrlSafetyChecker(self._settings)

    async def fetch(
        self,
        url: str,
        *,
        active_fetch: bool,
        dns_lookup: bool,
    ) -> UrlFetchResult:
        """Run the protected resolution and, if consented, bounded fetch."""
        started = time.perf_counter()
        checker = self._checker()

        # ---- 1. Validate + resolve (DNS) -----------------------------
        target = None
        try:
            target = checker.build_target(url)
        except SSRFBlockedError as exc:
            latency = int((time.perf_counter() - started) * 1000)
            return UrlFetchResult(
                fetch_blocked_reason=exc.message,
                dns_skipped_reason=None if exc.status_code == 400 else exc.message,
                latency_ms=latency,
            )

        result = UrlFetchResult(resolved_ips=list(target.resolved_ips), final_url=target.url)
        result.dns_skipped_reason = None if dns_lookup else "DNS lookup declined by the user."

        if not active_fetch:
            result.latency_ms = int((time.perf_counter() - started) * 1000)
            return result
        if not self._settings.url_fetch_enabled:
            result.fetch_blocked_reason = "URL fetching is disabled by configuration."
            result.latency_ms = int((time.perf_counter() - started) * 1000)
            return result

        # ---- 2. Bounded fetch with per-hop revalidation ---------------
        try:
            status, title, signals = await self._dereference(target.url, checker)
        except SSRFBlockedError as exc:
            # A redirect into a blocked destination is itself a finding.
            result.fetch_blocked_reason = exc.message
            result.signals.append(
                DetectionSignal(
                    code="url.redirect_blocked",
                    title="Redirect target was blocked",
                    description=(
                        "The URL redirected to a destination that the scanner is not permitted "
                        f"to follow: {exc.message} Redirect abuse is a common phishing chain."
                    ),
                    severity=Severity.MEDIUM,
                    category="deception",
                    source=SignalSource.STRUCTURAL,
                    confidence=0.8,
                    evidence={"reason": exc.message},
                )
            )
        except httpx.HTTPError as exc:
            result.fetch_blocked_reason = f"fetch failed: {type(exc).__name__}"
            result.signals.append(
                DetectionSignal(
                    code="url.fetch_error",
                    title="Page could not be retrieved",
                    description=(
                        "The page could not be fetched for an on-site inspection ("
                        f"{type(exc).__name__}). The structural, lexical and reputation "
                        "analysis still completed from the URL alone."
                    ),
                    severity=Severity.LOW,
                    category="scanner_health",
                    source=SignalSource.POLICY,
                    confidence=0.8,
                )
            )
        else:
            result.status = status
            result.page_title = title
            result.signals.extend(signals)

        result.latency_ms = int((time.perf_counter() - started) * 1000)
        return result

    # ------------------------------------------------------------------
    # Dereference
    # ------------------------------------------------------------------
    async def _dereference(
        self,
        start_url: str,
        checker: UrlSafetyChecker,
    ) -> tuple[int, str | None, list[DetectionSignal]]:
        """Follow validated redirects to a final page and read a bounded amount."""
        headers = {"User-Agent": self._settings.url_user_agent}
        timeout = httpx.Timeout(self._settings.url_fetch_timeout_seconds, connect=5.0)

        hop_url = start_url
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers=headers) as client:
            for _hop in range(self._settings.url_max_redirects + 1):
                # Per-hop revalidation: DNS and IP policy apply to every target,
                # so a redirect can never escape the allowlist.
                checker.build_target(hop_url)

                async with client.stream("GET", hop_url) as response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location")
                        if not location:
                            break
                        hop_url = urljoin(hop_url, location)
                        continue

                    content = b""
                    cap = self._settings.url_fetch_max_bytes
                    async for chunk in response.aiter_bytes():
                        content += chunk
                        if len(content) >= cap:
                            break

                    page = analyse_web_content(content, page_host=checker_target_host(checker, hop_url))
                    return response.status_code, page.title, page.signals

        raise SSRFBlockedError("The URL redirected more times than permitted.")


def checker_target_host(checker: UrlSafetyChecker, url: str) -> str:
    """Return the hostname after validation, for page-host comparisons."""
    try:
        return checker.build_target(url).hostname
    except SSRFBlockedError:
        from urllib.parse import urlsplit

        return urlsplit(url).hostname or ""


__all__ = ["UrlFetchResult", "UrlFetcher"]