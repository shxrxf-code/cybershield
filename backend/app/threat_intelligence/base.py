"""Threat-intelligence provider interface.

A provider answers one narrow question: *what is known about this indicator?*
Everything else - scoring, verdict, recommendation - belongs to the risk engine.

Contract
--------
* :meth:`lookup` **never raises** for a provider failure. It returns an
  :class:`~app.schemas.intel.IntelResult` with ``verdict=UNKNOWN`` and ``error``
  set. A provider being down must degrade a report's confidence, not turn a scan
  into a 500 or, worse, into a clean result.
* A provider never sends anything the user did not consent to submitting. The
  ``consent`` flag is passed in and providers that would transmit an indicator
  return ``UNKNOWN`` when it is absent.
* API keys are read from settings and never returned in a result. If a provider
  echoes a key back in an error body, that is stripped before it reaches
  :class:`IntelResult`.
* Results are attributable: ``provider`` is always populated, so a report can say
  which service answered.
"""

from __future__ import annotations

import abc
import logging
import re
from typing import Any, Final

import httpx

from app.core.config import get_settings
from app.schemas.common import IndicatorType
from app.schemas.intel import IntelResult, IntelVerdict

logger = logging.getLogger(__name__)

#: Matches anything that looks like an API token, used to scrub provider errors
#: before they are stored in a report.
_SECRET_RE = re.compile(
    r"(?i)\b(?:key|token|secret|apikey|x-api-key|authorization)\b\s*[=:]\s*['\"]?[\w\-]{8,}"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[\w\-\.]{8,}")

#: Read timeout and total timeout are separate because a slow provider should
#: consume the *total* budget, not refresh it on every chunk.
CONNECT_TIMEOUT: Final[float] = 3.0
READ_TIMEOUT: Final[float] = 8.0


def scrub_secrets(text: str | None) -> str | None:
    """Remove anything key-shaped from text destined for a client response.

    >>> scrub_secrets("error: apikey=abcdef123456789 rejected")
    'error: key=[redacted] rejected'
    """
    if not text:
        return text
    cleaned = _SECRET_RE.sub("key=[redacted]", text)
    cleaned = _BEARER_RE.sub("Bearer [redacted]", cleaned)
    return cleaned[:500]


class ProviderNotConfigured(Exception):
    """Raised internally when a provider has no usable credential."""


class IntelProvider(abc.ABC):
    """Base class for reputation services."""

    #: Stable identifier used in configuration, caching and reports.
    name: str = "provider"
    #: Indicator types this provider can answer for.
    supported_types: frozenset[IndicatorType] = frozenset()
    #: Whether the provider transmits the indicator to a third party, which is
    #: what makes user consent mandatory for it.
    transmits_indicator: bool = True
    #: Minimum seconds between two calls, enforced per process.
    rate_limit_seconds: float = 0.2

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._owns_client = client is None
        self._last_call = 0.0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    @property
    def client(self) -> httpx.AsyncClient:
        """Lazily build a shared HTTP client."""
        if self._client is None:
            settings = get_settings()
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(
                    READ_TIMEOUT,
                    connect=CONNECT_TIMEOUT,
                    read=READ_TIMEOUT,
                    write=READ_TIMEOUT,
                ),
                follow_redirects=False,
                headers={"User-Agent": "CyberShield-ThreatIntel/1.0"},
            )
        return self._client

    def is_configured(self) -> bool:
        """Whether this provider has everything it needs to answer."""
        return True

    async def is_available(self) -> bool:
        """Whether the provider is configured *and* reachable."""
        return self.is_configured()

    async def close(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------
    @abc.abstractmethod
    async def lookup(
        self, indicator: str, indicator_type: IndicatorType, *, consent: bool = True
    ) -> IntelResult:
        """Query the provider. Must not raise."""

    async def safe_lookup(
        self, indicator: str, indicator_type: IndicatorType, *, consent: bool = True
    ) -> IntelResult:
        """Wrap :meth:`lookup` so any provider bug becomes an ``UNKNOWN`` result.

        This is the method the aggregator calls. Keeping the guard here means a
        new provider cannot accidentally reintroduce "provider exception crashes
        the scan".
        """
        if indicator_type not in self.supported_types:
            return self._result(
                indicator, indicator_type, IntelVerdict.UNKNOWN, error="unsupported indicator type"
            )
        if not self.is_configured():
            return self._result(
                indicator,
                indicator_type,
                IntelVerdict.UNKNOWN,
                error="provider is not configured",
            )
        if not consent and self.transmits_indicator:
            # Reporting "clean" here would be a lie: the question was never asked.
            return self._result(
                indicator,
                indicator_type,
                IntelVerdict.UNKNOWN,
                error="user declined third-party submission for this indicator",
            )

        import time

        wait = self.rate_limit_seconds - (time.monotonic() - self._last_call)
        if wait > 0:
            import asyncio

            await asyncio.sleep(wait)
        self._last_call = time.monotonic()

        try:
            return await self.lookup(indicator, indicator_type, consent=consent)
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all
            logger.warning(
                "threat_intel_provider_failed",
                extra={"provider": self.name, "error_type": type(exc).__name__},
                exc_info=True,
            )
            return self._result(
                indicator,
                indicator_type,
                IntelVerdict.ERROR,
                error=scrub_secrets(str(exc)) or "provider request failed",
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _result(
        self,
        indicator: str,
        indicator_type: IndicatorType,
        verdict: IntelVerdict,
        *,
        latency_ms: int | None = None,
        error: str | None = None,
        **kwargs: Any,
    ) -> IntelResult:
        return IntelResult(
            provider=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            latency_ms=latency_ms,
            error=error,
            **kwargs,
        )

    async def _get_json(self, url: str, **kwargs: Any) -> dict[str, Any]:
        """GET and parse JSON, raising for non-2xx."""
        response = await self.client.get(url, **kwargs)
        response.raise_for_status()
        return response.json()

    async def _post_json(self, url: str, **kwargs: Any) -> dict[str, Any]:
        response = await self.client.post(url, **kwargs)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def normalise_hash(value: str) -> str:
        return value.strip().lower()

    @staticmethod
    def normalise_host(value: str) -> str:
        """Lowercase a hostname and strip a trailing dot."""
        host = value.strip().lower().rstrip(".")
        if host.startswith("www."):
            host = host[4:]
        return host


__all__ = [
    "CONNECT_TIMEOUT",
    "READ_TIMEOUT",
    "IntelProvider",
    "ProviderNotConfigured",
    "scrub_secrets",
]