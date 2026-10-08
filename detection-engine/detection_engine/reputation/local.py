"""Offline indicator store.

Purpose
-------
* Provide a *usable* threat-intel layer with zero configuration so the product
  works on an air-gapped deployment (and in CI, where live APIs are unavailable).
* Provide a local override/blacklist that operators control themselves - a
  private blocklist for company domains, or a "known bad" list seeded from
  incident response.
* Serve as the fast local tier in front of remote providers.

The store is deliberately simple (JSON on disk, in-memory index).  It is not a
replacement for a real IOC pipeline; it is the safe default.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from .base import IndicatorType, IndicatorVerdict, ProviderStatus, ThreatIntelProvider

__all__ = ["LocalIndicator", "LocalIndicatorStore", "LocalIndicatorProvider"]

#: Verdict strings understood in the indicator file.
_VERDICT_MALICIOUS = {"malicious", "phishing", "malware", "bad", "harmful", "block"}
_VERDICT_SUSPICIOUS = {"suspicious", "phish", "risk", "warn", "warning"}


class LocalIndicator:
    """A single locally-held intelligence record."""

    __slots__ = ("indicator", "kind", "verdict", "categories", "note", "added_at", "source")

    def __init__(
        self,
        indicator: str,
        kind: IndicatorType | str = IndicatorType.URL,
        verdict: str = "malicious",
        categories: list[str] | None = None,
        note: str = "",
        added_at: float | None = None,
        source: str = "local",
    ) -> None:
        self.indicator = indicator.strip().lower()
        self.kind = kind if isinstance(kind, IndicatorType) else IndicatorType(str(kind))
        self.verdict = verdict.strip().lower()
        self.categories = categories or []
        self.note = note
        self.added_at = added_at or time.time()
        self.source = source

    @property
    def is_malicious(self) -> bool:
        return self.verdict in _VERDICT_MALICIOUS

    @property
    def is_suspicious(self) -> bool:
        return self.is_malicious or self.verdict in _VERDICT_SUSPICIOUS

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "kind": self.kind.value if isinstance(self.kind, IndicatorType) else self.kind,
            "verdict": self.verdict,
            "categories": self.categories,
            "note": self.note,
            "added_at": self.added_at,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> LocalIndicator:
        return cls(
            indicator=str(payload.get("indicator", "")),
            kind=payload.get("kind", IndicatorType.URL),
            verdict=str(payload.get("verdict", "malicious")),
            categories=list(payload.get("categories") or []),
            note=str(payload.get("note", "")),
            added_at=payload.get("added_at"),
            source=str(payload.get("source", "local")),
        )


class LocalIndicatorStore:
    """Thread-safe in-memory indicator index with optional JSON persistence."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._lock = threading.RLock()
        self._index: dict[tuple[str, str], LocalIndicator] = {}
        self._path = Path(path) if path else None
        if self._path and self._path.exists():
            self.load(self._path)

    # ---------------------------------------------------------------- API

    def add(self, indicator: LocalIndicator) -> None:
        with self._lock:
            key = (indicator.kind.value, indicator.indicator)
            self._index[key] = indicator

    def add_many(self, indicators: list[LocalIndicator]) -> None:
        for item in indicators:
            self.add(item)

    def get(self, indicator: str, kind: IndicatorType) -> LocalIndicator | None:
        with self._lock:
            return self._index.get((kind.value, indicator.strip().lower()))

    def remove(self, indicator: str, kind: IndicatorType) -> bool:
        with self._lock:
            return self._index.pop((kind.value, indicator.strip().lower()), None) is not None

    def clear(self) -> None:
        with self._lock:
            self._index.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._index)

    def all(self) -> list[LocalIndicator]:
        with self._lock:
            return list(self._index.values())

    # ------------------------------------------------------- persistence

    def load(self, path: str | Path) -> int:
        target = Path(path)
        if not target.exists():
            return 0
        loaded = 0
        with target.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        entries = payload.get("indicators", payload) if isinstance(payload, dict) else payload
        for raw in entries or []:
            try:
                self.add(LocalIndicator.from_dict(raw))
                loaded += 1
            except (TypeError, ValueError, KeyError):
                continue
        return loaded

    def save(self, path: str | Path | None = None) -> Path:
        target = Path(path) if path else self._path
        if target is None:
            raise ValueError("No path configured for the indicator store.")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "saved_at": time.time(), "indicators": [i.to_dict() for i in self.all()]}
        tmp = target.with_suffix(target.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        tmp.replace(target)
        return target


class LocalIndicatorProvider(ThreatIntelProvider):
    """Serves verdicts from a :class:`LocalIndicatorStore`.

    Records explicitly added by an operator are treated as authoritative;
    records loaded from a file are not, because a stale file must not be able to
    permanently pin an indicator at MALICIOUS.
    """

    name = "local-indicators"
    requires_api_key = False
    supported_types = frozenset(
        {IndicatorType.URL, IndicatorType.DOMAIN, IndicatorType.SHA256, IndicatorType.IP}
    )

    def __init__(self, store: LocalIndicatorStore | None = None, *, authoritative: bool = False) -> None:
        self.store = store or LocalIndicatorStore()
        self.authoritative = authoritative

    def _lookup(self, indicator: str, kind: IndicatorType) -> IndicatorVerdict:
        record = self.store.get(indicator, kind)
        if record is None:
            # Also allow a URL indicator to answer domain queries.
            if kind is IndicatorType.DOMAIN:
                record = self.store.get(indicator, IndicatorType.URL)
            elif kind is IndicatorType.URL:
                from ..url.normalizer import parse_url

                try:
                    parsed = parse_url(indicator)
                    record = self.store.get(parsed.registrable, IndicatorType.DOMAIN) or self.store.get(
                        parsed.host, IndicatorType.DOMAIN
                    )
                except Exception:
                    record = None
        if record is None:
            return IndicatorVerdict(
                indicator=indicator,
                indicator_type=kind,
                status=ProviderStatus.NOT_FOUND,
                source=self.name,
            )
        return IndicatorVerdict(
            indicator=indicator,
            indicator_type=kind,
            malicious=record.is_malicious,
            suspicious=record.is_suspicious,
            confidence=0.95 if record.is_malicious else 0.6,
            report_count=1 if record.is_suspicious else 0,
            categories=list(record.categories),
            details={"note": record.note, "recorded_verdict": record.verdict},
            source=f"{self.name}:{record.source}",
            cache_age_seconds=max(0.0, time.time() - record.added_at),
        )

    async def check_url(self, url: str) -> IndicatorVerdict:
        return self._lookup(url, IndicatorType.URL)

    async def check_hash(self, sha256: str) -> IndicatorVerdict:
        return self._lookup(sha256, IndicatorType.SHA256)

    async def check_domain(self, domain: str) -> IndicatorVerdict:
        return self._lookup(domain, IndicatorType.DOMAIN)

    async def check_ip(self, ip: str) -> IndicatorVerdict:
        return self._lookup(ip, IndicatorType.IP)