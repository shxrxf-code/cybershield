"""Common interface for external scanners.

An external scanner is any detector that lives outside this process and answers
"is this object known bad?" with an authoritative opinion - an antivirus engine,
a sandbox, a curated feed. The contract is narrow on purpose:

* a scanner **never** decides a verdict or a score; it emits
  :class:`~app.schemas.signal.DetectionSignal` objects and the risk engine does
  the rest;
* **failure is not a clean bill of health.** :attr:`ScanResult.available` is
  ``False`` when the scanner could not be consulted, and the caller is expected
  to reduce ``scanner_coverage`` rather than treat silence as safety;
* no uploaded file is executed to obtain an answer.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.schemas.common import Severity, SignalSource
from app.schemas.signal import DetectionSignal, SignalBundle


@dataclass(slots=True)
class ScanResult:
    """Outcome of one scanner invocation."""

    scanner: str
    available: bool
    signals: list[DetectionSignal] = field(default_factory=list)
    #: Threat names / family labels reported by the engine.
    detections: list[str] = field(default_factory=list)
    #: Raw engine verdict string, e.g. ``FOUND`` or ``OK``.
    engine_verdict: str | None = None
    engine_version: str | None = None
    latency_ms: int | None = None
    scanned_bytes: int | None = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def detected(self) -> bool:
        return bool(self.detections)

    def to_bundle(self) -> SignalBundle:
        return SignalBundle(signals=list(self.signals))

    @classmethod
    def unavailable(cls, scanner: str, error: str, **kwargs: Any) -> "ScanResult":
        """Result representing *'the scanner could not answer'*.

        Constructing this explicitly - rather than returning an empty result with
        ``available=True`` - is what stops a ClamAV outage from reading as a
        clean file.
        """
        return cls(scanner=scanner, available=False, error=error, **kwargs)


class ExternalScanner(abc.ABC):
    """Base class for external detectors."""

    #: Stable identifier used in configuration, metrics and reports.
    name: str = "scanner"
    #: Provenance stamped on emitted signals.
    signal_source: SignalSource = SignalSource.HEURISTIC
    #: Maximum bytes this scanner will examine.
    max_bytes: int = 100 * 1024 * 1024

    @abc.abstractmethod
    async def is_available(self) -> bool:
        """Whether the scanner can currently answer a request."""

    @abc.abstractmethod
    async def scan_path(self, path: Path) -> ScanResult:
        """Scan a file already on local disk."""

    async def scan_bytes(self, data: bytes, suffix: str = "") -> ScanResult:
        """Scan an in-memory blob.

        The default implementation writes to a temporary file with a restricted
        mode and delegates. Subclasses that can scan a stream override this to
        avoid touching the filesystem at all.
        """
        import os
        import tempfile

        handle, tmp_name = tempfile.mkstemp(suffix=suffix, prefix="cybershield-scan-")
        try:
            os.fchmod(handle, 0o600)
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
            return await self.scan_path(Path(tmp_name))
        finally:
            try:
                os.unlink(tmp_name)
            except OSError:  # pragma: no cover - best effort cleanup
                pass

    def _make_signal(
        self,
        *,
        code: str,
        title: str,
        description: str,
        severity: Severity,
        evidence: dict[str, Any] | None = None,
        confidence: float = 0.95,
        category: str = "malware_detection",
    ) -> DetectionSignal:
        """Build a signal stamped with this scanner's provenance."""
        return DetectionSignal(
            code=code,
            title=title,
            description=description,
            severity=severity,
            category=category,
            source=self.signal_source,
            confidence=confidence,
            evidence=evidence or {},
        )

    async def close(self) -> None:
        """Release any resources. Overridden when needed."""
        return None


__all__ = ["ExternalScanner", "ScanResult"]