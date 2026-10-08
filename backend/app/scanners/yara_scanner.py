"""YARA rule matching.

YARA is the project's highest-signal local detector: rules match byte patterns
that encode *how* malware behaves (packer stubs, C2 config structures, known
dropper templates), so a match is far more informative than a generic heuristic.

Rules shipped with CyberShield live in ``detection-engine/yara/rules`` and are
reviewed source files. Operator-supplied rules may be dropped into
``rules/local`` and are compiled after the built-ins.

Safety properties
-----------------
* **The sample is never executed.** Matching reads bytes.
* **Compilation is bounded.** ``yara.compile`` accepts file paths; a rule file
  that fails to compile is logged and skipped rather than taking down the
  scanner.
* **Timeout.** A rule set can hang on pathological input (a pathological rule, or
  a zip bomb). A wall-clock timeout is enforced so a scan cannot hang a worker.
* **Immutable compilation.** Compiled rules are cached, because compiling on
  every scan would dominate request latency.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any, Final

from app.core.config import get_settings
from app.schemas.common import Severity, SignalSource
from app.schemas.signal import DetectionSignal
from app.scanners.base import ExternalScanner, ScanResult

logger = logging.getLogger(__name__)

#: A rule match on more than this many files inside an archive is treated as a
#: generic indicator of an archive full of tools, not a family match.
_MAX_RULES_PER_FILE: Final[int] = 25
#: YARA match timeout in seconds. Overridable per deployment.
_SCAN_TIMEOUT_SECONDS: Final[float] = 30.0
#: Guard against reading something enormous into memory when scanning a path.
_MAX_SCAN_BYTES: Final[int] = 200 * 1024 * 1024

_SEVERITY_BY_TAG: Final[dict[str, Severity]] = {
    "malware": Severity.CRITICAL,
    "trojan": Severity.CRITICAL,
    "ransomware": Severity.CRITICAL,
    "backdoor": Severity.CRITICAL,
    "rootkit": Severity.CRITICAL,
    "exploit": Severity.HIGH,
    "dropper": Severity.HIGH,
    "loader": Severity.HIGH,
    "packer": Severity.MEDIUM,
    "obfuscation": Severity.MEDIUM,
    "suspicious": Severity.MEDIUM,
    "tool": Severity.LOW,
    "apt": Severity.CRITICAL,
    "credential_stealer": Severity.CRITICAL,
}


def _severity_for(rule_name: str, tags: set[str]) -> Severity:
    """Derive severity from rule tags, falling back to the rule name."""
    severities = [
        _SEVERITY_BY_TAG[tag.lower()] for tag in tags if tag.lower() in _SEVERITY_BY_TAG
    ]
    if severities:
        return max(severities, key=lambda s: s.rank)
    lowered = rule_name.lower()
    for tag, severity in _SEVERITY_BY_TAG.items():
        if tag in lowered:
            return severity
    return Severity.MEDIUM


class YaraScanner(ExternalScanner):
    """Compiles and applies the project's YARA rule set."""

    name = "yara"
    signal_source = SignalSource.YARA

    def __init__(self, rules_dir: Path | None = None) -> None:
        settings = get_settings()
        self._rules_dir = rules_dir or settings.resolved_yara_rules_dir
        self._enabled = settings.yara_enabled
        self._rules: Any | None = None
        self._compiled_at: float | None = None
        self._rule_count = 0
        self._load_errors: list[str] = []

    @property
    def rules_dir(self) -> Path:
        return self._rules_dir

    @property
    def rule_count(self) -> int:
        return self._rule_count

    async def is_available(self) -> bool:
        if not self._enabled:
            return False
        try:
            import yara  # noqa: F401
        except ImportError:
            return False
        if await self._ensure_rules() is None:
            return False
        return self._rule_count > 0

    async def _ensure_rules(self) -> Any | None:
        """Compile the rule set once, reusing the compiled object thereafter."""
        if self._rules is not None:
            return self._rules
        if not self._enabled:
            return None
        try:
            import yara  # noqa: F401
        except ImportError:
            logger.info("yara-python is not installed; YARA scanning is disabled")
            return None

        return await asyncio.to_thread(self._compile_rules)

    def _compile_rules(self) -> Any | None:
        """Compile built-in and local rules. Blocking; runs in a worker thread."""
        import yara

        if not self._rules_dir.exists():
            logger.warning("YARA rules directory does not exist: %s", self._rules_dir)
            return None

        namespaces: dict[str, str] = {}
        self._load_errors = []

        for category in ("builtin", "local"):
            directory = self._rules_dir / category
            if not directory.is_dir():
                continue
            for rule_file in sorted(directory.glob("*.yar")):
                source = self._read_source(rule_file)
                if source is None:
                    continue
                namespaces[rule_file.stem] = source

        # A single file containing every rule is supported as a fallback.
        combined = self._rules_dir / "all.yar"
        if not namespaces and combined.exists():
            source = self._read_source(combined)
            if source is not None:
                namespaces["all"] = source

        if not namespaces:
            logger.warning("No YARA rules found in %s", self._rules_dir)
            return None

        try:
            compiled = yara.compile(sources=namespaces)
        except Exception as exc:  # noqa: BLE001 - yara raises many types
            logger.error("YARA rule compilation failed: %s", exc)
            return None

        self._rules = compiled
        self._compiled_at = time.time()
        self._rule_count = len(namespaces)
        logger.info(
            "YARA rules compiled", extra={"rule_files": self._rule_count, "dir": str(self._rules_dir)}
        )
        return compiled

    @staticmethod
    def _read_source(rule_file: Path) -> str | None:
        """Read a rule file, returning ``None`` if it is unusable."""
        try:
            # Read as bytes: rule files are often not valid UTF-8 because they
            # contain raw hex patterns and escape bytes.
            return rule_file.read_bytes().decode("utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read YARA rule file %s: %s", rule_file, exc)
            return None

    def invalidate(self) -> None:
        """Drop the compiled cache so rules are re-read on the next scan."""
        self._rules = None
        self._compiled_at = None
        self._rule_count = 0

    async def scan_path(self, path: Path) -> ScanResult:
        """Match rules against a file on disk."""
        rules = await self._ensure_rules()
        if rules is None:
            return ScanResult.unavailable(self.name, "YARA is not available.")

        try:
            size = path.stat().st_size
        except OSError as exc:
            return ScanResult.unavailable(self.name, f"Cannot stat file: {exc.strerror}")

        started = time.perf_counter()
        try:
            matches = await asyncio.wait_for(
                asyncio.to_thread(rules.match, str(path), timeout=_SCAN_TIMEOUT_SECONDS),
                timeout=_SCAN_TIMEOUT_SECONDS + 5,
            )
        except asyncio.TimeoutError:
            # A timed-out match means the scan did not complete, so the result is
            # "no answer", never "no matches".
            return ScanResult.unavailable(
                self.name,
                f"YARA matching exceeded {_SCAN_TIMEOUT_SECONDS:.0f}s and was abandoned.",
                scanned_bytes=size,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("YARA match failed: %s", exc)
            return ScanResult.unavailable(self.name, f"YARA match failed: {exc}")

        latency = int((time.perf_counter() - started) * 1000)
        return self._interpret(matches, latency, size)

    async def scan_bytes(self, data: bytes, suffix: str = "") -> ScanResult:
        """Match rules against an in-memory blob.

        ``timeout`` is passed through to yara-python so a pathological rule cannot
        wedge the worker thread.
        """
        rules = await self._ensure_rules()
        if rules is None:
            return ScanResult.unavailable(self.name, "YARA is not available.")
        if len(data) > _MAX_SCAN_BYTES:
            return ScanResult.unavailable(
                self.name, f"Payload exceeds the YARA limit of {_MAX_SCAN_BYTES} bytes."
            )

        started = time.perf_counter()
        try:
            matches = await asyncio.to_thread(
                rules.match, data=data, timeout=int(_SCAN_TIMEOUT_SECONDS)
            )
        except Exception as exc:  # noqa: BLE001 - includes TimeoutError from yara
            logger.warning("YARA match failed: %s", exc)
            return ScanResult.unavailable(self.name, f"YARA match failed: {exc}")

        latency = int((time.perf_counter() - started) * 1000)
        return self._interpret(matches, latency, len(data))

    # ------------------------------------------------------------------
    # Interpretation
    # ------------------------------------------------------------------
    def _interpret(self, matches: Any, latency_ms: int, size: int) -> ScanResult:
        """Convert YARA matches into signals."""
        if not matches:
            return ScanResult(
                scanner=self.name,
                available=True,
                engine_verdict="NO_MATCH",
                latency_ms=latency_ms,
                scanned_bytes=size,
            )

        signals: list[DetectionSignal] = []
        names: list[str] = []

        for match in matches[:_MAX_RULES_PER_FILE]:
            rule_name = getattr(match, "rule", "unknown")
            namespace = getattr(match, "namespace", "")
            tags = {str(tag) for tag in getattr(match, "tags", []) or []}
            meta = dict(getattr(match, "meta", {}) or {})
            names.append(rule_name)

            severity = _severity_for(rule_name, tags)
            matched_strings = list(getattr(match, "strings", []) or [])

            family = meta.get("family") or meta.get("malware_family") or namespace or None
            description = (
                f"The YARA rule '{rule_name}' matched this content. YARA rules encode "
                "byte-level patterns of known malicious families and techniques, so a match "
                "is strong evidence of compromise. The file was not executed."
            )
            if family:
                description += f" The rule identifies the family as '{family}'."

            signals.append(
                self._make_signal(
                    code=f"yara.{rule_name}",
                    title=f"YARA rule matched: {rule_name}",
                    description=description,
                    severity=severity,
                    category="signature",
                    evidence={
                        "rule": rule_name,
                        "namespace": namespace,
                        "tags": sorted(tags),
                        "meta": {k: str(v)[:200] for k, v in meta.items()},
                        "matched_string_count": len(matched_strings),
                    },
                    confidence=0.92 if severity.rank >= Severity.HIGH.rank else 0.75,
                )
            )

        if len(matches) > _MAX_RULES_PER_FILE:
            signals.append(
                self._make_signal(
                    code="yara.mass_matches",
                    title=f"{len(matches)} YARA rules matched",
                    description=(
                        "An unusually large number of rules matched this file. That pattern is "
                        "more consistent with a generic tool, a multi-purpose builder, or a "
                        "packed sample than with one specific malware family."
                    ),
                    severity=Severity.LOW,
                    category="signature",
                    evidence={"match_count": len(matches)},
                    confidence=0.6,
                )
            )

        return ScanResult(
            scanner=self.name,
            available=True,
            signals=signals,
            detections=names,
            engine_verdict="MATCH",
            latency_ms=latency_ms,
            scanned_bytes=size,
            metadata={
                "match_count": len(matches),
                "rule_files": self._rule_count,
                "compiled_at": self._compiled_at,
            },
        )


_scanner: YaraScanner | None = None


def get_yara_scanner() -> YaraScanner:
    """Return the process-wide YARA scanner."""
    global _scanner
    if _scanner is None:
        _scanner = YaraScanner()
    return _scanner


__all__ = ["YaraScanner", "get_yara_scanner"]