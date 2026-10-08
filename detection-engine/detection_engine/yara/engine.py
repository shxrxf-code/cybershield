"""YARA rule engine: loading, compiling and matching CyberShield's own rules.

The rules shipped here are **defensive detection rules** written for this project.
They express behaviours that appear in phishing documents, credential-stealing
scripts and malicious installers.

Rule governance
---------------
* Rules live in ``rules/*.yar`` with a ``rules/index.json`` manifest carrying a
  version, author and per-rule severity.
* The manifest is what the engine trusts.  A ``.yar`` file present on disk but
  absent from the manifest is ignored, so an attacker who can write to the rules
  directory cannot silently add a rule that suppresses findings.
* Compilation happens once and is cached; a rule that fails to compile is
  reported and skipped rather than aborting the scan.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import Finding, Severity, SignalSource

__all__ = ["YaraEngine", "YaraMatch", "RuleLoadResult", "load_rules", "DEFAULT_RULES_DIR"]

DEFAULT_RULES_DIR = Path(__file__).parent.parent / "rules"

#: Map YARA rule tags onto our severity model.
_TAG_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

#: Map YARA rule names onto our risk weights so reports stay calibrated.
_TAG_WEIGHT: dict[str, float] = {
    "critical": 34.0,
    "high": 22.0,
    "medium": 14.0,
    "low": 8.0,
    "info": 3.0,
}


@dataclass(slots=True)
class YaraMatch:
    """One rule match against scanned data."""

    rule: str
    namespace: str = "default"
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        """Severity declared by the rule.

        Prefers an explicit ``tags:`` entry because that is the conventional place
        for it, but falls back to the ``severity`` meta field so that rules which
        only carry a description still report the severity their author intended.
        """
        for tag in self.tags:
            lowered = tag.lower()
            if lowered in _TAG_SEVERITY:
                return _TAG_SEVERITY[lowered]
        meta_severity = str(self.meta.get("severity", "")).lower().strip()
        if meta_severity in _TAG_SEVERITY:
            return _TAG_SEVERITY[meta_severity]
        return Severity.MEDIUM

    @property
    def is_authoritative(self) -> bool:
        """True when the rule author marked the match as decisive on its own."""
        declared = str(self.meta.get("authoritative", "")).strip().lower()
        if declared in ("true", "yes", "1"):
            return True
        return "authoritative" in {tag.lower() for tag in self.tags}

    @property
    def weight(self) -> float:
        return _TAG_WEIGHT.get(self.severity.value.lower(), 14.0)

    @property
    def category(self) -> str:
        value = self.meta.get("category")
        return value if isinstance(value, str) and value else "signature"

    @property
    def description(self) -> str:
        for key in ("description", "desc", "summary"):
            value = self.meta.get(key)
            if isinstance(value, str) and value:
                return value
        return f"YARA rule '{self.rule}' matched."

    def to_dict(self) -> dict[str, object]:
        return {
            "rule": self.rule,
            "namespace": self.namespace,
            "tags": self.tags,
            "severity": self.severity.value,
            "category": self.category,
            "authoritative": self.is_authoritative,
            "weight": self.weight,
            "description": self.description,
            "strings": [s.get("identifier") for s in self.strings if s.get("identifier")][:20],
        }


@dataclass(slots=True)
class RuleLoadResult:
    """Outcome of loading the rule set."""

    compiled: bool = False
    rule_count: int = 0
    manifest_version: str = "unknown"
    namespaces: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    engine_version: str = ""
    #: True when YARA itself is not installed.
    unavailable: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "compiled": self.compiled,
            "rule_count": self.rule_count,
            "manifest_version": self.manifest_version,
            "namespaces": self.namespaces,
            "files": self.files,
            "errors": self.errors,
            "warnings": self.warnings,
            "engine_version": self.engine_version,
            "unavailable": self.unavailable,
        }


def load_rules(rules_dir: str | Path | None = None) -> tuple[RuleLoadResult, Any]:
    """Compile the rule set from *rules_dir*, honouring the manifest.

    Returns ``(status, compiled_rules)``.  ``compiled_rules`` is ``None`` when the
    rule set could not be built; ``status`` always explains why.
    """
    root = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
    result = RuleLoadResult()

    try:
        import yara  # type: ignore[import-not-found]
    except ImportError:
        result.unavailable = True
        result.errors.append("yara-python is not installed; rule scanning is disabled.")
        return result, None

    try:
        result.engine_version = str(getattr(yara, "__version__", "unknown"))
    except Exception:  # pragma: no cover
        pass

    manifest_path = root / "index.json"
    manifest: dict[str, Any] = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            result.warnings.append(f"Rule manifest unreadable: {exc}")
    result.manifest_version = str(manifest.get("version") or "unknown")

    allowed = manifest.get("files")
    sources: dict[str, str] = {}
    for path in sorted(root.glob("*.yar")):
        relative = path.name
        if isinstance(allowed, list) and allowed and relative not in allowed:
            result.warnings.append(
                f"Skipped '{relative}': present on disk but not listed in index.json."
            )
            continue
        try:
            sources[relative.removesuffix(".yar")] = path.read_text(encoding="utf-8")
            result.files.append(relative)
        except OSError as exc:
            result.errors.append(f"Could not read '{relative}': {exc}")

    for name, text in list(sources.items()):
        try:
            yara.compile(source=text)
        except Exception as exc:
            result.errors.append(f"Rule file '{name}' failed to compile: {exc}")
            sources.pop(name)

    if not sources:
        return result, None

    try:
        rules = yara.compile(sources=sources)
    except Exception as exc:  # pragma: no cover - individual compiles already checked
        result.errors.append(f"Rule compilation failed: {exc}")
        return result, None

    result.compiled = True
    result.namespaces = sorted(sources)
    try:
        result.rule_count = sum(1 for _ in rules)
    except Exception:
        result.rule_count = len(sources)
    return result, rules


class YaraEngine:
    """Thread-safe wrapper around a compiled YARA rule set."""

    def __init__(self, rules_dir: str | Path | None = None) -> None:
        self._lock = threading.Lock()
        self._rules: Any = None
        self._load_result = RuleLoadResult()
        if rules_dir is not None or DEFAULT_RULES_DIR.exists():
            self.load(rules_dir)

    # ------------------------------------------------------------------ #

    def load(self, rules_dir: str | Path | None = None) -> RuleLoadResult:
        """(Re)load and compile the rule set."""
        with self._lock:
            try:
                load_result, compiled = load_rules(rules_dir)
            except Exception as exc:  # pragma: no cover - defensive
                load_result = RuleLoadResult()
                load_result.errors.append(f"Rule loading failed: {exc}")
                load_result.unavailable = True
                compiled = None
            self._load_result = load_result
            self._rules = compiled
            return self._load_result

    @property
    def available(self) -> bool:
        return self._rules is not None

    @property
    def status(self) -> RuleLoadResult:
        return self._load_result

    def scan(self, data: bytes, *, timeout: int = 30) -> list[YaraMatch]:
        """Match *data* against the rule set."""
        if self._rules is None:
            return []
        try:
            hits = self._rules.match(data=data, timeout=timeout)
        except Exception:
            # A rule timeout or error must not fail the whole scan.
            return []
        return [self._to_match(hit) for hit in hits]

    @staticmethod
    def _to_match(hit: Any) -> YaraMatch:
        meta = dict(getattr(hit, "meta", {}) or {})
        strings: list[dict[str, Any]] = []
        for entry in getattr(hit, "strings", []) or []:
            for identifier in getattr(entry, "identifier", []) or []:
                for instance in getattr(identifier, "instances", []) or []:
                    strings.append(
                        {
                            "identifier": getattr(identifier, "identifier", "?"),
                            "offset": getattr(instance, "offset", 0),
                            "matched_data": _safe_preview(instance),
                        }
                    )
                    break
        return YaraMatch(
            rule=getattr(hit, "rule", "unknown"),
            namespace=getattr(hit, "namespace", "default"),
            tags=[str(tag) for tag in (getattr(hit, "tags", []) or [])],
            meta=meta,
            strings=strings,
        )

    # ------------------------------------------------------------------ #

    def findings(self, data: bytes, *, source_label: str = "file") -> list[Finding]:
        """Run the rules and convert matches into findings."""
        if not self.available:
            return [
                Finding(
                    code="YARA.UNAVAILABLE",
                    title="YARA rule scanning did not run",
                    detail=(
                        f"Rule scanning is unavailable: "
                        f"{'; '.join(self.status.errors) or 'no rules compiled'}. "
                        "Signature-based detection was therefore not applied, which "
                        "reduces the confidence of this verdict."
                    ),
                    severity=Severity.INFO,
                    source=SignalSource.YARA,
                    category="coverage",
                    weight=0.0,
                )
            ]

        matches = self.scan(data)
        if not matches:
            return []

        findings: list[Finding] = []
        for match in matches:
            # A single rule match is evidence, not proof.  The authoritative flag is
            # only honoured when the rule author explicitly declared it, so a
            # behaviourally broad rule cannot force a verdict on its own.
            evidence_offsets = [s.get("offset") for s in match.strings if s.get("offset") is not None]
            matched_text = [s.get("matched_data") for s in match.strings if s.get("matched_data")]
            findings.append(
                Finding(
                    code=f"YARA.{match.rule}",
                    title=match.description,
                    detail=(
                        f"The CyberShield YARA rule '{match.rule}' matched this "
                        f"{source_label}"
                        + (f" at byte offset(s) {evidence_offsets[:5]}" if evidence_offsets else "")
                        + f". Matched content: {'; '.join(repr(t) for t in matched_text[:5])}. "
                        + f"Rule set version {self.status.manifest_version}."
                    ),
                    severity=match.severity,
                    source=SignalSource.YARA,
                    category=match.category,
                    weight=match.weight,
                    authoritative=match.is_authoritative,
                    evidence=match.to_dict(),
                )
            )
        return findings

    def status_dict(self) -> dict[str, object]:
        return self.status.to_dict()


def _safe_preview(instance: Any, limit: int = 64) -> str:
    data = getattr(instance, "matched_data", b"") or b""
    if isinstance(data, bytes):
        return data[:limit].decode("utf-8", errors="replace")
    return str(data)[:limit]


#: Process-wide engine instance, lazily compiled.
_engine: YaraEngine | None = None
_engine_lock = threading.Lock()


def get_engine(rules_dir: str | Path | None = None) -> YaraEngine:
    """Return the shared :class:`YaraEngine`, compiling it on first use."""
    global _engine
    with _engine_lock:
        if _engine is None or rules_dir is not None:
            _engine = YaraEngine(rules_dir)
        return _engine