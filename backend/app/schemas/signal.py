"""Detection signal model.

A :class:`DetectionSignal` is the atomic unit of evidence. Scanners emit signals;
they never compute a score or a verdict themselves. The risk engine is the only
component that aggregates signals, which keeps scoring consistent and auditable
across every scan type.
"""

from __future__ import annotations

import hashlib
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from app.schemas.common import IndicatorType, Severity, SignalSource, json_safe


class Indicator(BaseModel):
    """A concrete observable extracted from the analysed object."""

    model_config = ConfigDict(frozen=True)

    type: IndicatorType
    value: str
    context: str | None = Field(default=None, max_length=512)

    @field_validator("value")
    @classmethod
    def _trim(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Indicator value must not be empty")
        if len(cleaned) > 2048:
            cleaned = cleaned[:2048]
        return cleaned

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fingerprint(self) -> str:
        """Stable short hash so identical indicators can be de-duplicated."""
        return hashlib.sha256(f"{self.type.value}:{self.value}".encode()).hexdigest()[:16]


class DetectionSignal(BaseModel):
    """One explainable piece of evidence contributing to a risk assessment.

    Attributes:
        code: Stable machine identifier, e.g. ``av.malware_detected``.
        title: Short human-readable summary shown in the UI.
        description: Why the signal fired, including the concrete evidence.
        severity: Nominal severity; supplies the default weight.
        category: Coarse grouping used to avoid correlated double counting.
        weight: 0-1 contribution, defaulting from severity. The risk engine
            clamps this into the category budget.
        confidence: 0-1 reliability of *this specific signal*, distinct from the
            overall verdict confidence.
        source: Provenance, surfaced so users can judge authority.
        evidence: Structured supporting data (counts, matched patterns, hashes).
            Must never contain raw file contents or credentials.
        indicators: Observable indicators associated with the signal.
    """

    model_config = ConfigDict(frozen=True)

    code: str = Field(min_length=2, max_length=120)
    title: str = Field(min_length=2, max_length=200)
    description: str = Field(min_length=2, max_length=2000)
    severity: Severity
    category: str = Field(min_length=2, max_length=64)
    source: SignalSource = SignalSource.HEURISTIC
    weight: float | None = Field(default=None, ge=0.0, le=1.0)
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)
    indicators: tuple[Indicator, ...] = ()

    @field_validator("evidence", mode="before")
    @classmethod
    def _sanitise_evidence(cls, value: Any) -> Any:
        return json_safe(value)

    @property
    def effective_weight(self) -> float:
        """Weight used by the risk engine (severity default when unset)."""
        if self.weight is not None:
            return self.weight
        return self.severity.default_weight

    @property
    def is_authoritative(self) -> bool:
        """True for sources that are direct, curated evidence of compromise.

        Authoritative signals dominate the aggregate score because they are far
        less prone to false positives than heuristics or model output.
        """
        return self.source in (
            SignalSource.ANTIVIRUS,
            SignalSource.THREAT_INTELLIGENCE,
            SignalSource.YARA,
        )

    @property
    def impact(self) -> float:
        """Effective contribution ceiling: weight scaled by confidence."""
        return self.effective_weight * self.confidence

    def dedupe_key(self) -> str:
        """Identity used to collapse duplicate signals from repeated detectors."""
        indicator_keys = sorted(i.fingerprint for i in self.indicators)
        return f"{self.code}|{indicator_keys}"


class SignalBundle(BaseModel):
    """Accumulator that scanners use to collect signals before scoring."""

    signals: list[DetectionSignal] = Field(default_factory=list)

    def add(self, signal: DetectionSignal) -> DetectionSignal:
        self.signals.append(signal)
        return signal

    def extend(self, signals: "list[DetectionSignal] | tuple[DetectionSignal, ...]") -> None:
        self.signals.extend(signals)

    def extend_bundle(self, other: "SignalBundle") -> None:
        self.signals.extend(other.signals)

    def deduplicate(self) -> list[DetectionSignal]:
        """Collapse signals that are identical in code and indicator set.

        When duplicates collapse, the highest-confidence instance wins so that a
        second corroborating detector cannot dilute the finding.
        """
        best: dict[str, DetectionSignal] = {}
        for signal in self.signals:
            key = signal.dedupe_key()
            current = best.get(key)
            if current is None or signal.confidence > current.confidence:
                best[key] = signal
        return list(best.values())

    def has_code(self, *codes: str) -> bool:
        wanted = set(codes)
        return any(signal.code in wanted for signal in self.signals)

    def codes(self) -> list[str]:
        return [signal.code for signal in self.signals]

    def __len__(self) -> int:
        return len(self.signals)

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self.signals)

    def __bool__(self) -> bool:
        return bool(self.signals)


class AnalysisContext(BaseModel):
    """Shared, immutable context threaded through the analysis pipeline.

    Carries correlation metadata and user consent state. Consent flags gate
    outbound submission to third-party reputation services, because doing so
    without consent would leak the user's browsing or file activity.
    """

    model_config = ConfigDict(frozen=True)

    scan_id: str | None = None
    correlation_id: str | None = None
    user_id: str | None = None
    consent_third_party_lookup: bool = True
    consent_dns_lookup: bool = True
    consent_active_fetch: bool = True
    timeout_seconds: float = 30.0
    metadata: dict[str, Any] = Field(default_factory=dict)