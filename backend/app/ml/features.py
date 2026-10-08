"""Static feature extraction for the advisory machine-learning layer.

Why features are "static"
-------------------------
No raw content ever enters a model. Every feature is derived from the
already-*scored and human-interpretable* signal bundle, the object type, and the
pipeline coverage. This guarantees three properties:

* **No content leakage.** A feature vector contains counts, severities, sources
  and confidence - never bytes, strings, filenames, hashes or headers. It is
  therefore safe to store, log and return in a report.
* **Attribution.** Every feature is traceable to the signal that produced it, so
  a model opinion can be explained in the same vocabulary as the rest of the
  report and is never a black box.
* **Determinism.** The same bundle always yields the same vector, which makes the
  model reproducible and unit-testable without training a network.

The machine-learning layer is **advisory only**. Its output is a 0-1 opinion
that is never the sole authority for a verdict: the risk engine owns verdicts,
and the model at most contributes a low-budget signal when it disagrees strongly
with the rule-based result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.schemas.common import ObjectType, Severity, SignalSource, json_safe
from app.schemas.signal import DetectionSignal

#: Category groups collapsed into a few interpretable features. Grouping keeps
#: the vector small enough to be fit from a modest labelled set while still
#: capturing the top-level shape of an attack.
_CATEGORY_GROUPS: dict[str, frozenset[str]] = {
    "deception": frozenset({"deception", "impersonation", "social_engineering"}),
    "structural": frozenset({"structural", "delivery"}),
    "textual": frozenset({"lexical", "obfuscation", "transparency", "transport"}),
    "authentication_reputation": frozenset(
        {"authentication", "reputation", "reputation_context", "legitimacy"}
    ),
}

#: Sources considered authoritative evidence of compromise.
_AUTHORITATIVE_SOURCES: frozenset[SignalSource] = frozenset(
    {SignalSource.ANTIVIRUS, SignalSource.THREAT_INTELLIGENCE, SignalSource.YARA}
)


@dataclass(slots=True)
class FeatureVector:
    """An ordered, fixed-width numeric vector and its feature names.

    The order of :attr:`values` always matches :attr:`names`, so the vector can
    be handed to a linear model verbatim and the names can travel with it for
    attribution.
    """

    names: list[str] = field(default_factory=list)
    values: list[float] = field(default_factory=list)

    def as_dict(self) -> dict[str, float]:
        """Mapping form for metadata storage and reporting."""
        return dict(zip(self.names, self.values, strict=True))

    def as_list(self) -> list[float]:
        """Array form for model inference."""
        return list(self.values)

    def __len__(self) -> int:
        return len(self.values)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<FeatureVector n={len(self.values)}>"


def _noisy_or(impacts: list[float]) -> float:
    """Collapse independent evidence: ``1 - product(1 - impact)``."""
    survival = 1.0
    for impact in impacts:
        survival *= 1.0 - min(0.99, max(0.0, impact))
    return 1.0 - survival


def extract_features(
    signals: list[DetectionSignal] | tuple[DetectionSignal, ...],
    *,
    object_type: ObjectType = ObjectType.UNKNOWN,
    coverage: float = 1.0,
) -> FeatureVector:
    """Build the fixed-width feature vector from an analysed signal bundle.

    Args:
        signals: The deduplicated signals produced by the pipeline.
        object_type: Kind of the analysed object; one-hot features are derived
            from it so the model can learn per-type priors.
        coverage: 0-1 scanner coverage. Low coverage must reduce, never raise,
            the model's confidence in a risky opinion.

    Returns:
        A :class:`FeatureVector` whose :attr:`values` align with :attr:`names`.
    """
    names: list[str] = []
    values: list[float] = []

    def add(name: str, value: float) -> None:
        names.append(name)
        values.append(round(value, 6))

    signals = list(signals)
    impacts = [signal.impact for signal in signals]

    add("signal_count", min(len(signals), 40))
    add("authoritative_signal_count", sum(1 for s in signals if s.source in _AUTHORITATIVE_SOURCES))
    add("critical_count", sum(1 for s in signals if s.severity is Severity.CRITICAL))
    add("high_count", sum(1 for s in signals if s.severity is Severity.HIGH))
    add("medium_count", sum(1 for s in signals if s.severity is Severity.MEDIUM))
    add("low_count", sum(1 for s in signals if s.severity is Severity.LOW))
    add("info_count", sum(1 for s in signals if s.severity is Severity.INFO))
    add("sum_impact", min(sum(impacts), 10.0))
    add("max_impact", max(impacts, default=0.0))
    add("collapsed_noisy_or", _noisy_or(impacts))
    add(
        "deception_signals",
        sum(1 for s in signals if s.category in _CATEGORY_GROUPS["deception"]),
    )
    add(
        "structural_signals",
        sum(1 for s in signals if s.category in _CATEGORY_GROUPS["structural"]),
    )
    add(
        "textual_signals",
        sum(1 for s in signals if s.category in _CATEGORY_GROUPS["textual"]),
    )
    add(
        "authentication_reputation_signals",
        sum(1 for s in signals if s.category in _CATEGORY_GROUPS["authentication_reputation"]),
    )
    add_confidence = sum(s.confidence for s in signals) / len(signals) if signals else 0.0
    add("mean_confidence", add_confidence)
    add("scanner_coverage", max(0.0, min(1.0, coverage)))
    add("is_url", float(object_type is ObjectType.URL))
    add("is_email", float(object_type is ObjectType.EMAIL))
    add("is_binary", float(object_type in (ObjectType.FILE, ObjectType.APK, ObjectType.ARCHIVE)))
    add("is_text", float(object_type is ObjectType.TEXT))

    return FeatureVector(names=names, values=values)


def feature_vector_to_json(vector: FeatureVector) -> dict[str, Any]:
    """Serialise a feature vector for a report's metadata (JSON-safe)."""
    return {
        "names": list(vector.names),
        "values": [json_safe(value) for value in vector.values],
    }


__all__ = ["FeatureVector", "extract_features", "feature_vector_to_json"]