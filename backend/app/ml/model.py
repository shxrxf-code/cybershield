"""Advisory machine-learning risk opinion.

Position and honesty
--------------------
This layer answers one question: *given every signal already extracted by the
rule-based engines, how risky does a statistical model think the object is?* It
is deliberately constrained and never authoritative:

* It sees **no raw content** - only the static feature vector derived from the
  signal bundle (see :mod:`app.ml.features`).
* Its output is a **0-1 probability plus a label**, never a verdict. The risk
  engine owns verdicts; a model opinion can at most contribute a low-budget
  ``machine_learning`` signal when it disagrees strongly with the rule-based
  result, and that signal is capped by the engine's category budget.
* It **degrades gracefully**: when ``sklearn``/``numpy`` are absent, or the
  fitted model fails for any reason, the rule-based baseline model answers
  instead. An opinion is never required to produce a scan result.

Two models
----------
* :class:`RuleBasedOpinionModel` - a deterministic logistic baseline with
  documented coefficients. Always available.
* :class:`LogisticOpinionModel` - a regularised logistic regression fitted
  lazily on the project's labelled calibration corpus (the same hand-authored
  cases the risk engine is calibrated against, see ``tests/calibration_set.py``).
  The fit is deterministic (fixed seed), tiny, and only useful as an
  independent cross-check of the engine's aggregate, not as ground truth.
"""

from __future__ import annotations

import importlib.util
import logging
import math
from dataclasses import dataclass, field
from typing import Any

from app.ml.features import FeatureVector

logger = logging.getLogger(__name__)

#: Whether a real statistical model can be fitted in this process.
_SKLEARN_AVAILABLE: bool = bool(
    importlib.util.find_spec("sklearn") is not None
    and importlib.util.find_spec("numpy") is not None
)

#: Label thresholds for the probability output.
_LOW = 0.30
_MEDIUM = 0.55
_HIGH = 0.80


def _sigmoid(z: float) -> float:
    """Numerically stable logistic function."""
    return 1.0 / (1.0 + math.exp(-max(-40.0, min(40.0, z))))


def _label_for(probability: float) -> str:
    if probability < _LOW:
        return "low"
    if probability < _MEDIUM:
        return "medium"
    if probability < _HIGH:
        return "high"
    return "critical"


@dataclass(slots=True)
class ModelOpinion:
    """One advisory model output."""

    #: 0-1 probability that the object is malicious, per the model alone.
    probability: float
    #: ``low`` | ``medium`` | ``high`` | ``critical`` | ``unknown``.
    label: str
    #: Which model produced the opinion (``rule_based`` | ``logistic_regression``).
    model: str
    features: dict[str, float] = field(default_factory=dict)
    note: str | None = None

    def as_metadata(self) -> dict[str, Any]:
        return {
            "probability": round(self.probability, 4),
            "label": self.label,
            "model": self.model,
            "note": self.note,
        }


class RuleBasedOpinionModel:
    """Deterministic baseline derived from the engine's published semantics.

    The coefficients below mirror the risk engine's own vocabulary - noisy-OR
    collapse of evidence, a boost for authoritative sources, and a hard discount
    when scan coverage is thin. They are documented so the baseline is as
    auditable as the rule engine itself.
    """

    name = "rule_based"

    def predict(self, vector: FeatureVector) -> ModelOpinion:
        f = vector.as_dict()
        collapsed = float(f.get("collapsed_noisy_or", 0.0))
        authoritative = int(f.get("authoritative_signal_count", 0))
        signal_count = int(f.get("signal_count", 0))
        max_impact = float(f.get("max_impact", 0.0))
        coverage = float(f.get("scanner_coverage", 1.0))

        # An authoritative confirmation is the single strongest driver.
        authority_boost = 2.4 * min(authoritative, 2)
        volume = 0.35 * min(signal_count, 8)
        z = 3.8 * collapsed + 1.2 * max_impact + authority_boost + volume - 1.6
        probability = _sigmoid(z)

        # Thin coverage must reduce, never raise, a risky opinion.
        probability *= 0.35 + 0.65 * max(0.0, min(1.0, coverage))

        if signal_count == 0 and coverage < 0.5:
            return ModelOpinion(
                probability=0.5,
                label="unknown",
                model=self.name,
                features=f,
                note="No evidence and low coverage: the model returns no opinion.",
            )

        return ModelOpinion(
            probability=max(0.0, min(1.0, probability)),
            label=_label_for(probability),
            model=self.name,
            features=f,
        )


class LogisticOpinionModel:
    """Regularised logistic regression fitted on the calibration corpus.

    The fit is lazy and memoised. A failure to import, build or fit degrades to
    ``None`` so the caller falls back to the rule-based baseline - an opinion is
    never mandatory.
    """

    name = "logistic_regression"

    def __init__(self) -> None:
        self._features: dict[str, Any] | None = None
        self._trained_on = 0

    @property
    def is_available(self) -> bool:
        return _SKLEARN_AVAILABLE

    @property
    def trained_on(self) -> int:
        """Number of labelled cases the fitted model saw, or 0 when unfitted."""
        return self._trained_on

    def _ensure_fitted(self, feature_names: list[str]) -> None:
        if self._features is not None:
            return
        X, y, names = self._build_corpus(feature_names)
        if len(y) < 4 or len(set(y)) < 2:
            raise RuntimeError("calibration corpus is too small to fit a classifier")

        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler

        scaler = StandardScaler().fit(X)
        clf = LogisticRegression(
            C=0.05,  # strong regularisation: 17 samples, ~20 features
            solver="lbfgs",
            max_iter=2000,
            random_state=0,
        )
        clf.fit(scaler.transform(X), y)

        # Keep the scaler and classifier separate so inference can transform a
        # vector of the same width without re-fitting.
        self._features = {"scaler": scaler, "classifier": clf, "names": names}
        self._trained_on = len(y)
        logger.info(
            "ML opinion model fitted",
            extra={"model": self.name, "training_cases": len(y), "features": len(names)},
        )

    def predict(self, vector: FeatureVector) -> ModelOpinion | None:
        """Return an opinion, or ``None`` to signal 'no model available'."""
        if not self.is_available:
            return None
        try:
            self._ensure_fitted(vector.names)
        except Exception as exc:  # noqa: BLE001 - any failure means "degrade"
            logger.warning("ML model unavailable, degrading to rule-based: %s", exc)
            return None

        assert self._features is not None  # set by _ensure_fitted on success
        scaler = self._features["scaler"]
        classifier = self._features["classifier"]
        row = scaler.transform([vector.as_list()])
        probability = float(classifier.predict_proba(row)[0][1])
        return ModelOpinion(
            probability=max(0.0, min(1.0, probability)),
            label=_label_for(probability),
            model=self.name,
            features=vector.as_dict(),
            note=f"fitted on {self._trained_on} labelled calibration cases",
        )

    # ------------------------------------------------------------------
    # Corpus
    # ------------------------------------------------------------------
    @staticmethod
    def _build_corpus(feature_names: list[str]) -> tuple[list[list[float]], list[int], list[str]]:
        """Build (X, y) from the labelled calibration set.

        Imported lazily so the model layer does not depend on the tests package
        unless a statistical fit is actually requested.
        """
        from app.schemas.common import ObjectType, Verdict
        from app.schemas.signal import SignalBundle
        from app.ml.features import extract_features

        from tests.calibration_set import ALL_CASES

        X: list[list[float]] = []
        y: list[int] = []
        names: list[str] = feature_names

        for case in ALL_CASES:
            if case.object_type == "URL":
                from app.detection_engine.url.analyzer import analyse_url_structure
                from app.detection_engine.url.parser import parse_url

                bundle = SignalBundle(
                    signals=analyse_url_structure(parse_url(str(case.payload["url"])))
                )
                object_type = ObjectType.URL
            elif case.object_type == "TEXT":
                from app.detection_engine.phishing.heuristics import analyse_text_content

                bundle = SignalBundle(signals=analyse_text_content(str(case.payload["text"])))
                object_type = ObjectType.TEXT
            else:  # pragma: no cover - the current set has no file cases
                from app.detection_engine.file.analyzer import analyse_file

                result = analyse_file(
                    case.payload.get("data", b""),
                    filename=case.payload.get("filename"),
                )
                bundle = SignalBundle(signals=result.signals)
                object_type = ObjectType.FILE

            vector = extract_features(bundle.deduplicate(), object_type=object_type)
            names = vector.names
            label = 1 if case.maximum_verdict.value in ("SUSPICIOUS", "HIGH_RISK", "MALICIOUS") else 0
            X.append(vector.as_list())
            y.append(label)

        return X, y, names


# ---------------------------------------------------------------------------
# Facade
# ---------------------------------------------------------------------------

_model: Any | None = None


@dataclass(slots=True)
class OpinionService:
    """Selects the best available model and answers risk-opinion questions."""

    statistical: LogisticOpinionModel = field(default_factory=LogisticOpinionModel)

    @property
    def model_used(self) -> str:
        return self.statistical.name if self.statistical.is_available else RuleBasedOpinionModel.name

    def predict_risk(self, vector: FeatureVector) -> ModelOpinion:
        """Return the best available opinion for ``vector``."""
        statistical_opinion = self.statistical.predict(vector)
        if statistical_opinion is not None:
            return statistical_opinion
        return RuleBasedOpinionModel().predict(vector)


def get_opinion_service() -> OpinionService:
    """Return the process-wide opinion service."""
    global _model
    if _model is None:
        _model = OpinionService()
    return _model


def set_opinion_service(service: OpinionService | None) -> None:
    """Replace the service, for tests."""
    global _model
    _model = service


__all__ = [
    "LogisticOpinionModel",
    "ModelOpinion",
    "OpinionService",
    "RuleBasedOpinionModel",
    "get_opinion_service",
    "set_opinion_service",
]