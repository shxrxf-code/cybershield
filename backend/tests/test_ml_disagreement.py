"""ML-advisory disagreement behaviour.

The model is advisory: it can *raise suspicion* of a rule-declared safe scan
(``ml.risk_underestimate``, MEDIUM, surfaces in signals/reasons metadata) but it
can never fabricate a detection on its own - a single uncorroborated model
signal must not force the verdict out of the SAFE band. A "more optimistic"
opinion never dilutes an evidence-backed verdict. The suite stubs the model so
probability values are deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas.common import ObjectType, Severity, SignalSource, Verdict
from app.schemas.signal import DetectionSignal, SignalBundle
from app.services.scan_service import ScanService


@dataclass
class _StubOpinion:
    probability: float
    model: str = "stub"

    def as_metadata(self) -> dict:
        return {
            "model": self.model,
            "probability": round(self.probability, 4),
            "verdict": "dangerous" if self.probability >= 0.7 else "safe",
        }


class _StubMl:
    def __init__(self, probability: float) -> None:
        self._probability = probability

    def predict_risk(self, vector):  # noqa: ANN001 - stub interface
        return _StubOpinion(self._probability)


def _service(probability: float) -> ScanService:
    return ScanService(ml=_StubMl(probability))


def test_model_can_raise_suspicion_but_never_fabricate_detection() -> None:
    """High model probability + SAFE rule verdict => suspicion signal + score
    increase, while the verdict stays SAFE (suspicion is not a detection)."""
    svc = _service(0.85)
    metadata: dict = {}
    assessment, bundle = svc._apply_ml(  # noqa: SLF001 - white-box unit test
        SignalBundle(),
        object_type=ObjectType.URL,
        coverage=1.0,
        incomplete=False,
        metadata=metadata,
    )

    # The disagreement is surfaced honestly...
    assert metadata["ml"]["disagreement"] == "model_more_risky"
    assert metadata["ml"]["ml_opinion"]["probability"] == 0.85

    # ...as a MEDIUM machine-learning signal with explanatory reasons...
    codes = [s.code for s in bundle]
    assert "ml.risk_underestimate" in codes
    signal = next(s for s in bundle if s.code == "ml.risk_underestimate")
    assert signal.severity == Severity.MEDIUM
    assert signal.source == SignalSource.MACHINE_LEARNING

    # ...and a material score lift.
    assert assessment.score > 0.0
    assert "disagrees" in " ".join(assessment.reasons)

    # But suspicion alone is not a detection: the verdict may not move to a
    # risk band, and the reasons must not claim one.
    assert assessment.verdict.is_safe_enough
    assert assessment.recommendation_text


def test_model_more_optimistic_never_dilutes_evidence() -> None:
    """A low model probability against a rule-declared risky verdict records
    the disagreement for calibration but adds no mitigating signal."""
    svc = _service(0.05)
    metadata, extra = svc._ml_opinion(  # noqa: SLF001
        [],
        object_type=ObjectType.URL,
        coverage=1.0,
        pre_ml_verdict=Verdict.HIGH_RISK,
    )
    assert metadata["disagreement"] == "model_more_optimistic"
    assert extra == []


def test_agreement_when_both_agree_risky() -> None:
    """High model probability on an already-risky rule verdict is simple
    agreement: no extra signal, no metadata flag."""
    svc = _service(0.9)
    metadata, extra = svc._ml_opinion(  # noqa: SLF001
        [],
        object_type=ObjectType.URL,
        coverage=1.0,
        pre_ml_verdict=Verdict.HIGH_RISK,
    )
    assert metadata["disagreement"] == "agreement"
    assert extra == []


def test_ml_failure_degrades_to_rule_based_without_crashing() -> None:
    class _BrokenMl:
        def predict_risk(self, vector):  # noqa: ANN001
            raise RuntimeError("model crashed")

    svc = ScanService(ml=_BrokenMl())
    metadata: dict = {}
    assessment, bundle = svc._apply_ml(  # noqa: SLF001
        SignalBundle(),
        object_type=ObjectType.URL,
        coverage=1.0,
        incomplete=False,
        metadata=metadata,
    )
    assert metadata["ml"]["ml_opinion"]["error"] == "model_unavailable"
    assert not any(s.code == "ml.risk_underestimate" for s in bundle)
    assert assessment.verdict == Verdict.SAFE