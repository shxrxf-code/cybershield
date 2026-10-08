"""Risk scoring: the aggregation rules and the honesty guarantees.

Two properties matter more than any individual score:

* **Signals combine, they do not add.**  Ten trivial observations must not reach
  a scary verdict.  If they did, the whole product would be a false-positive
  generator, because trivial observations are the common case.
* **No verdict is ever certainty.**  Confidence is capped below 1.0, and a result
  with no evidence is UNKNOWN rather than SAFE.
"""

from __future__ import annotations

import pytest

from detection_engine import (
    AnalysisResult,
    Finding,
    ObjectType,
    RiskEngine,
    Severity,
    SignalSource,
    Verdict,
    verdict_for_score,
)
from detection_engine.scoring import DEFAULT_DISCLAIMER


def finding(
    severity: Severity = Severity.MEDIUM,
    weight: float | None = None,
    *,
    authoritative: bool = False,
    source: SignalSource = SignalSource.ENGINE,
    category: str = "general",
    index: int = 0,
) -> Finding:
    """A synthetic finding.

    ``index`` varies the code so a caller can model *distinct* observations.
    Findings are deduplicated by code during scoring, so a repetition test that
    reused one code would be measuring the dedupe rather than the decay.
    """
    return Finding(
        code=f"TEST.{severity.value}.{index}",
        title=f"{severity.value} observation",
        detail="A test observation.",
        severity=severity,
        source=source,
        category=category,
        weight=weight,
        authoritative=authoritative,
    )


def result_with(*findings: Finding, incomplete: bool = False) -> AnalysisResult:
    result = AnalysisResult(object_type=ObjectType.BINARY, object_name="test.bin")
    result.findings.extend(findings)
    result.engines_ran = ["test_engine"]
    result.incomplete = incomplete
    return result


@pytest.fixture
def engine() -> RiskEngine:
    return RiskEngine()


# --------------------------------------------------------------------- #
# Banding
# --------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "score,verdict",
    [
        (0.0, Verdict.SAFE),
        (19.9, Verdict.SAFE),
        (20.0, Verdict.LOW_RISK),
        (39.9, Verdict.LOW_RISK),
        (40.0, Verdict.SUSPICIOUS),
        (59.9, Verdict.SUSPICIOUS),
        (60.0, Verdict.HIGH_RISK),
        (79.9, Verdict.HIGH_RISK),
        (80.0, Verdict.MALICIOUS),
        (100.0, Verdict.MALICIOUS),
    ],
)
def test_bands(score: float, verdict: Verdict) -> None:
    assert verdict_for_score(score) is verdict


# --------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------- #


def test_one_strong_signal_outweighs_many_weak_ones(engine: RiskEngine) -> None:
    """The central false-positive brake.

    Twenty INFO findings must score well below a single CRITICAL one.  If they
    did not, an unremarkable file with twenty small oddities would be reported
    as dangerous, and users would learn to ignore the output.
    """
    weak = result_with(*[finding(Severity.INFO, 4.0) for _ in range(20)])
    strong = result_with(finding(Severity.CRITICAL, 100.0))

    weak_score = engine.score(weak).score
    strong_score = engine.score(strong).score
    assert weak_score < 20.0, weak_score
    assert strong_score > weak_score * 3, (weak_score, strong_score)


def test_repetition_inside_a_tier_decays(engine: RiskEngine) -> None:
    """More signals of one severity help, but with shrinking returns.

    The aggregate is noisy-OR, so a second signal always adds something; what
    must not happen is linear growth.  Twenty MEDIUM findings have to be worth
    far less than twenty times one MEDIUM finding, otherwise a file that trips
    many rules in the same class would be reported as twenty separate dangers.
    """
    scores = []
    for count in (1, 5, 20):
        breakdown = engine.score(
            result_with(*[finding(Severity.MEDIUM, 38.0, index=i) for i in range(count)])
        )
        scores.append(breakdown.score)
    assert scores[0] <= scores[1] <= scores[2], scores
    single = scores[0]
    twenty = scores[2]
    assert twenty > single, scores
    assert twenty < single * 2.0, scores


def test_tier_caps_hold(engine: RiskEngine) -> None:
    """No single severity class may claim more than its share of 100."""
    for severity, cap in (
        (Severity.INFO, 4.0),
        (Severity.LOW, 14.0),
        (Severity.MEDIUM, 38.0),
        (Severity.HIGH, 72.0),
    ):
        score = engine.score(
            result_with(*[finding(severity, 100.0) for _ in range(40)])
        ).score
        assert score <= cap + 1e-6, (severity, score, cap)


def test_score_never_exceeds_100(engine: RiskEngine) -> None:
    score = engine.score(
        result_with(*[finding(Severity.CRITICAL, 100.0, authoritative=True) for _ in range(50)])
    ).score
    assert score <= 100.0


def test_source_reliability_damps_weak_engines(engine: RiskEngine) -> None:
    """A signature match outweighs a heuristic at equal severity and weight."""
    signature = engine.score(
        result_with(finding(Severity.HIGH, 50.0, source=SignalSource.CLAMAV))
    ).score
    heuristic = engine.score(
        result_with(finding(Severity.HIGH, 50.0, source=SignalSource.APK_CODE))
    ).score
    assert signature > heuristic


# --------------------------------------------------------------------- #
# Authoritative detections
# --------------------------------------------------------------------- #


def test_critical_authoritative_finding_floors_at_confirmed(engine: RiskEngine) -> None:
    result = engine.score(
        result_with(finding(Severity.CRITICAL, 10.0, authoritative=True))
    )
    assert result.score >= RiskEngine.confirmed_malware_floor
    assert result.floors_applied


def test_authoritative_high_finding_floors_at_malware(engine: RiskEngine) -> None:
    result = engine.score(result_with(finding(Severity.HIGH, 5.0, authoritative=True)))
    assert result.score >= RiskEngine.malware_floor


def test_low_authoritative_finding_gets_no_floor(engine: RiskEngine) -> None:
    """Authoritative does not mean "floored".

    Only a detection that is a confirmed positive may override the aggregate.  A
    debug-signed package is worth reporting, and flooring it into MALICIOUS
    would be the system claiming a certainty it has not earned.
    """
    result = engine.score(result_with(finding(Severity.LOW, 8.0, authoritative=True)))
    assert result.score < RiskEngine.malware_floor
    assert result.verdict is not Verdict.MALICIOUS


# --------------------------------------------------------------------- #
# Coverage and honesty
# --------------------------------------------------------------------- #


def test_incomplete_scan_is_unknown_with_no_score(engine: RiskEngine) -> None:
    """Missing capability must not read as a clean result.

    The numeric score is withheld rather than reported as zero risk, because
    "we looked and found nothing" and "we could not look" are different facts
    and only one of them is safe to display as 0.
    """
    breakdown = engine.score(result_with(incomplete=True))
    assert breakdown.verdict is Verdict.UNKNOWN
    assert breakdown.score == 0.0


def test_confirmed_detection_survives_incomplete_coverage(engine: RiskEngine) -> None:
    """Reduced coverage lowers confidence; it does not retract a detection."""
    breakdown = engine.score(
        result_with(finding(Severity.CRITICAL, 90.0, authoritative=True), incomplete=True)
    )
    assert breakdown.verdict is Verdict.MALICIOUS


def test_confidence_never_reaches_certainty(engine: RiskEngine) -> None:
    for _ in range(30):
        breakdown = engine.score(
            result_with(
                finding(Severity.CRITICAL, 100.0, authoritative=True, category="signature"),
                finding(Severity.CRITICAL, 100.0, authoritative=True, category="integrity"),
                finding(Severity.HIGH, 70.0, category="identity"),
                finding(Severity.HIGH, 70.0, category="behaviour"),
            )
        )
        assert breakdown.confidence < 1.0, breakdown.confidence


def test_confidence_falls_when_coverage_is_missing(engine: RiskEngine) -> None:
    strong = engine.score(
        result_with(finding(Severity.HIGH, 40.0, category="identity"))
    ).confidence
    weak = engine.score(
        result_with(finding(Severity.HIGH, 40.0, category="identity"), incomplete=True)
    ).confidence
    assert strong > weak


def test_every_result_carries_the_caveat(engine: RiskEngine) -> None:
    result = engine.finalise(result_with(finding()))
    assert result.disclaimer == DEFAULT_DISCLAIMER
    assert "false positives" in result.disclaimer
    assert "not a guarantee" in result.disclaimer


def test_breakdown_accounts_for_the_score(engine: RiskEngine) -> None:
    """A score a user cannot interrogate is not actionable.

    Each contribution records the finding that produced it, so the UI can show
    "this is why" next to every number rather than asking for trust.
    """
    result = engine.finalise(
        result_with(
            finding(Severity.HIGH, 40.0, category="identity"),
            finding(Severity.MEDIUM, 20.0, category="structure"),
        )
    )
    assert result.score_breakdown
    for entry in result.score_breakdown:
        assert entry["code"].startswith("TEST.")
        assert entry["weight"] > 0
        assert entry["title"]


def test_empty_result_is_unknown_not_safe(engine: RiskEngine) -> None:
    """No evidence at all must not produce an all-clear."""
    breakdown = engine.score(AnalysisResult(object_type=ObjectType.BINARY))
    assert breakdown.verdict is not Verdict.SAFE