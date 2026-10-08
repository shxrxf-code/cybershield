"""Transparent, explainable risk scoring.

Design goals
------------
1. **Never blindly add weights.**  Naive summation lets a pile of trivial
   heuristic observations accumulate into a MALICIOUS verdict, which is the main
   source of false positives.  We combine signals with a *damped* (noisy-OR)
   aggregation so that a single strong signal dominates while weak signals only
   nudge the score.
2. **Authoritative detections win.**  A confirmed antivirus signature or
   threat-intelligence match raises a score *floor* - we do not want a broken
   heuristic pipeline to talk down a confirmed detection.
3. **Explain everything.**  Every point of score is attributable to a
   :class:`~detection_engine.models.Finding`, and the contributions are returned
   in :attr:`AnalysisResult.score_breakdown`.
4. **Honest confidence.**  Confidence reflects *evidence coverage* and
   *signal agreement*, is clamped below 1.0, and collapses when engines are
   missing.  We never claim certainty.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import (
    AnalysisResult,
    Finding,
    Severity,
    Verdict,
    verdict_for_score,
)

__all__ = ["RiskEngine", "ScoreBreakdown", "DEFAULT_DISCLAIMER"]

DEFAULT_DISCLAIMER = (
    "Automated static analysis can produce false positives and false negatives. "
    "This verdict is decision support, not a guarantee."
)

#: Minimum number of independent signal *categories* required before we are
#: willing to state a low-risk confidence.
_SATURATION_CATEGORY_COUNT = 3

#: Weights below this are treated as noise and dropped from the breakdown.
_NOISE_FLOOR = 0.5

#: ``severity -> (tier_cap, per_finding_decay)``.
#:
#: ``cap``    maximum share of the 0-100 score a severity class may claim in
#:            total.  This is the main false-positive brake: informational
#:            observations can never, on their own, produce a scary verdict.
#: ``decay``  geometric multiplier applied for each further finding in the same
#:            class, so repetition within a class buys progressively less.
TIER_CONFIG: dict[Severity, tuple[float, float]] = {
    Severity.CRITICAL: (100.0, 0.85),
    Severity.HIGH: (72.0, 0.65),
    Severity.MEDIUM: (38.0, 0.45),
    Severity.LOW: (14.0, 0.30),
    Severity.INFO: (4.0, 0.20),
}


@dataclass(slots=True)
class ScoreBreakdown:
    """Ordered explanation of how a final score was reached."""

    score: float
    verdict: Verdict
    confidence: float
    contributions: list[dict[str, object]]
    floors_applied: list[str]
    coverage: float

    def as_dict(self) -> dict[str, object]:
        return {
            "score": round(self.score, 1),
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 3),
            "contributions": self.contributions,
            "floors_applied": self.floors_applied,
            "coverage": round(self.coverage, 3),
        }


class RiskEngine:
    """Aggregates findings into a 0-100 risk score, verdict and confidence.

    The engine is stateless and safe to share across threads/requests.
    """

    #: Score floors enforced by authoritative findings.
    malware_floor = 80.0
    confirmed_malware_floor = 90.0

    def finalise(self, result: AnalysisResult) -> AnalysisResult:
        """Populate ``score``/``verdict``/``confidence``/``score_breakdown``."""
        breakdown = self.score(result)
        result.score = breakdown.score
        result.verdict = breakdown.verdict
        result.confidence = breakdown.confidence
        result.score_breakdown = breakdown.contributions
        if not result.disclaimer:
            result.disclaimer = DEFAULT_DISCLAIMER
        return result

    # ------------------------------------------------------------------ #
    # Public scoring API
    # ------------------------------------------------------------------ #

    def score(self, result: AnalysisResult) -> ScoreBreakdown:
        findings = [f for f in result.findings if f.effective_weight > _NOISE_FLOOR]
        contributions = self._contributions(findings)
        raw_score = self._aggregate(contributions)

        floors: list[str] = []
        score = raw_score
        for finding in findings:
            if not finding.authoritative:
                continue
            floor = self._floor_for(finding)
            if floor > score:
                score = floor
                floors.append(
                    f"{finding.title} - confirmed detection raised the minimum "
                    f"risk score to {floor:.0f}"
                )
            elif floor <= 0.0:
                # Recorded so the breakdown can show that an authoritative
                # finding was weighed on its own merits rather than floored.
                floors.append(
                    f"{finding.title} - authoritative, scored on its own weight "
                    f"rather than a floor, because {finding.severity.value} "
                    "detections are not confirmed positives"
                )

        score = round(max(0.0, min(100.0, score)), 1)

        # An authoritative detection is a confirmed positive: it must never be
        # downgraded to UNKNOWN because some *other* engine was unavailable.
        # Reduced coverage lowers confidence, it does not retract a detection.
        has_authoritative = any(f.authoritative for f in findings)

        # No engine ran at all is a coverage gap the analyser did not record.
        # Treating "nothing looked" as "nothing found" is the single most
        # dangerous default this engine could have, so it is caught here rather
        # than trusted to every caller.
        ran_nothing = not result.engines_ran and not findings
        incomplete = (result.incomplete or ran_nothing) and not has_authoritative

        verdict = Verdict.UNKNOWN if incomplete else verdict_for_score(score)
        if verdict is Verdict.UNKNOWN:
            # Insufficient evidence must not read as "clean", so the numeric score
            # is withheld rather than reported as zero risk.
            score = 0.0
        coverage = self._coverage(result, findings)
        confidence = self._confidence(result, findings, score, verdict, coverage)

        return ScoreBreakdown(
            score=score,
            verdict=verdict,
            confidence=confidence,
            contributions=contributions,
            floors_applied=floors,
            coverage=coverage,
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _contributions(self, findings: list[Finding]) -> list[dict[str, object]]:
        """Turn findings into ordered, tier-damped contribution records.

        Findings are grouped by severity.  Within a tier each additional finding
        is damped geometrically and the tier total is capped, giving two
        properties we need:

        * one very strong signal is never diluted by a crowd of weak ones;
        * a pile of trivial observations cannot climb out of its tier's cap, so
          "10 x LOW" can never read like "1 x CRITICAL".

        ``TIER_CONFIG`` holds ``(cap, decay)`` per severity.
        """
        ordered = sorted(
            findings,
            key=lambda f: (f.severity.rank, f.effective_weight),
            reverse=True,
        )
        tier_used: dict[Severity, float] = {}
        tier_index: dict[Severity, int] = {}
        records: list[dict[str, object]] = []
        seen: set[str] = set()
        for finding in ordered:
            weight = finding.effective_weight
            duplicate = finding.code in seen
            seen.add(finding.code)
            cap, decay = TIER_CONFIG[finding.severity]
            if duplicate:
                # The same observation twice is one observation.  Counting it
                # again would let a generator that emits a finding per matched
                # pattern manufacture any score it liked, and it would also let
                # one duplicated rule breach its tier's cap.
                clamped = 0.0
            else:
                rank = tier_index.get(finding.severity, 0)
                damped = weight * (decay**rank)
                clamped = max(
                    0.0, min(damped, cap - tier_used.get(finding.severity, 0.0))
                )
                tier_index[finding.severity] = rank + 1
                tier_used[finding.severity] = tier_used.get(finding.severity, 0.0) + clamped
            records.append(
                {
                    "code": finding.code,
                    "title": finding.title,
                    "detail": finding.detail,
                    "severity": finding.severity.value,
                    "source": finding.source.value,
                    "category": finding.category,
                    "weight": round(weight, 2),
                    "damped_weight": round(clamped, 2),
                    "duplicate": duplicate,
                    "authoritative": finding.authoritative,
                }
            )
        return records

    @staticmethod
    def _aggregate(contributions: list[dict[str, object]]) -> float:
        """Damped noisy-OR combination.

        ``score = 100 * (1 - Π(1 - w_i / 100))``

        Properties we rely on:

        * Monotonic: adding evidence never lowers the score.
        * Bounded: always < 100 unless a floor is applied.
        * Non-additive: 10 x weight-10 findings yield ~65, not 100.
        """
        complement = 1.0
        for record in contributions:
            if record.get("duplicate"):
                continue
            w = float(record["damped_weight"])  # type: ignore[arg-type]
            complement *= max(0.0, 1.0 - min(1.0, w / 100.0))
        return 100.0 * (1.0 - complement)

    @staticmethod
    def _floor_for(finding: Finding) -> float:
        """Minimum score implied by an authoritative detection.

        Only a CRITICAL authoritative finding reaches the confirmed-malware
        floor.  An authoritative HIGH floors at the malware floor; anything lower
        gets no floor at all, because a floor means "this detection cannot be
        talked down", and that is only true of a detection that is a confirmed
        positive.  A debug-signed package is a real, useful finding, but flooring
        it into MALICIOUS would be the system claiming certainty it has not
        earned.
        """
        if finding.severity is Severity.CRITICAL:
            return RiskEngine.confirmed_malware_floor
        if finding.severity is Severity.HIGH:
            return RiskEngine.malware_floor
        return 0.0

    @staticmethod
    def _coverage(result: AnalysisResult, findings: list[Finding]) -> float:
        """Fraction of expected signal families that produced evidence.

        Coverage is about *how much we actually inspected*, not how scary the
        result is.  A clean scan with full coverage is high-confidence SAFE; a
        clean scan with no engines is UNKNOWN.
        """
        expected = _expected_categories(result)
        if not expected:
            return 0.0
        observed = {str(f.category) for f in findings}
        return min(1.0, len(observed & expected) / len(expected))

    @staticmethod
    def _confidence(
        result: AnalysisResult,
        findings: list[Finding],
        score: float,
        verdict: Verdict,
        coverage: float,
    ) -> float:
        """Blend coverage, engine availability and signal agreement."""
        if verdict is Verdict.UNKNOWN:
            return 0.1

        engine_factor = min(1.0, len(result.engines_ran) / 3.0)
        # Agreement: how many *distinct categories* contributed.  One lonely
        # heuristic should not be reported as a confident verdict.
        categories = {f.category for f in findings}
        spread = min(1.0, len(categories) / _SATURATION_CATEGORY_COUNT)
        # Authoritative evidence is worth more than heuristics.
        authority = 1.0 if any(f.authoritative for f in findings) else 0.85
        # Distance from the nearest threshold means the verdict is not marginal.
        from .models import VERDICT_THRESHOLDS

        distances = [abs(score - t) for t, _ in VERDICT_THRESHOLDS]
        margin = min(1.0, max(distances) / 20.0)

        confidence = 0.30 + 0.30 * coverage + 0.15 * engine_factor + 0.10 * spread + 0.10 * margin
        confidence *= authority
        if result.incomplete:
            confidence *= 0.5
        # Hard ceiling: never claim certainty.
        return round(max(0.05, min(0.97, confidence)), 3)


def _expected_categories(result: AnalysisResult) -> set[str]:
    """Signal families that *should* have produced evidence for this object type."""
    from .models import ObjectType

    table: dict[ObjectType, set[str]] = {
        ObjectType.URL: {"syntax", "network", "reputation", "phishing", "certificate"},
        ObjectType.EMAIL: {"auth", "structure", "phishing", "links", "attachments"},
        ObjectType.IMAGE: {"integrity", "metadata", "structure", "payload"},
        ObjectType.DOCUMENT: {"integrity", "structure", "payload", "metadata"},
        ObjectType.ARCHIVE: {"integrity", "structure", "payload"},
        ObjectType.APK: {"integrity", "permissions", "code", "certificate", "reputation"},
        ObjectType.TEXT: {"structure", "phishing"},
        ObjectType.BINARY: {"integrity", "payload"},
        ObjectType.UNKNOWN: {"integrity"},
    }
    return table.get(result.object_type, {"integrity"})