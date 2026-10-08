"""Transparent risk scoring engine.

Why this is not a sum
---------------------
Naively adding weights breaks down badly: twenty trivial "informational"
observations would outrank a single authoritative antivirus detection, and a
phishing message could not exceed a threshold no matter how strong its evidence.
This engine instead:

1. Groups signals into **categories** and collapses each category with a noisy-OR
   combination, so repeated weak signals inside one category saturate instead of
   accumulating without bound.
2. Applies a **category budget**: a URL can never exceed the risk implied by its
   categories alone, so structural oddities alone cannot reach ``MALICIOUS``.
3. Applies documented **escalation floors** when authoritative sources
   (antivirus, threat intelligence, YARA) confirm compromise, so a confirmed
   detection is never diluted by weak signals.
4. Applies **mitigation** when strong evidence of legitimacy exists.
5. Reports **confidence** separately from score, and lowers it when evidence is
   thin or sources disagree. The score is never presented as certainty.

Every step is reported in :class:`RiskBreakdown` so the result is explainable in
the UI and reproducible in the documentation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from app.schemas.common import (
    ObjectType,
    Recommendation,
    Recommendation as Rec,
    Severity,
    SignalSource,
    Verdict,
    verdict_for_score,
)
from app.schemas.signal import DetectionSignal, SignalBundle

# ---------------------------------------------------------------------------
# Category budgets
# ---------------------------------------------------------------------------
# The value is the maximum share of the final score a category may contribute,
# expressed in score points (0-100). Signals inside a category share that budget.
# A category with no signals contributes 0.
CATEGORY_BUDGET: dict[str, float] = {
    "malware_detection": 62.0,   # antivirus engine verdict
    "threat_intelligence": 58.0, # curated reputation feeds
    "signature": 52.0,           # YARA / rule matches
    "reputation": 45.0,
    "authentication": 34.0,     # SPF/DKIM/DMARC and certificate checks
    "deception": 30.0,
    "impersonation": 30.0,
    "social_engineering": 28.0,
    "static_analysis": 27.0,
    "structural": 26.0,
    "lexical": 16.0,
    "obfuscation": 16.0,
    "transport": 12.0,
    "reputation_context": 10.0,
    "transparency": 8.0,
    "machine_learning": 14.0,
    "policy": 20.0,
    "scanner_health": 0.0,       # never raises risk, only confidence
}

# Signals in these categories are only meaningful in combination with others.
NON_AUTHORITATIVE_CATEGORIES: frozenset[str] = frozenset(
    {"lexical", "obfuscation", "transport", "reputation_context", "transparency", "structural"}
)

# ---------------------------------------------------------------------------
# Escalation floors
# ---------------------------------------------------------------------------
# (signal source, minimum category severity) -> score floor.
ESCALATION_FLOORS: tuple[tuple[SignalSource, Severity, float, str], ...] = (
    (
        SignalSource.ANTIVIRUS,
        Severity.CRITICAL,
        92.0,
        "An antivirus engine classified this object as malware.",
    ),
    (
        SignalSource.THREAT_INTELLIGENCE,
        Severity.CRITICAL,
        90.0,
        "Threat intelligence confirmed this object is malicious.",
    ),
    (
        SignalSource.YARA,
        Severity.CRITICAL,
        86.0,
        "A YARA rule matched a known malware family pattern.",
    ),
    (
        SignalSource.ANTIVIRUS,
        Severity.HIGH,
        78.0,
        "An antivirus engine flagged this object as suspicious or heuristically malicious.",
    ),
    (
        SignalSource.THREAT_INTELLIGENCE,
        Severity.HIGH,
        74.0,
        "Threat intelligence matched this object against a known malicious feed.",
    ),
)

#: High-precision structural detections that are decisive on their own.
#:
#: Unlike a noisy heuristic, each of these is a *positive identification* rather
#: than an absence of reassuring evidence: the domain is an exact match for a
#: curated typosquat of a major brand, or it resolves to a hostname built from a
#: different writing system that spells a brand when decoded. False-positive
#: rates for such curated lists are near zero because the lists are small and
#: specific, so these bypass the category budget and corroboration multiplier
#: exactly as an antivirus detection would.
PRECISE_DETECTION_FLOORS: dict[str, tuple[float, str]] = {
    "phish.typosquatting": (
        68.0,
        "The hostname is a deliberate misspelling of a major brand's domain.",
    ),
    "phish.homograph_domain": (
        68.0,
        "The hostname uses characters from another writing system to imitate a trusted brand.",
    ),
    "url.credential_deception_ip": (
        72.0,
        "The URL supplies apparent credentials in front of an IP address host, so the visible "
        "text names a trusted host while the browser connects elsewhere.",
    ),
    "url.double_extension": (
        48.0,
        "The filename masks an executable type behind a document type (for example "
        "'invoice.pdf.exe'), which exists only to make running code look like opening a file.",
    ),
    "pdf.javascript": (62.0, "The PDF contains active script content."),
    "document.dde_execution": (
        70.0,
        "The document contains DDE command execution fields that need no macro to run code.",
    ),
    "archive.hidden_executable": (
        66.0,
        "An archive member is executable code despite its filename, which is the core mechanism "
        "of archive-delivered malware.",
    ),
    "document.auto_execute_macro": (
        70.0,
        "The document defines macros that execute automatically when the file is opened.",
    ),
}

#: Floors applied when a precise detection is present but a stronger signal
#: already set the score. Kept separate so the report can name the specific
#: decisive finding rather than the generic category.
_PRECISE_FLOOR_VARIANTS: dict[str, tuple[float, str]] = {
    "phish.typosquatting": (78.0, "Typosquatting of a major brand's domain."),
    "phish.homograph_domain": (
        78.0,
        "Homograph domain imitating a trusted brand using foreign characters.",
    ),
    "phish.brand_impersonation": (
        56.0,
        "The URL impersonates a recognised brand from a domain that brand does not own.",
    ),
}

# ---------------------------------------------------------------------------
# Composite-pattern floors
# ---------------------------------------------------------------------------
#: Named, documented *combinations* of findings that are more diagnostic than the
#: sum of their parts, because the combination is what the attack needs.
#:
#: Each entry is a set of signal codes that must **all** be present; the floor is
#: applied only when every listed code is matched. This exists because individual
#: social-engineering signals are individually cheap - "urgent" and "wire transfer"
#: each appear in ordinary business mail - while their co-occurrence is the
#: published signature of business email compromise (BEC), which the FBI treats as
#: a multi-billion-dollar loss category. Without this rule the per-category budget
#: is right to keep the total low, and the result under-reports a real attack.
COMBINATION_FLOORS: tuple[tuple[frozenset[str], float, str], ...] = (
    (
        frozenset(
            {
                "phish.secrecy_request",
                "phish.financial_request",
                "phish.urgency_language",
            }
        ),
        48.0,
        "Business email compromise pattern: an urgent request to move money while asking the "
        "recipient to keep it secret from colleagues.",
    ),
    (
        frozenset({"phish.credential_request", "phish.secrecy_request", "phish.urgency_language"}),
        45.0,
        "Credential-harvesting pattern: an urgent request for login details that must be kept "
        "secret and must not be verified through normal channels.",
    ),
    (
        frozenset({"phish.authority_impersonation", "phish.secrecy_request"}),
        44.0,
        "An impersonated authority is instructing the recipient to conceal the request, which "
        "defeats the internal verification that usually catches fraud.",
    ),
)

#: Signals that demonstrate legitimacy and reduce the score.
MITIGATING_CATEGORIES: dict[str, float] = {
    "legitimacy": 12.0,  # maximum reduction available from positive evidence
}

#: Each additional *independent* category multiplies the base score. Corroboration
#: across unrelated detector families is far stronger evidence than repeated
#: findings within one family, which is what the per-category saturation models.
_CORROBORATION_STEP = 0.55
_MAX_CORROBORATION = 3.2


@dataclass
class CategoryContribution:
    """Per-category scoring detail for the report."""

    category: str
    budget: float
    raw_score: float
    score: float
    signal_count: int
    top_signal: str | None = None

    @property
    def utilisation(self) -> float:
        return round(self.score / self.budget, 4) if self.budget > 0 else 0.0


@dataclass
class RiskBreakdown:
    """Full, human-auditable explanation of how a score was produced."""

    category_contributions: list[CategoryContribution] = field(default_factory=list)
    precise_detections: list[str] = field(default_factory=list)
    composite_patterns: list[str] = field(default_factory=list)
    corroborated_by: list[str] = field(default_factory=list)
    independent_categories: int = 0
    corroboration_factor: float = 1.0
    heuristic_ceiling_applied: float | None = None
    escalated_to: float | None = None
    escalation_reason: str | None = None
    mitigation_applied: float = 0.0
    mitigation_reason: str | None = None
    authoritative_source_count: int = 0
    heuristic_source_count: int = 0
    coverage: float = 1.0
    agreement_penalty: float = 0.0

    def top_contributions(self, limit: int = 5) -> list[CategoryContribution]:
        return sorted(self.category_contributions, key=lambda c: c.score, reverse=True)[:limit]


@dataclass
class RiskAssessment:
    """Final scored outcome."""

    score: float
    verdict: Verdict
    confidence: float
    reasons: list[str]
    recommendation: Recommendation
    recommendation_text: str
    breakdown: RiskBreakdown
    signals: list[DetectionSignal]

    @property
    def is_confidently_malicious(self) -> bool:
        return self.verdict is Verdict.MALICIOUS and self.confidence >= 0.6


def _noisy_or(impacts: list[float]) -> float:
    """Combine independent evidence: 1 - Π(1 - x).

    Saturating at 1.0 is the desired property: ten weak observations cannot
    exceed the strength of one strong one, so noisy detectors cannot inflate risk.
    """
    if not impacts:
        return 0.0
    survival = 1.0
    for impact in impacts:
        survival *= 1.0 - min(0.99, max(0.0, impact))
    return 1.0 - survival


def _redundancy_discount(distinct_codes: int) -> float:
    """Discount *repeated detector types*, not merely repeated findings.

    Ten variations of one detector's output must not outrank three independent
    findings, so the discount keys on the number of **distinct** signal codes.
    Distinct codes within a category represent genuinely different techniques -
    urgency, secrecy, authority abuse and a wire-transfer request are four
    separate social-engineering levers, not four restatements of one - so the
    discount is deliberately gentle (logarithmic) rather than steep.
    """
    if distinct_codes <= 1:
        return 1.0
    return 1.0 / (1.0 + 0.12 * math.log(distinct_codes, 2))


def assess_risk(
    bundle: SignalBundle | list[DetectionSignal],
    *,
    object_type: ObjectType = ObjectType.UNKNOWN,
    scanner_coverage: float = 1.0,
    analysis_incomplete: bool = False,
) -> RiskAssessment:
    """Score a signal bundle into a verdict with confidence and explanation.

    Args:
        bundle: Signals emitted by the analysis pipeline.
        object_type: Used to select the recommendation wording.
        scanner_coverage: 0-1 fraction of expected checks that actually ran. Low
            coverage must reduce confidence, never inflate the score.
        analysis_incomplete: When True and nothing authoritative fired, the result
            is forced to ``UNKNOWN`` rather than implying an all-clear.
    """
    signals = bundle.deduplicate() if isinstance(bundle, SignalBundle) else list(bundle)
    breakdown = RiskBreakdown(coverage=max(0.0, min(1.0, scanner_coverage)))

    if not signals:
        return RiskAssessment(
            score=0.0,
            verdict=Verdict.UNKNOWN if analysis_incomplete else Verdict.SAFE,
            confidence=0.35 if analysis_incomplete else 0.55,
            reasons=(
                ["No detectors produced a finding; analysis coverage was incomplete."]
                if analysis_incomplete
                else ["No malicious indicators were detected by any available detector."]
            ),
            recommendation=Rec.MANUAL_REVIEW if analysis_incomplete else Rec.NONE,
            recommendation_text="",
            breakdown=breakdown,
            signals=[],
        )

    # -- 1. Group into categories -------------------------------------
    grouped: dict[str, list[DetectionSignal]] = {}
    for signal in signals:
        if signal.category in MITIGATING_CATEGORIES:
            continue
        grouped.setdefault(signal.category, []).append(signal)

    base_score = 0.0
    for category, category_signals in grouped.items():
        budget = CATEGORY_BUDGET.get(category, 15.0)
        impacts = [signal.impact for signal in category_signals]
        collapsed = _noisy_or(impacts)
        discount = _redundancy_discount(len({s.code for s in category_signals}))
        contribution = budget * collapsed * discount
        base_score += contribution

        strongest = max(category_signals, key=lambda s: s.impact)
        breakdown.category_contributions.append(
            CategoryContribution(
                category=category,
                budget=budget,
                raw_score=round(contribution, 2),
                score=round(contribution, 2),
                signal_count=len(category_signals),
                top_signal=strongest.title,
            )
        )

    # -- 2. Corroboration ---------------------------------------------
    # Independent detectors agreeing is the strongest available evidence of a
    # real threat, and is far more informative than one detector being louder.
    # A single category therefore cannot escalate on its own, while several
    # independent categories quickly can.
    category_count = len(grouped)
    corroboration = min(_MAX_CORROBORATION, 1.0 + _CORROBORATION_STEP * (category_count - 1))
    breakdown.corroboration_factor = round(corroboration, 3)
    breakdown.independent_categories = category_count

    raw_score = min(100.0, base_score * corroboration)

    # Heuristic and model evidence alone may not escalate to HIGH_RISK or above:
    # those bands require authoritative corroboration (antivirus, threat
    # intelligence or YARA), which is what escalation floors below enforce.
    breakdown.corroborated_by = sorted(grouped.keys())

    has_authoritative = any(s.is_authoritative for s in signals)
    if not has_authoritative:
        heuristic_ceiling = 78.0
        if raw_score > heuristic_ceiling:
            breakdown.heuristic_ceiling_applied = heuristic_ceiling
            raw_score = heuristic_ceiling

    # -- 2. Mitigation ------------------------------------------------
    mitigation = 0.0
    legitimacy = [s for s in signals if s.category in MITIGATING_CATEGORIES]
    if legitimacy:
        mitigation = min(
            MITIGATING_CATEGORIES["legitimacy"],
            sum(s.impact * 4.0 for s in legitimacy),
        )
        raw_score = max(0.0, raw_score - mitigation)
        breakdown.mitigation_applied = round(mitigation, 2)
        breakdown.mitigation_reason = "Positive evidence of legitimacy reduced the score."

    # -- 3. Escalation floors -----------------------------------------
    escalated_to: float | None = None
    escalation_reason: str | None = None

    # 3a. Precise structural detections are decisive on their own.
    matched_precise: list[tuple[float, str]] = []
    for code, (floor, reason) in PRECISE_DETECTION_FLOORS.items():
        if any(s.code == code for s in signals):
            matched_precise.append((floor, reason))
    for code, (floor, reason) in _PRECISE_FLOOR_VARIANTS.items():
        if any(s.code == code for s in signals):
            matched_precise.append((floor, reason))

    if matched_precise:
        matched_precise.sort(key=lambda item: item[0], reverse=True)
        best_floor, best_reason = matched_precise[0]
        if raw_score < best_floor:
            escalated_to = best_floor
            escalation_reason = best_reason
            raw_score = best_floor
        breakdown.precise_detections = sorted(
            reason for _floor, reason in matched_precise
        )[:5]

    # 3b. Documented combinations of findings escalate on their own.
    present_codes = {s.code for s in signals}
    matched_combinations = [
        (floor, reason)
        for required, floor, reason in COMBINATION_FLOORS
        if required <= present_codes
    ]
    for floor, reason in sorted(matched_combinations, key=lambda item: item[0], reverse=True):
        breakdown.composite_patterns.append(reason)
        if raw_score < floor:
            escalated_to = floor
            escalation_reason = reason
            raw_score = floor

    # 3c. Authoritative external sources escalate above their floor.
    for source, severity, floor, reason in ESCALATION_FLOORS:
        if any(s.source is source and s.severity.rank >= severity.rank for s in signals):
            if raw_score < floor:
                escalated_to = floor
                escalation_reason = reason
                raw_score = floor
            break

    if escalated_to is not None:
        breakdown.escalated_to = escalated_to
        breakdown.escalation_reason = escalation_reason

    score = round(max(0.0, min(100.0, raw_score)), 1)

    # -- 4. Source accounting and agreement ---------------------------
    authoritative = {s.source for s in signals if s.is_authoritative}
    breakdown.authoritative_source_count = len(authoritative)
    breakdown.heuristic_source_count = len(
        {s.source for s in signals if not s.is_authoritative}
    )

    # Authoritative + heuristic disagreement lowers confidence.
    authoritative_alarm = any(
        s.is_authoritative and s.severity.rank >= Severity.HIGH.rank for s in signals
    )
    strong_heuristic_only = (
        not authoritative_alarm
        and all(s.category in NON_AUTHORITATIVE_CATEGORIES for s in signals)
        and score >= 40
    )
    if strong_heuristic_only:
        breakdown.agreement_penalty = 0.15
        breakdown.authoritative_source_count = 0

    verdict = verdict_for_score(score)

    # -- 5. Confidence ------------------------------------------------
    confidence = _compute_confidence(
        signals=signals,
        coverage=breakdown.coverage,
        breakdown=breakdown,
    )

    # -- 6. UNKNOWN handling ------------------------------------------
    if analysis_incomplete and not authoritative:
        verdict = Verdict.UNKNOWN
        breakdown.mitigation_applied = 0.0
        if raw_score < 1.0:
            raw_score = 1.0
        score = round(max(score, 1.0), 1)
        confidence = min(confidence, 0.3)

    reasons = _build_reasons(signals, verdict, breakdown, analysis_incomplete)
    recommendation = _recommend(verdict, signals, object_type)

    from app.schemas.common import RECOMMENDATION_TEXT

    return RiskAssessment(
        score=score,
        verdict=verdict,
        confidence=confidence,
        reasons=reasons,
        recommendation=recommendation,
        recommendation_text=RECOMMENDATION_TEXT[recommendation],
        breakdown=breakdown,
        signals=signals,
    )


def _compute_confidence(
    *,
    signals: list[DetectionSignal],
    coverage: float,
    breakdown: RiskBreakdown,
) -> float:
    """Confidence in the verdict, in (0, 1). Never returns 1.0."""
    confidence = 0.30

    # Independent authoritative sources are the strongest confidence driver.
    confidence += 0.22 * min(breakdown.authoritative_source_count, 2)

    # Volume and quality of evidence.
    distinct_categories = len({s.category for s in signals})
    confidence += 0.05 * min(distinct_categories, 6)

    high_confidence_signals = sum(1 for s in signals if s.confidence >= 0.75)
    confidence += 0.03 * min(high_confidence_signals, 5)

    # Independent detector families (AV, TI, YARA are genuinely independent).
    families = len({s.source for s in signals})
    confidence += 0.04 * min(families, 4)

    # Detector coverage: an incomplete pipeline cannot be confident.
    confidence *= 0.45 + 0.55 * max(0.0, min(1.0, coverage))

    # Disagreement between authoritative and heuristic evidence.
    confidence -= breakdown.agreement_penalty

    return round(max(0.05, min(0.99, confidence)), 3)


def _build_reasons(
    signals: list[DetectionSignal],
    verdict: Verdict,
    breakdown: RiskBreakdown,
    analysis_incomplete: bool,
) -> list[str]:
    """Produce the ordered, human-readable explanation shown in the report."""
    reasons: list[str] = []

    if breakdown.escalation_reason:
        reasons.append(breakdown.escalation_reason)

    if breakdown.corroborated_by:
        reasons.append(
            "Corroborated by "
            f"{len(breakdown.corroborated_by)} independent checks: "
            + ", ".join(breakdown.corroborated_by[:6])
            + "."
        )

    ranked = sorted(signals, key=lambda s: (s.is_authoritative, s.impact), reverse=True)
    seen_titles: set[str] = set()
    for signal in ranked:
        if signal.title in seen_titles:
            continue
        seen_titles.add(signal.title)
        prefix = "" if signal.is_authoritative else ""
        reasons.append(f"{prefix}{signal.title}: {signal.description}")
        if len(reasons) >= (6 if verdict in (Verdict.SAFE, Verdict.LOW_RISK) else 10):
            break

    if breakdown.mitigation_applied > 0 and verdict in (Verdict.SAFE, Verdict.LOW_RISK):
        reasons.append(breakdown.mitigation_reason or "Positive legitimacy evidence applied.")

    if verdict is Verdict.SAFE and not reasons:
        reasons.append(
            "No malicious indicators were detected. This does not guarantee the object is safe."
        )
    if verdict is Verdict.UNKNOWN and analysis_incomplete:
        reasons.append(
            "The analysis could not be completed, so no reliable conclusion is possible. "
            "Manual review is recommended."
        )
    return reasons


def _recommend(
    verdict: Verdict, signals: list[DetectionSignal], object_type: ObjectType
) -> Recommendation:
    """Map verdict plus object type onto the standard recommended action."""
    if verdict is Verdict.MALICIOUS:
        if object_type is ObjectType.APK:
            return Rec.DO_NOT_INSTALL
        if object_type is ObjectType.URL:
            return Rec.BLOCK
        if object_type in (ObjectType.FILE, ObjectType.ARCHIVE, ObjectType.DOCUMENT, ObjectType.IMAGE):
            return Rec.DELETE
        if object_type is ObjectType.EMAIL:
            return Rec.VERIFY_SENDER
        return Rec.DELETE

    if verdict is Verdict.HIGH_RISK:
        if object_type is ObjectType.URL:
            return Rec.BLOCK
        if object_type is ObjectType.APK:
            return Rec.QUARANTINE
        if object_type is ObjectType.EMAIL:
            return Rec.DO_NOT_OPEN
        return Rec.QUARANTINE

    if verdict is Verdict.SUSPICIOUS:
        if object_type is ObjectType.URL:
            return Rec.BLOCK
        if object_type is ObjectType.EMAIL:
            return Rec.VERIFY_SENDER
        return Rec.DO_NOT_DOWNLOAD

    if verdict is Verdict.LOW_RISK:
        return Rec.MONITOR

    if verdict is Verdict.UNKNOWN:
        return Rec.MANUAL_REVIEW

    return Rec.NONE