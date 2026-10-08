"""Social-engineering text analysis: urgency, authority, credential and money cues.

The central design rule of this module: **language alone never produces a
malicious verdict.**  Security newsletters, incident-response blogs and phishing
awareness training material all score highly on these lexicons.  Every function
here returns evidence; the caller combines it with structural, sender and
reputation signals before drawing a conclusion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Finding, Severity, SignalSource

__all__ = [
    "TextPhishingProfile",
    "analyze_text",
    "URGENCY_PATTERNS",
    "CREDENTIAL_PATTERNS",
    "FINANCIAL_PATTERNS",
    "AUTHORITY_PATTERNS",
    "THREAT_PATTERNS",
]

# --------------------------------------------------------------------- #
# Pattern lexicons
# --------------------------------------------------------------------- #

URGENCY_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(act|immediately)\b.{0,30}\b(urgent|now|today)\b", "immediate-action demand"),
    (r"\burgent(ly)?\b", "explicit urgency"),
    (r"\bimmediat(e|ely)\b", "immediacy pressure"),
    (r"\bwithin\s+(\d+\s*)?(hours?|minutes?|days?)\b", "short deadline"),
    (r"\bexpires?\b.{0,20}\b(in|within|on)\b", "expiry deadline"),
    (r"\bfinal\s+(notice|warning|reminder)\b", "final-notice framing"),
    (r"\b(last|critical)\s+chance\b", "scarcity pressure"),
    (r"\bdo\s+not\s+delay\b", "delay pressure"),
    (r"\bavoid\s+(account\s+)?(suspension|closure|termination|lock)", "threat of loss"),
    (r"\b(suspend|suspension|suspended|deactivat)", "account-suspension threat"),
    (r"\b(permanently\s+)?(clos|expir|terminat)", "closure threat"),
    (r"\bleft\s+with\s+no\s+(choice|option|alternative)\b", "false urgency"),
)

CREDENTIAL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(verify|confirm|validate)\s+(your\s+)?(account|identity|email|password|credentials|details|information)\b",
     "account-verification request"),
    (r"\b(re-?enter|re-?set|update|change)\s+(your\s+)?(password|passcode|pin|credentials)\b",
     "credential reset request"),
    (r"\bsign\s?in\s+(to|at)\s+.{0,40}\b(verify|confirm|secure)\b", "credential re-entry prompt"),
    (r"\benter\s+(your\s+)?(username|login|email)\s+and\s+password\b", "login form request"),
    (r"\b(provide|supply|enter)\s+(your\s+)?(password|pin|cvv|ssn|social\s+security)\b",
     "sensitive-data request"),
    (r"\b(confirm|provide)\s+(your\s+)?(date\s+of\s+birth|security\s+question)\b", "identity-data request"),
    (r"\bavoid\s+(account\s+)?(deletion|closure)\s+by\b", "deletion-threat plus action"),
    (r"\b(click|tap)\s+(the\s+)?(link|button)\s+(below|here)\b.{0,40}\b(verify|confirm|update|login)\b",
     "link-to-credential-flow"),
    (r"\b(mfa|2fa|otp|one-time\s+(code|password))\b.{0,30}\b(enter|type|provide)\b",
     "one-time-code harvesting"),
    (r"\bseed\s+phrase\b|\brecovery\s+phrase\b|\bprivate\s+key\b.{0,20}\b(wallet|enter|provide)\b",
     "crypto-wallet secret request"),
)

FINANCIAL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(wire\s+transfer|bank\s+transfer|money\s+transfer)\b", "wire-transfer request"),
    (r"\b(gift\s+card|itunes\s+card|google\s+play\s+card|prepaid\s+card)\b", "gift-card payment request"),
    (r"\b(invoice|payment)\s+(is\s+)?(overdue|due|past\s+due|outstanding)\b", "overdue-invoice pressure"),
    (r"\b(refund|reimbursement|compensation)\b.{0,30}\b(claim|provide|confirm|eligible)\b",
     "refund-scam framing"),
    (r"\b(bitcoin|crypto(currency)?|eth(ereum)?|btc|monero|usdt)\b", "cryptocurrency reference"),
    (r"\b(bank|account)\s+details\b.{0,30}\b(update|change|confirm|provide)\b",
     "bank-detail change request"),
    (r"\bpay\s?(pal|now)\b", "payment-processor reference"),
    (r"\b(credit|debit)\s+card\s+(number|details|expiry)\b", "card-data request"),
)

AUTHORITY_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(official|authorized|authorised)\s+(notice|message|department|support)\b", "authority claim"),
    (r"\b(security|compliance|legal|audit|government)\s+(team|department|office|officer)\b",
     "authority impersonation"),
    (r"\b(irs|hmrc|hmv|inland\s+revenue|cisa|fbi|nsa)\b", "government agency reference"),
    (r"\b(bank|your\s+financial\s+institution)\b.{0,30}\b(policy|require|request)", "financial-authority claim"),
    (r"\b(it|technical|support)\s+department\b", "support impersonation"),
    (r"\bdo\s+not\s+reply\b", "no-reply disclaimer"),
    (r"\bthis\s+is\s+(an?\s+)?(automated|automated\s+system|notification|alert)\b",
     "automated-message claim"),
    (r"\bdo\s+not\s+(reply|respond)\s+to\s+this", "no-reply disclaimer"),
)

THREAT_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(legal\s+action|lawsuit|litigation|prosecut)\b", "legal-threat framing"),
    (r"\b(service\s+will\s+be\s+)?(suspend|terminate|deactivate)\w*\b", "service-termination threat"),
    (r"\b(permanent)\s+(deletion|removal|termination)\b", "permanent-deletion threat"),
    (r"\b(unauthorised|unauthorized)\s+(access|attempt|activity)\b", "unauthorised-access scare"),
    (r"\b(we\s+have\s+(detected|identified)|security\s+alert)\b", "breach-notification framing"),
    (r"\bpassword\s+(will\s+be\s+)?expir\w+", "password-expiry scare"),
    (r"\b(unable|unable)\s+to\s+(verify|process)\b", "processing-failure pretext"),
)

#: Compiled once at import time.
_COMPILED: dict[str, list[tuple[re.Pattern[str], str]]] = {
    "urgency": [(re.compile(p, re.IGNORECASE), label) for p, label in URGENCY_PATTERNS],
    "credential": [(re.compile(p, re.IGNORECASE), label) for p, label in CREDENTIAL_PATTERNS],
    "financial": [(re.compile(p, re.IGNORECASE), label) for p, label in FINANCIAL_PATTERNS],
    "authority": [(re.compile(p, re.IGNORECASE), label) for p, label in AUTHORITY_PATTERNS],
    "threat": [(re.compile(p, re.IGNORECASE), label) for p, label in THREAT_PATTERNS],
}

#: Categories whose presence is much more indicative than others.
_CATEGORY_WEIGHT: dict[str, float] = {
    "credential": 18.0,
    "urgency": 10.0,
    "financial": 12.0,
    "threat": 9.0,
    "authority": 6.0,
}


@dataclass(slots=True)
class TextPhishingProfile:
    """Aggregated social-engineering evidence extracted from text."""

    categories: dict[str, list[str]] = field(default_factory=dict)
    matches: dict[str, list[str]] = field(default_factory=dict)
    word_count: int = 0
    sentence_count: int = 0
    exclamation_marks: int = 0
    all_caps_words: int = 0
    urls: list[str] = field(default_factory=list)
    display_names: list[str] = field(default_factory=list)

    @property
    def total_matches(self) -> int:
        return sum(len(v) for v in self.matches.values())

    @property
    def category_score(self) -> float:
        """Weighted count of matched categories, capped so repetition is not free."""
        score = 0.0
        for category, labels in self.matches.items():
            if not labels:
                continue
            base = _CATEGORY_WEIGHT.get(category, 5.0)
            # Diminishing returns: the 5th 'urgent' is not 5x the 1st.
            score += base * (1 + 0.35 * (len(labels) - 1)) if len(labels) > 1 else base
        return min(60.0, score)

    def to_dict(self) -> dict[str, object]:
        return {
            "categories": self.categories,
            "matches": self.matches,
            "word_count": self.word_count,
            "sentence_count": self.sentence_count,
            "exclamation_marks": self.exclamation_marks,
            "all_caps_words": self.all_caps_words,
            "urls": self.urls,
            "category_score": round(self.category_score, 2),
        }


_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'\)\]]+", re.IGNORECASE)
_SENTENCE_RE = re.compile(r"[.!?]+")
_WORD_RE = re.compile(r"[A-Za-z']+")


def analyze_text(text: str, *, max_chars: int = 200_000) -> TextPhishingProfile:
    """Extract social-engineering evidence from *text*."""
    sample = (text or "")[:max_chars]
    profile = TextPhishingProfile()
    profile.word_count = len(_WORD_RE.findall(sample))
    profile.sentence_count = len([s for s in _SENTENCE_RE.split(sample) if s.strip()])
    profile.exclamation_marks = sample.count("!")
    caps_words = re.findall(r"\b[A-Z]{3,}\b", sample)
    # Acronyms like SMS, OTP, KYC are normal; ALL-CAPS words of 5+ letters are not.
    profile.all_caps_words = len([w for w in caps_words if len(w) >= 5])
    profile.urls = sorted({m.rstrip(".,);:") for m in _URL_RE.findall(sample)})

    lowered = sample.lower()
    for category, patterns in _COMPILED.items():
        matched: list[str] = []
        for pattern, label in patterns:
            if pattern.search(lowered) or pattern.search(sample):
                matched.append(label)
        if matched:
            profile.categories[category] = matched
            profile.matches[category] = matched
    return profile


def findings_from_profile(
    profile: TextPhishingProfile, *, source: SignalSource = SignalSource.PHISHING
) -> list[Finding]:
    """Convert a :class:`TextPhishingProfile` into findings.

    Urgency + credential demand together is the classic combo and is scored
    higher than either alone, because security education material usually has
    one without the other.
    """
    findings: list[Finding] = []
    labels = {
        "credential": ("PHISH.CREDENTIAL_REQUEST", "Message requests credentials or sensitive data", Severity.HIGH),
        "urgency": ("PHISH.URGENCY_LANGUAGE", "Message applies time pressure or threatens loss", Severity.MEDIUM),
        "financial": ("PHISH.FINANCIAL_REQUEST", "Message requests money or payment details", Severity.HIGH),
        "threat": ("PHISH.THREATENING_LANGUAGE", "Message uses threats to force compliance", Severity.MEDIUM),
        "authority": ("PHISH.AUTHORITY_CLAIM", "Message claims to be from an authority or support desk", Severity.LOW),
    }
    for category, (code, title, severity) in labels.items():
        matched = profile.matches.get(category)
        if not matched:
            continue
        weight = _CATEGORY_WEIGHT.get(category, 5.0)
        if len(matched) > 1:
            weight *= 1.3
        detail = (
            f"The text contains {len(matched)} indicator(s) in this category: "
            f"{', '.join(sorted(set(matched))[:5])}. "
            "Note that security awareness material also uses this language, so "
            "this must be read together with sender and link evidence."
        )
        findings.append(
            Finding(
                code=code,
                title=title,
                detail=detail,
                severity=severity,
                source=source,
                category="phishing",
                weight=min(30.0, weight),
                evidence={"matches": sorted(set(matched)), "category": category},
            )
        )

    if profile.matches.get("credential") and profile.matches.get("urgency"):
        findings.append(
            Finding(
                code="PHISH.CREDENTIAL_PLUS_URGENCY",
                title="Credential request combined with time pressure",
                detail=(
                    "The message demands credentials or sensitive data *and* applies "
                    "urgent or threatening language. Legitimate organisations do not "
                    "combine the two: no real provider will lose your account "
                    "because you did not re-enter your password within minutes."
                ),
                severity=Severity.HIGH,
                source=source,
                category="phishing",
                weight=25.0,
                evidence={
                    "credential": sorted(set(profile.matches.get("credential", []))),
                    "urgency": sorted(set(profile.matches.get("urgency", []))),
                },
            )
        )

    if profile.exclamation_marks >= 4:
        findings.append(
            Finding(
                code="PHISH.EXCESSIVE_EXCLAMATION",
                title="Heavy use of exclamation marks",
                detail=(
                    f"{profile.exclamation_marks} exclamation marks were found. "
                    "Strong emotional arousal is a documented persuasion tactic in "
                    "social-engineering campaigns."
                ),
                severity=Severity.INFO,
                source=source,
                category="phishing",
                weight=4.0,
                evidence={"count": profile.exclamation_marks},
            )
        )
    return findings