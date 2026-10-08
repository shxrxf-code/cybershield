"""Domain intelligence: impersonation, typosquatting, TLD risk and registration age.

No single check here is conclusive.  Brand similarity in particular produces a
steady stream of false positives (a security blog legitimately discussing
``apple.com``), so findings are weighted low and always require corroboration
from reputation, TLS or redirect analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from ..constants import (
    IMPERSONATED_BRANDS,
    PHISHING_PRONE_TLDS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)
from ..models import Finding, Severity, SignalSource
from .dga import GeneratedDomainProfile
from .normalizer import ParsedUrl

__all__ = ["BrandMatch", "analyze_domain", "levenshtein", "domain_age_verdict"]

_VOWELS = set("aeiou")


def levenshtein(left: str, right: str) -> int:
    """Classic edit distance (insert/delete/substitute)."""
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, lchar in enumerate(left, start=1):
        current = [i]
        for j, rchar in enumerate(right, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            substitute = previous[j - 1] + (lchar != rchar)
            current.append(min(insert, delete, substitute))
        previous = current
    return previous[-1]


def _ratio(left: str, right: str) -> float:
    return SequenceMatcher(None, left, right).ratio()


#: Keyboard adjacency, used to explain likely typo intent.
_KEYBOARD_NEIGHBOURS = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
    "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "i": "ujko", "j": "huikmn",
    "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu",
    "z": "asx",
}


def _strip_suffix(host: str) -> str:
    return host.split(".", 1)[0] if host else host


def _is_dissimilar_but_close(candidate: str, target: str) -> str | None:
    """Explain how a label mimics *target*, or return None if unrelated."""
    if candidate == target:
        return None
    distance = levenshtein(candidate, target)
    ratio = _ratio(candidate, target)
    if candidate in target:
        return f"'{candidate}' is embedded in the legitimate name '{target}'"
    if target in candidate:
        return f"'{candidate}' extends the legitimate name '{target}'"
    if distance <= 2 or ratio >= 0.78:
        return f"edit distance {distance} from '{target}' (similarity {ratio:.0%})"
    # Keyboard adjacency
    for index, (a, b) in enumerate(zip(candidate, target)):
        if a != b and a in _KEYBOARD_NEIGHBOURS.get(b, ""):
            return f"'{a}' is adjacent to '{b}' on a QWERTY keyboard (position {index})"
    # Missing/extra letters
    if abs(len(candidate) - len(target)) == 1 and distance == 1:
        return f"one character differs from '{target}'"
    return None


@dataclass(slots=True)
class BrandMatch:
    """Result of comparing the URL host against a protected brand domain."""

    brand: str
    official_domain: str
    similarity: float
    explanation: str | None = None
    matched_label: str = ""

    @property
    def is_impersonation(self) -> bool:
        return self.explanation is not None


def find_brand_matches(parsed: ParsedUrl) -> list[BrandMatch]:
    """Return brand domains the host resembles, ordered by similarity."""
    host = (parsed.host or "").lower()
    if not host or parsed.is_ip_literal:
        return []
    label = _strip_suffix(host)
    registrable = parsed.registrable or host
    matches: list[BrandMatch] = []
    for brand, domains in IMPERSONATED_BRANDS.items():
        for official in domains:
            official_label = official.split(".", 1)[0]
            similarity = max(_ratio(label, official_label), _ratio(host, official))
            explanation = _is_dissimilar_but_close(label, official_label)
            if registrable == official or registrable.endswith(f".{official}"):
                matches.append(
                    BrandMatch(
                        brand=brand,
                        official_domain=official,
                        similarity=1.0,
                        explanation=None,
                        matched_label=label,
                    )
                )
                continue
            if explanation or similarity >= 0.72:
                matches.append(
                    BrandMatch(
                        brand=brand,
                        official_domain=official,
                        similarity=similarity,
                        explanation=explanation,
                        matched_label=label,
                    )
                )
    matches.sort(key=lambda m: (-m.similarity, m.brand))
    deduped: list[BrandMatch] = []
    seen_brands: set[str] = set()
    for match in matches:
        if match.brand in seen_brands:
            continue
        seen_brands.add(match.brand)
        deduped.append(match)
    return deduped[:6]


def domain_age_verdict(age_days: int | None) -> tuple[str, Severity, float, str]:
    """Map a domain age onto (label, severity, weight, explanation).

    Brand-new domains are a meaningful phishing signal because campaigns are
    cheap to stand up per victim; established domains are rarely repurposed for
    mass phishing because reputation matters.
    """
    if age_days is None:
        return "unknown", Severity.INFO, 0.0, "Domain age could not be determined."
    if age_days <= 2:
        return (
            "registered_today",
            Severity.HIGH,
            22.0,
            f"The domain was registered {age_days} day(s) ago. Newly registered "
            "domains are a strong phishing indicator because they are created per "
            "campaign and abandoned quickly.",
        )
    if age_days <= 14:
        return (
            "very_new",
            Severity.MEDIUM,
            14.0,
            f"The domain is only {age_days} days old. Very young domains are "
            "commonly used for short-lived phishing or malware distribution.",
        )
    if age_days <= 90:
        return (
            "new",
            Severity.LOW,
            8.0,
            f"The domain is {age_days} days old. Newer domains carry less "
            "reputation than long-established ones.",
        )
    if age_days >= 365 * 3:
        return (
            "established",
            Severity.INFO,
            0.0,
            f"The domain has been registered for about {age_days // 365} years, "
            "which lowers the likelihood of mass-phishing abuse.",
        )
    return (
        "mature",
        Severity.INFO,
        0.0,
        f"The domain has been registered for approximately {age_days} days.",
    )


def analyze_domain(parsed: ParsedUrl, *, domain_age_days: int | None = None) -> list[Finding]:
    """Domain-level intelligence findings (no network required)."""
    findings: list[Finding] = []
    host = (parsed.host or "").lower()
    tld = parsed.tld.lower()
    label = _strip_suffix(host)

    # --------------------------------------------------------- brand match
    for match in find_brand_matches(parsed):
        if not match.is_impersonation:
            continue
        findings.append(
            Finding(
                code="URL.BRAND_IMPERSONATION",
                title=f"Domain resembles {match.official_domain}",
                detail=(
                    f"The host '{host}' mimics the well-known domain "
                    f"'{match.official_domain}' ({match.explanation}). Legitimate "
                    "services never ask users to authenticate on look-alike "
                    "domains. Confirm the address with the organisation directly."
                ),
                severity=Severity.HIGH if match.similarity >= 0.72 else Severity.MEDIUM,
                source=SignalSource.URL_DOMAIN,
                category="phishing",
                weight=20.0 if match.similarity >= 0.72 else 14.0,
                evidence={
                    "brand": match.brand,
                    "official_domain": match.official_domain,
                    "similarity": round(match.similarity, 3),
                    "host": host,
                    "matched_label": match.matched_label,
                    "position": match.position,
                },
            )
        )

    # --------------------------------------------------------- keyword stuffing
    if any(brand in label for brand in IMPERSONATED_BRANDS) and label != host.split(".")[0]:
        pass  # handled by brand impersonation above

    for brand in ("secure", "login", "verify", "update", "account", "bank", "support", "helpdesk"):
        if label.startswith(brand) and label != brand:
            findings.append(
                Finding(
                    code="URL.KEYWORD_STUFFED_LABEL",
                    title=f"Host begins with '{brand}'",
                    detail=(
                        f"The leading label '{label}' starts with a high-frequency "
                        "security or support keyword. Combined with a non-brand "
                        "domain this is a typical credential-lure pattern."
                    ),
                    severity=Severity.LOW,
                    source=SignalSource.URL_DOMAIN,
                    category="phishing",
                    weight=6.0,
                    evidence={"label": label},
                )
            )
            break

    # --------------------------------------------------------- TLD risk
    if tld in PHISHING_PRONE_TLDS:
        findings.append(
            Finding(
                code="URL.PHISHING_PRONE_TLD",
                title=f"Top-level domain '.{tld}' has an elevated abuse rate",
                detail=(
                    f"'.{tld}' domains are inexpensive and are disproportionately "
                    "used in phishing campaigns, often imitating legitimate "
                    "file-sharing or document services."
                ),
                severity=Severity.LOW,
                source=SignalSource.URL_DOMAIN,
                category="reputation",
                weight=7.0,
                evidence={"tld": tld},
            )
        )
    elif tld in SUSPICIOUS_TLDS:
        findings.append(
            Finding(
                code="URL.SUSPICIOUS_TLD",
                title=f"Top-level domain '.{tld}' is frequently abused",
                detail=(
                    f"'.{tld}' appears frequently in abuse reports. It is not "
                    "evidence of malice on its own, but it removes the comfort of "
                    "an unknown-but-established domain."
                ),
                severity=Severity.LOW,
                source=SignalSource.URL_DOMAIN,
                category="reputation",
                weight=4.0,
                evidence={"tld": tld},
            )
        )

    # --------------------------------------------------------- label shape
    if host and not parsed.is_ip_literal:
        # The DGA assessment is reported once, by the syntax analyzer, which has
        # access to the full profile.  Here we only use the word-decomposition
        # result for the supplementary observations below.
        dga = GeneratedDomainProfile(label)
        if any(v in label for v in _VOWELS) is False and len(label) >= 6 and not dga.word_based:
            findings.append(
                Finding(
                    code="URL.NO_VOWELS_LABEL",
                    title="Host label contains no vowels",
                    detail=(
                        "Generated domains frequently omit vowels entirely, because "
                        "syllable-based word lists yield none. Human-chosen labels "
                        "almost always contain at least one."
                    ),
                    severity=Severity.INFO,
                    source=SignalSource.URL_DOMAIN,
                    category="structure",
                    weight=4.0,
                )
            )

    # --------------------------------------------------------- shortener
    registrable = parsed.registrable or host
    if registrable in URL_SHORTENERS or host in URL_SHORTENERS:
        findings.append(
            Finding(
                code="URL.SHORTENED_LINK",
                title="URL is a shortened link",
                detail=(
                    f"'{registrable}' hides the real destination. Shorteners are "
                    "legitimate but prevent you from judging the target before "
                    "clicking, so the final destination must be inspected."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.URL_DOMAIN,
                category="redirect",
                weight=12.0,
                evidence={"provider": registrable},
            )
        )

    # --------------------------------------------------------- domain age
    label_name, severity, weight, detail = domain_age_verdict(domain_age_days)
    if weight > 0:
        findings.append(
            Finding(
                code=f"URL.DOMAIN_AGE_{label_name.upper()}",
                title=f"Domain is {label_name.replace('_', ' ')}",
                detail=detail,
                severity=severity,
                source=SignalSource.URL_DOMAIN,
                category="reputation",
                weight=weight,
                evidence={"age_days": domain_age_days},
            )
        )
    return findings


def summarize_domain_analysis(parsed: ParsedUrl, *, domain_age_days: int | None = None) -> dict[str, object]:
    """Machine-readable summary used for reports, ML features and exports."""
    matches = find_brand_matches(parsed)
    label_name, _, _, _ = domain_age_verdict(domain_age_days)
    return {
        "host": parsed.host,
        "registrable_domain": parsed.registrable,
        "tld": parsed.tld,
        "is_punycode": parsed.is_punycode,
        "subdomain_count": parsed.subdomain_count,
        "is_shortener": (parsed.registrable or parsed.host) in URL_SHORTENERS,
        "brand_matches": [
            {
                "brand": m.brand,
                "official_domain": m.official_domain,
                "similarity": round(m.similarity, 3),
                "impersonation": m.is_impersonation,
                "explanation": m.explanation,
            }
            for m in matches
        ],
        "domain_age_days": domain_age_days,
        "domain_age_class": label_name,
        "tld_in_suspicious_set": parsed.tld in SUSPICIOUS_TLDS,
    }


@dataclass(slots=True)
class DomainReputation:
    """Cached reputation verdict for a domain."""

    domain: str
    verdict: str = "unrated"
    score: float = 0.0
    categories: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    checked_at: float = 0.0