"""Phishing heuristics: text social-engineering analysis and URL deception analysis.

Every function returns :class:`~app.schemas.signal.DetectionSignal` objects rather
than a score. Scoring is the risk engine's responsibility, which keeps the
"why" and the "how much" independently auditable.

A design rule enforced throughout: **no single heuristic can produce a MALICIOUS
verdict.** Lexical analysis raises suspicion; only independent corroboration
(reputation, threat intelligence, an AV detection, a mismatched redirect target)
escalates a verdict.
"""

from __future__ import annotations

import re
from typing import Iterable, Sequence

from app.detection_engine.phishing.keywords import (
    AUTHORITY_PATTERNS,
    BRAND_OFFICIAL_DOMAINS,
    BRAND_TOKENS,
    CREDENTIAL_REQUEST_PATTERNS,
    FINANCIAL_REQUEST_PATTERNS,
    KEYWORD_WEIGHTS,
    LINK_ANCHOR_RE,
    SECRECY_PATTERNS,
    TYPOSQUAT_VARIANTS,
    URGENCY_PHRASES,
)
from app.detection_engine.text import compact_text, normalise_text, truncate_for_display
from app.detection_engine.url.parser import ParsedUrl, is_shortened_url
from app.schemas.common import IndicatorType, Severity, SignalSource
from app.schemas.signal import DetectionSignal, Indicator

# Words that legitimately appear alongside credential keywords on real sites.
# Their presence suppresses (not deletes) keyword signals, because a real
# bank login page and a phishing login page look identical lexically.
_BENIGN_CONTEXT_RE = re.compile(
    r"(?:official|legitimate|genuine|real|support|help|faq|how\s+to|reset\s+your\s+own|"
    r"forgot\s+password\s+page|developer|documentation|changelog|blog|news)",
    re.I,
)

_CONFIDENCE_BY_COUNT = ((0, 0.35), (1, 0.5), (2, 0.62), (3, 0.72), (5, 0.82), (8, 0.9))


def _count_to_confidence(count: int) -> float:
    """Map an occurrence count onto a calibrated confidence."""
    if count <= 0:
        return 0.0
    for threshold, confidence in _CONFIDENCE_BY_COUNT:
        if count <= threshold + 1:
            return confidence
    return 0.95


# ---------------------------------------------------------------------------
# Text / social-engineering analysis
# ---------------------------------------------------------------------------
def analyse_text_content(text: str) -> list[DetectionSignal]:
    """Analyse message prose for phishing social-engineering language."""
    if not text or not text.strip():
        return []

    normalised = normalise_text(text)
    lowered = normalised.lower()
    de_spaced = compact_text(lowered)
    signals: list[DetectionSignal] = []

    urgency_hits = sorted({phrase for phrase in URGENCY_PHRASES if phrase in lowered})
    if urgency_hits:
        # Breadth of manipulation drives severity: a single urgent phrase is
        # ordinary writing, while five distinct pressure techniques combined
        # (threat of loss, deadline, immediate action, warning) is engineered.
        if len(urgency_hits) >= 5:
            urgency_severity = Severity.HIGH
        elif len(urgency_hits) >= 3:
            urgency_severity = Severity.MEDIUM
        else:
            urgency_severity = Severity.LOW
        signals.append(
            DetectionSignal(
                code="phish.urgency_language",
                title="Pressure and urgency language detected",
                description=(
                    "The message uses urgency or threat language to prompt immediate action "
                    f"without giving the reader time to verify: {', '.join(urgency_hits[:6])}."
                    + (
                        " Several distinct pressure techniques are combined, which is the "
                        "signature of deliberate social engineering."
                        if len(urgency_hits) >= 5
                        else ""
                    )
                ),
                severity=urgency_severity,
                category="social_engineering",
                source=SignalSource.HEURISTIC,
                confidence=min(0.85, 0.4 + 0.06 * len(urgency_hits)),
                weight=min(0.55, 0.16 + 0.055 * len(urgency_hits)),
                evidence={
                    "matched_phrases": urgency_hits[:20],
                    "phrase_count": len(urgency_hits),
                },
            )
        )

    credential_hits = _collect_pattern_matches(CREDENTIAL_REQUEST_PATTERNS, lowered)
    credential_hits += _collect_pattern_matches(
        [re.compile(p.pattern, re.I) for p in CREDENTIAL_REQUEST_PATTERNS], de_spaced, spaced=False
    )
    credential_hits = sorted(set(credential_hits))
    if credential_hits:
        signals.append(
            DetectionSignal(
                code="phish.credential_request",
                title="Credential or identity verification requested",
                description=(
                    "The content explicitly asks the reader to submit a password, code, recovery "
                    f"phrase or other authentication factor: {truncate_for_display(', '.join(credential_hits[:4]), 160)}."
                ),
                severity=Severity.CRITICAL if len(credential_hits) >= 2 else Severity.HIGH,
                category="social_engineering",
                source=SignalSource.HEURISTIC,
                confidence=_count_to_confidence(len(credential_hits)),
                weight=min(0.72, 0.5 + 0.08 * len(credential_hits)),
                evidence={
                    "matched_phrases": credential_hits[:10],
                    "match_count": len(credential_hits),
                },
            )
        )

    financial_hits = _collect_pattern_matches(FINANCIAL_REQUEST_PATTERNS, lowered)
    financial_hits = sorted(set(financial_hits))
    if financial_hits:
        signals.append(
            DetectionSignal(
                code="phish.financial_request",
                title="Sensitive financial or payment data requested",
                description=(
                    "The content asks for payment details, bank credentials or a transfer of "
                    f"funds: {truncate_for_display(', '.join(financial_hits[:4]), 160)}."
                ),
                severity=Severity.CRITICAL if len(financial_hits) >= 2 else Severity.HIGH,
                category="social_engineering",
                source=SignalSource.HEURISTIC,
                confidence=_count_to_confidence(len(financial_hits)),
                weight=min(0.7, 0.48 + 0.08 * len(financial_hits)),
                evidence={
                    "matched_phrases": financial_hits[:10],
                    "match_count": len(financial_hits),
                },
            )
        )

    keyword_signal = _analyse_keyword_density(normalised, lowered)
    if keyword_signal is not None:
        signals.append(keyword_signal)

    signals.extend(_analyse_social_pressure(lowered, de_spaced))
    signals.extend(analyse_html_markup(normalised))
    return signals


def _analyse_social_pressure(normalised_lowered: str, de_spaced: str) -> list[DetectionSignal]:
    """Detect secrecy and authority abuse used in Business Email Compromise.

    BEC relies on suppressing the victim's normal verification step rather than
    on technical evasion, so these patterns carry signal even when no link or
    attachment is present.
    """
    signals: list[DetectionSignal] = []

    secrecy = _collect_pattern_matches(SECRECY_PATTERNS, normalised_lowered)
    secrecy += _collect_pattern_matches(SECRECY_PATTERNS, de_spaced)
    secrecy = sorted(set(secrecy))
    if secrecy:
        signals.append(
            DetectionSignal(
                code="phish.secrecy_request",
                title="Message requests secrecy from the recipient",
                description=(
                    "The message instructs the reader not to discuss the request with others "
                    "("
                    + truncate_for_display(", ".join(secrecy[:3]), 140)
                    + "). Legitimate business requests are not confidential from the "
                    "recipient's own colleagues, and this instruction exists specifically to "
                    "defeat the verification step that would expose fraud."
                ),
                severity=Severity.HIGH,
                category="social_engineering",
                source=SignalSource.HEURISTIC,
                confidence=_count_to_confidence(len(secrecy)),
                weight=0.6,
                evidence={"matched_phrases": secrecy[:8], "match_count": len(secrecy)},
            )
        )

    authority = _collect_pattern_matches(AUTHORITY_PATTERNS, normalised_lowered)
    authority += _collect_pattern_matches(AUTHORITY_PATTERNS, de_spaced)
    authority = sorted(set(authority))
    if authority:
        signals.append(
            DetectionSignal(
                code="phish.authority_impersonation",
                title="Message invokes executive or official authority",
                description=(
                    "The message addresses the recipient by title or claims to act for a senior "
                    "figure (" + truncate_for_display(", ".join(authority[:3]), 140)
                    + "). Senior figures are impersonated in Business Email Compromise because "
                    "junior staff comply with urgent instructions from leadership."
                ),
                severity=Severity.MEDIUM,
                category="social_engineering",
                source=SignalSource.HEURISTIC,
                confidence=_count_to_confidence(len(authority)) * 0.9,
                evidence={"matched_phrases": authority[:8], "match_count": len(authority)},
            )
        )

    return signals


def _analyse_keyword_density(normalised: str, lowered: str) -> DetectionSignal | None:
    """Weight phishing vocabulary by frequency, discounted by benign context."""
    matched: dict[str, int] = {}
    for keyword, weight in KEYWORD_WEIGHTS.items():
        count = lowered.count(keyword)
        if count:
            matched[keyword] = count
    if not matched:
        return None

    density = sum(KEYWORD_WEIGHTS[k] * min(c, 4) for k, c in matched.items())
    benign = bool(_BENIGN_CONTEXT_RE.search(lowered))
    word_count = max(1, len(normalised.split()))
    words_per_hit = word_count / sum(matched.values())

    if density < 1.2:
        return None

    top = sorted(matched.items(), key=lambda item: KEYWORD_WEIGHTS[item[0]], reverse=True)[:8]
    severity = Severity.MEDIUM if density < 2.5 else Severity.HIGH
    if benign:
        severity = Severity.LOW
        density *= 0.5

    return DetectionSignal(
        code="phish.keyword_density",
        title="High concentration of phishing terminology",
        description=(
            "The content repeatedly uses credential and urgency vocabulary typical of "
            f"phishing messages ({', '.join(f'{k}x{c}' for k, c in top)})."
        ),
        severity=severity,
        category="lexical",
        source=SignalSource.HEURISTIC,
        confidence=_count_to_confidence(len(matched)),
        evidence={
            "matched_keywords": dict(top),
            "weighted_density": round(density, 3),
            "benign_context_detected": benign,
            "word_count": word_count,
            "words_per_keyword": round(words_per_hit, 2),
        },
    )


def analyse_html_markup(text: str) -> list[DetectionSignal]:
    """Detect link-text/anchor deception and obfuscated markup."""
    signals: list[DetectionSignal] = []
    lowered = text.lower()

    mismatches: list[dict[str, str]] = []
    for href, anchor in LINK_ANCHOR_RE.findall(text):
        anchor_text = re.sub(r"<[^>]+>", " ", anchor)
        anchor_norm = normalise_text(anchor_text).lower()
        if not anchor_norm or len(anchor_norm) > 120:
            continue
        href_norm = href.strip().lower()
        # Only flag when the visible text names a brand or a destination that the
        # href does not actually point at.
        if len(href_norm) < 8:
            continue
        from app.detection_engine.url.parser import parse_url

        target = parse_url(href_norm)
        href_host = target.hostname
        if not href_host:
            continue
        anchor_host_tokens = set(re.split(r"[^a-z0-9]+", anchor_norm)) - {""}
        named_hosts = {
            token for token in anchor_host_tokens if token.endswith((".com", ".net", ".org", ".co.uk"))
        }
        if named_hosts and not any(named in href_host for named in named_hosts):
            mismatches.append({"visible_text": anchor_norm[:120], "actual_destination": href_host})
        elif anchor_norm in BRAND_TOKENS and anchor_norm not in href_host:
            mismatches.append({"visible_text": anchor_norm[:120], "actual_destination": href_host})

    if mismatches:
        signals.append(
            DetectionSignal(
                code="phish.link_text_mismatch",
                title="Link text does not match its real destination",
                description=(
                    "One or more hyperlinks display a destination that differs from where the "
                    "link actually leads. This is a standard phishing technique used to mislead "
                    "the reader before clicking."
                ),
                severity=Severity.HIGH,
                category="deception",
                source=SignalSource.HEURISTIC,
                confidence=min(0.9, 0.5 + 0.12 * len(mismatches)),
                evidence={"mismatches": mismatches[:10], "count": len(mismatches)},
                indicators=tuple(
                    Indicator(type=IndicatorType.DOMAIN, value=m["actual_destination"][:255])
                    for m in mismatches[:10]
                ),
            )
        )

    if lowered.count("<script") > 0 and lowered.count("onerror=") + lowered.count("onload=") > 0:
        signals.append(
            DetectionSignal(
                code="phish.active_markup",
                title="Active markup with event handlers",
                description=(
                    "The content contains script elements together with inline event handlers, "
                    "which can execute code automatically in a mail or browser client."
                ),
                severity=Severity.MEDIUM,
                category="deception",
                source=SignalSource.HEURISTIC,
                confidence=0.65,
                evidence={
                    "script_tags": lowered.count("<script"),
                    "event_handlers": lowered.count("onerror=") + lowered.count("onload="),
                },
            )
        )

    return signals


def _collect_pattern_matches(
    patterns: Sequence[re.Pattern[str]], text: str, *, spaced: bool = True
) -> list[str]:
    found: list[str] = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            found.append(match.group(0) if spaced else match.group(0))
    return found


# ---------------------------------------------------------------------------
# URL deception analysis
# ---------------------------------------------------------------------------
def analyse_url_deception(url: ParsedUrl) -> list[DetectionSignal]:
    """Detect impersonation, typosquatting and homograph attacks on a URL."""
    signals: list[DetectionSignal] = []
    if not url.hostname:
        return signals

    brand_signal = _detect_brand_impersonation(url)
    if brand_signal:
        signals.append(brand_signal)

    typo_signal = _detect_typosquatting(url)
    if typo_signal:
        signals.append(typo_signal)

    if url.has_mixed_script:
        # Identify which brands the decoded host visually approximates. This is
        # what turns a generic "mixed script" note into an actionable
        # impersonation finding.
        imitated = _brands_resembling(url.display_hostname)
        imitated_note = (
            " Decoded, the host reads as '" + url.display_hostname[:120] + "'"
            + (f", which visually resembles {', '.join(imitated)}." if imitated else ".")
        )
        signals.append(
            DetectionSignal(
                code="phish.homograph_domain",
                title="Host mixes multiple writing systems (homograph attack)",
                description=(
                    "The domain name mixes characters from different alphabets. Legitimate "
                    "brands use a single writing system, so a mixed-script host is a strong "
                    "indicator of a homograph (lookalike) attack designed to impersonate a brand "
                    "the reader trusts." + imitated_note
                ),
                severity=Severity.HIGH,
                category="impersonation",
                source=SignalSource.STRUCTURAL,
                confidence=0.85,
                weight=0.6,
                evidence={
                    "punycode_host": url.hostname[:253],
                    "decoded_host": url.display_hostname[:253],
                    # The non-Latin character count is the objective evidence: a
                    # genuine brand domain is never built from another script.
                    "non_latin_characters": sum(
                        1 for ch in url.display_hostname if ord(ch) > 127
                    ),
                    "resembles_brands": imitated[:5],
                },
                indicators=(
                    Indicator(
                        type=IndicatorType.DOMAIN,
                        value=url.display_hostname[:253],
                        context="decoded internationalised host",
                    ),
                ),
            )
        )

    if url.is_punycode and not url.has_unicode:
        signals.append(
            DetectionSignal(
                code="url.punycode_host",
                title="Punycode (internationalised) domain",
                description=(
                    "The hostname is an IDN punycode label. Punycode is used legitimately, but "
                    "attackers use it to impersonate brands visually while rendering as ASCII."
                ),
                severity=Severity.LOW,
                category="impersonation",
                source=SignalSource.STRUCTURAL,
                confidence=0.35,
                evidence={"punycode_host": url.hostname[:253]},
            )
        )

    return signals


def _detect_brand_impersonation(url: ParsedUrl) -> DetectionSignal | None:
    """Flag brand tokens hosted outside the brand's official domain."""
    registered = (url.registered_domain or "").lower()
    if not registered:
        return None

    haystack_labels = [label for label in (url.subdomain or "").split(".") if label]
    haystack = " ".join(haystack_labels)
    haystack_compact = haystack.replace("-", "").replace("_", "").replace(".", "")

    hits: list[dict[str, str]] = []
    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        if registered in official_domains:
            continue  # Genuine official domain.
        brand_compact = brand.replace("-", "").replace("_", "")
        if brand in haystack.lower() or brand_compact in haystack_compact.lower():
            # Ignore a brand that is only a substring of a longer, unrelated word.
            if _is_standalone_match(haystack.lower(), brand_compact):
                hits.append({"brand": brand, "official_domain": sorted(official_domains)[0]})

    if not hits:
        return None

    # A shortener hides the real host, so the brand token in the path matters.
    if is_shortened_url(url):
        path_lower = url.path.lower()
        for brand in BRAND_TOKENS:
            if brand in path_lower and not any(h["brand"] == brand for h in hits):
                hits.append({"brand": brand, "official_domain": sorted(BRAND_OFFICIAL_DOMAINS[brand])[0]})

    return DetectionSignal(
        code="phish.brand_impersonation",
        title="Impersonation of a recognised brand",
        description=(
            "The URL uses the name of a well-known organisation ("
            + ", ".join(h["brand"] for h in hits[:5])
            + f") but is hosted on {registered}, which is not that organisation's domain. "
            "Attackers register lookalike domains to harvest credentials."
        ),
        severity=_BRAND_IMPERSONATION_SEVERITY,
        category="impersonation",
        source=SignalSource.STRUCTURAL,
        confidence=min(0.9, 0.6 + 0.08 * len(hits)),
        weight=_BRAND_IMPERSONATION_WEIGHT,
        evidence={
            "impersonated_brands": hits[:10],
            "registered_domain": registered,
            "brand_count": len(hits),
        },
        indicators=(
            Indicator(type=IndicatorType.DOMAIN, value=registered[:255], context="actual registrable domain"),
        ),
    )


def _is_standalone_match(haystack: str, brand_compact: str) -> bool:
    """Require the brand to appear as a delimited token, not inside another word."""
    for label in haystack.replace(".", " ").split():
        compact = label.replace("-", "").replace("_", "")
        if compact == brand_compact:
            return True
        if compact.startswith(brand_compact) and len(compact) - len(brand_compact) <= 12:
            return True
        if compact.endswith(brand_compact) and len(compact) - len(brand_compact) <= 12:
            return True
        if f" {brand_compact}" in f" {compact}":
            return True
    return False


#: Evidence-backed detection of a brand token embedded in an unrelated domain.
#: This is the highest-value phishing signal available from URL structure alone,
#: so it is granted a strong explicit weight rather than relying on the category
#: budget, which would otherwise dilute it among cosmetic findings.
_BRAND_IMPERSONATION_WEIGHT = 0.72
_BRAND_IMPERSONATION_SEVERITY = Severity.CRITICAL


#: Characters treated as visually confusable with their Latin counterpart when
#: scoring how closely a decoded host resembles a brand. Cyrillic а/е/р/о/с and
#: Greek ο/ν are the highest-value cases in real homograph campaigns.
_CONFUSABLES: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ɡ": "g",
    "ο": "o", "ν": "v", "α": "a", "ρ": "p", "τ": "t", "υ": "u",
    "ϲ": "c", "ο": "o", "і": "i", "ѕ": "s", "ԛ": "q", "ԝ": "w",
    "`：": ":", "．": ".", "／": "/", "＠": "@", "‐": "-", "‑": "-",
}


def _fold_confusables(text: str) -> str:
    """Fold visually confusable characters onto their Latin equivalents."""
    return "".join(_CONFUSABLES.get(char, char) for char in (text or "").lower())


def _label_is_typosquat_of(label: str, variant: str) -> bool:
    """Does ``label`` contain ``variant`` as a stand-alone token?

    Matching is token-aware so that ``microsft-login`` matches the ``microsft``
    variant while ``microsoft`` (the genuine brand) does not, and so that a
    variant embedded inside an unrelated longer word (``microsftware``) is only
    flagged when the surrounding text is itself a plausible impersonation token.
    """
    variant_folded = _fold_confusables(variant)
    label_folded = _fold_confusables(label)
    if variant_folded not in label_folded:
        return False

    # The variant must align with the start of a hyphen/underscore/dot separated
    # token, or the whole label. That keeps "microsft-login" and "loginmicrosft"
    # as matches but rejects "microsftware2fa" where the typo is mid-word.
    for token in re.split(r"[-_.]", label_folded):
        if token == variant_folded:
            return True
    return label_folded.startswith(variant_folded)


def _brands_resembling(display_hostname: str) -> list[str]:
    """Brands whose spelling the decoded host appears to imitate."""
    if not display_hostname:
        return []
    folded = _fold_confusables(display_hostname)
    matches: list[str] = []
    for brand in sorted(BRAND_TOKENS):
        if brand in folded and brand != folded:
            matches.append(brand)
    return matches


def _detect_typosquatting(url: ParsedUrl) -> DetectionSignal | None:
    """Match host labels against a curated typosquat variant list.

    Every label of the full hostname is examined, not just the registered
    domain, because a misspellingsquat frequently lives in the subdomain
    (``microsft-login.example.tk``) while the registrable domain is innocuous.
    """
    labels = [
        label
        for label in (url.hostname or "").lower().split(".")
        if label and not label.isdigit()
    ]
    if not labels:
        return None

    hits: list[dict[str, str]] = []
    for brand, variants in TYPOSQUAT_VARIANTS.items():
        official = BRAND_OFFICIAL_DOMAINS.get(brand, frozenset())
        registered = (url.registered_domain or "").lower()
        # A host that *is* the official domain (or a subdomain of it) is genuine.
        if any(registered == domain or hostname.endswith("." + domain)
               for domain in official
               for hostname in [registered, (url.hostname or "").lower()]):
            continue

        for label in labels:
            for variant in variants:
                if _label_is_typosquat_of(label, variant):
                    hits.append(
                        {
                            "brand": brand,
                            "host": url.hostname[:253],
                            "label": label,
                            "variant": variant,
                        }
                    )
    if not hits:
        return None
    return DetectionSignal(
        code="phish.typosquatting",
        title="Typosquatting domain detected",
        description=(
            "The hostname closely resembles a major brand's domain using a deliberate "
            "misspelling or substitution, a technique designed to catch mistyped or hurried visits."
        ),
        severity=Severity.CRITICAL,
        category="impersonation",
        source=SignalSource.STRUCTURAL,
        confidence=0.85,
        weight=0.75,
        evidence={"matches": hits[:10], "match_count": len(hits)},
        indicators=tuple(
            Indicator(type=IndicatorType.DOMAIN, value=h["host"][:255]) for h in hits[:10]
        ),
    )


def summarise_urls(urls: Iterable[str], *, limit: int = 25) -> dict[str, object]:
    """Produce a small, privacy-conscious summary of extracted links."""
    from app.detection_engine.url.parser import parse_url

    parsed = [parse_url(url) for url in urls][:limit]
    return {
        "count": len(parsed),
        "domains": sorted({u.hostname for u in parsed if u.hostname}),
        "https_ratio": (
            round(sum(1 for u in parsed if u.is_https) / len(parsed), 3) if parsed else 0.0
        ),
        "shorteners": sorted({u.hostname for u in parsed if is_shortened_url(u)}),
        "ip_hosts": sorted({u.hostname for u in parsed if u.is_ip_literal}),
    }