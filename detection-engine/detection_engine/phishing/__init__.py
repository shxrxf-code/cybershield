"""Phishing detection: text analysis, sender/URL correlation, combined verdict."""

from __future__ import annotations

from .text import TextPhishingProfile, analyze_text, findings_from_profile

__all__ = [
    "TextPhishingProfile",
    "analyze_text",
    "findings_from_profile",
    "analyze_link_text",
    "link_text_mismatch",
]


def link_text_mismatch(display_text: str, actual_url: str) -> dict[str, object] | None:
    """Detect a hyperlink whose visible text claims one destination but points elsewhere.

    This is one of the highest-signal phishing patterns available and it needs no
    network access: HTML anchors carry both the human-readable text and the real
    href.

    >>> link_text_mismatch("https://www.paypal.com", "http://paypal-secure.tk/login")
    {'displayed': 'https://www.paypal.com', 'actual': '...', 'registered_domain': ...}
    """
    from ..url.normalizer import parse_url

    display = (display_text or "").strip()
    if not display or not actual_url:
        return None
    display_urls = [u for u in display.split() if "://" in u or u.startswith("www.")]
    if not display_urls:
        return None
    if len(display_urls) != 1:
        return None
    shown = display_urls[0]
    if shown.rstrip("/").lower() == actual_url.rstrip("/").lower():
        return None
    try:
        shown_parsed = parse_url(shown)
        actual_parsed = parse_url(actual_url)
    except Exception:
        return None
    if shown_parsed.host == actual_parsed.host:
        return None
    return {
        "displayed": shown,
        "actual": actual_url,
        "displayed_host": shown_parsed.host,
        "actual_host": actual_parsed.host,
        "displayed_registrable": shown_parsed.registrable,
        "actual_registrable": actual_parsed.registrable,
        "scheme_mismatch": shown_parsed.scheme != actual_parsed.scheme,
    }


def analyze_link_text(text: str, links: list[tuple[str, str]]) -> tuple[TextPhishingProfile, list]:
    """Analyse free text plus extracted ``(display_text, href)`` anchor pairs."""
    from ..models import Finding, Severity, SignalSource

    profile = analyze_text(text)
    findings = findings_from_profile(profile)

    for display_text, href in links[:200]:
        mismatch = link_text_mismatch(display_text, href)
        if mismatch is None:
            continue
        displayed_host = str(mismatch["displayed_host"])
        actual_host = str(mismatch["actual_host"])
        findings.append(
            Finding(
                code="PHISH.LINK_TEXT_MISMATCH",
                title="Link text does not match the real destination",
                detail=(
                    f"The link displays '{displayed_host}' but navigates to "
                    f"'{actual_host}'. This deception is designed to look like a "
                    "legitimate site in the address bar preview while capturing "
                    "credentials on an attacker-controlled domain."
                ),
                severity=Severity.CRITICAL,
                source=SignalSource.PHISHING,
                category="phishing",
                weight=30.0,
                authoritative=True,
                evidence=mismatch,
            )
        )
    return profile, findings