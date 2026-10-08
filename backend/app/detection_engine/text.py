"""Text extraction helpers shared by the URL, email, document and image analysers."""

from __future__ import annotations

import re
from typing import Iterable

# Whitespace/control characters that must be stripped from URLs before parsing.
# Browsers ignore CR, LF and TAB inside URLs, which makes them a classic vector
# for request splitting and for smuggling a real host past a naive validator.
_URL_STRIP_CHARS = re.compile(r"[\x00-\x20\x7f   ﻿]")

# Matches http/https/ftp schemes. Requires a scheme so that bare "example.com"
# inside prose is not mistaken for a link.
_URL_RE = re.compile(
    r"\b(?:https?|ftp)://"
    r"[^\s<>\"'`\]\[{}|\\^]+",
    re.IGNORECASE,
)

# Deliberately conservative: requires a label, a TLD of 2+ letters, and rejects
# trailing sentence punctuation which is almost always prose, not a hostname.
_EMAIL_RE = re.compile(
    r"\b[a-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}\b",
    re.IGNORECASE,
)

# IPv4 with each octet 0-255 and no leading zeros (leading-zero octets are a
# known parser-differential trick used to disguise 127.0.0.1).
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
)

_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)

_WORD_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)


def normalise_text(text: str) -> str:
    """Collapse whitespace and normalise Unicode so token matching is stable.

    Attackers defeat naive keyword matching with zero-width joiners, mixed case,
    homoglyphs and interleaved spaces (``v e r i f y``). Folding to a
    lowercase, space-collapsed, NFKC-normalised form defeats the cheap variants.
    """
    import unicodedata

    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return re.sub(r"\s+", " ", text).strip()


def compact_text(text: str) -> str:
    """Remove all whitespace, for defeat of ``v e r i f y`` style obfuscation."""
    return re.sub(r"\s+", "", text or "")


def strip_url_noise(url: str) -> str:
    """Strip characters browsers ignore when resolving a URL."""
    return _URL_STRIP_CHARS.sub("", url)


def extract_urls(text: str, *, limit: int = 500) -> list[str]:
    """Extract candidate URLs from free text, de-duplicated, order preserved.

    Cleaning is applied to each *candidate*, never to the whole text: collapsing
    all whitespace first would glue ``Visit https://`` into
    ``Visithttps://`` and kill the word boundary the URL pattern requires.
    """
    if not text:
        return []
    seen: set[str] = set()
    results: list[str] = []
    for match in _URL_RE.findall(text):
        candidate = strip_url_noise(match).rstrip(".,;:!?)\"'")
        if len(candidate) > 4 and "://" in candidate and candidate not in seen:
            seen.add(candidate)
            results.append(candidate)
        if len(results) >= limit:
            break
    return results


def extract_email_addresses(text: str, *, limit: int = 200) -> list[str]:
    """Extract email addresses from free text."""
    if not text:
        return []
    seen: set[str] = set()
    results: list[str] = []
    for match in _EMAIL_RE.findall(text):
        candidate = match.strip(".").lower()
        if candidate not in seen:
            seen.add(candidate)
            results.append(candidate)
        if len(results) >= limit:
            break
    return results


def extract_ips(text: str, *, limit: int = 200) -> list[str]:
    """Extract IPv4 literals from free text."""
    if not text:
        return []
    seen: set[str] = set()
    results: list[str] = []
    for match in _IPV4_RE.findall(text):
        if match not in seen:
            seen.add(match)
            results.append(match)
        if len(results) >= limit:
            break
    return results


def extract_domains(text: str, *, limit: int = 200) -> list[str]:
    """Extract domain names, excluding anything that looks like an IP literal."""
    if not text:
        return []
    seen: set[str] = set()
    results: list[str] = []
    for match in _DOMAIN_RE.findall(text):
        candidate = match.lower().rstrip(".")
        if candidate in seen or _IPV4_RE.fullmatch(candidate):
            continue
        seen.add(candidate)
        results.append(candidate)
        if len(results) >= limit:
            break
    return results


def extract_words(text: str, *, limit: int = 20000) -> list[str]:
    """Tokenise text into lowercase alphanumeric words."""
    return [token.lower() for token in _WORD_RE.findall(text or "")][:limit]


def count_matches(text: str, patterns: Iterable[re.Pattern[str] | str]) -> int:
    """Count total matches of ``patterns`` in ``text`` (case-insensitive)."""
    total = 0
    lowered = (text or "").lower()
    for pattern in patterns:
        if isinstance(pattern, str):
            total += lowered.count(pattern.lower())
        else:
            total += len(pattern.findall(lowered))
    return total


def contains_any(text: str, patterns: Iterable[re.Pattern[str] | str]) -> bool:
    """Return True when any pattern matches ``text`` (case-insensitive)."""
    return count_matches(text, patterns) > 0


def truncate_for_display(text: str, limit: int = 240) -> str:
    """Truncate text for report display, collapsing newlines."""
    collapsed = re.sub(r"\s+", " ", text or "").strip()
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"