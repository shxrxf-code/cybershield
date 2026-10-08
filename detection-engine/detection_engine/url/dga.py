"""Heuristics for distinguishing generated (DGA-style) domains from real ones.

Entropy alone is not enough: ``stackoverflow`` scores 3.55 bits/char, close to
the 3.70 of a genuinely random label like ``xkqzjvhpwldnt``.  The discriminator
that actually works is *decomposability*: human-chosen domain names are built
from words, while algorithmically generated ones are not.

This module is deliberately dependency-free and its word list is small and
auditable.  A production deployment should swap :func:`decomposes_into_words`
for a frequency model trained on the top of a public suffix list, keeping the
same interface.
"""

from __future__ import annotations

import math
import re
from collections import Counter

__all__ = ["char_entropy", "decomposes_into_words", "looks_generated", "GeneratedDomainProfile"]

_SPLIT_RE = re.compile(r"[^a-z0-9]+")

#: Common English and technology words seen in legitimate domain names.
#: Kept short on purpose: the function only needs to *recognise* word-shaped
#: labels, not to be a dictionary.
COMMON_DOMAIN_WORDS: frozenset[str] = frozenset(
    {
        # tech / development
        "stack", "overflow", "github", "gitlab", "bitbucket", "source", "code",
        "codes", "dev", "devel", "develop", "build", "builder", "api", "app",
        "apps", "web", "net", "network", "networks", "host", "hosting", "server",
        "servers", "cloud", "data", "database", "compute", "software", "hardware",
        "systems", "system", "solutions", "service", "services", "tech",
        "technology", "technologies", "digital", "cyber", "secure", "security",
        "shield", "guard", "protect", "scan", "scanner", "mail", "email", "webmail",
        "smtp", "office", "docs", "doc", "wiki", "forum", "board", "chat", "help",
        "support", "portal", "gateway", "router", "proxy", "vpn", "host", "domain",
        "domains", "dns", "cdn", "cloud", "panel", "console", "status", "health",
        "care", "medical", "clinic", "hospital", "pharmacy", "legal", "law",
        "attorney", "finance", "financial", "bank", "banking", "money", "pay",
        "payment", "payments", "cash", "coin", "coins", "crypto", "wallet",
        "trade", "trading", "market", "markets", "capital", "invest", "investments",
        "insurance", "account", "accounting", "books", "book", "read", "library",
        "publish", "publisher", "press", "news", "media", "photo", "photos",
        "image", "images", "video", "videos", "music", "audio", "studio", "design",
        "creative", "agency", "digital", "brand", "brands", "group", "team",
        "works", "world", "global", "globalwide", "central", "united", "union",
        "national", "international", "enterprise", "industries", "ventures",
        "holdings", "partners", "associates", "consulting", "advisors", "labs",
        "lab", "studio", "factory", "outlet", "store", "shop", "shopping", "sale",
        "sales", "deal", "deals", "offers", "promo", "marketplace", "auction",
        "travel", "tour", "tours", "hotel", "hotels", "flight", "flights", "taxi",
        "food", "restaurant", "cafe", "coffee", "pizza", "kitchen", "recipes",
        "recipe", "gym", "fitness", "yoga", "sports", "sport", "football", "club",
        "team", "league", "games", "game", "gaming", "play", "toys", "kids",
        "children", "school", "college", "university", "institute", "academy",
        "learn", "learning", "training", "courses", "course", "lessons", "tutor",
        "english", "math", "maths", "science", "physics", "chemistry", "biology",
        "history", "geography", "art", "music", "dance", "theatre", "theater",
        # qualifier words commonly glued into brand-ish domains
        "secure", "safety", "safe", "first", "best", "top", "new", "next", "now",
        "get", "go", "run", "make", "create", "one", "two", "three", "my", "me",
        "your", "our", "their", "pro", "plus", "max", "prime", "elite", "ultra",
        "premium", "gold", "silver", "diamond", "platinum", "royal", "smart",
        "quick", "fast", "easy", "simple", "open", "free", "net", "online",
        "home", "house", "city", "town", "world", "zone", "space", "works",
        "system", "network", "cloud", "hub", "link", "links", "path", "route",
        "point", "spot", "center", "centre", "base", "basics", "basic", "info",
        "news", "alert", "alerts", "alerting", "watch", "monitor", "track",
        "tracker", "verify", "valid", "validate", "check", "testing", "test",
        "demo", "sample", "example", "template", "templates", "theme", "themes",
        "login", "signin", "signup", "account", "accounts", "user", "users",
        "member", "members", "customer", "customers", "client", "clients",
        "partner", "partners", "supplier", "vendor", "market", "seller",
        "cart", "checkout", "billing", "invoice", "subscription", "order",
        "orders", "shipping", "delivery", "tracking", "returns", "refund",
    }
)

#: Longest word considered during segmentation.
_MAX_WORD_LENGTH = 18


def char_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def decomposes_into_words(label: str, *, min_words: int = 2) -> bool:
    """True when *label* can be segmented into :data:`COMMON_DOMAIN_WORDS`.

    Uses dynamic programming so overlapping candidates are handled, and only
    reports success when at least *min_words* words are needed (otherwise every
    one-word label would trivially "decompose").
    """
    cleaned = _SPLIT_RE.sub("", (label or "").lower())
    if not cleaned:
        return False
    # Reachability table: reachable[i] = max number of words covering cleaned[:i]
    reachable: list[int] = [-1] * (len(cleaned) + 1)
    reachable[0] = 0
    for end in range(1, len(cleaned) + 1):
        for start in range(max(0, end - _MAX_WORD_LENGTH), end):
            if reachable[start] < 0:
                continue
            chunk = cleaned[start:end]
            if chunk in COMMON_DOMAIN_WORDS:
                reachable[end] = max(reachable[end], reachable[start] + 1)
    return reachable[-1] >= min_words


def _segments(label: str) -> list[str]:
    """Return a word segmentation of *label*, or an empty list."""
    cleaned = _SPLIT_RE.sub("", (label or "").lower())
    if not cleaned:
        return []
    best: list[int] = [-1] * (len(cleaned) + 1)
    best[0] = 0
    for end in range(1, len(cleaned) + 1):
        for start in range(max(0, end - _MAX_WORD_LENGTH), end):
            if best[start] < 0:
                continue
            if cleaned[start:end] in COMMON_DOMAIN_WORDS:
                best[end] = max(best[end], best[start] + 1)
    if best[-1] < 0:
        return []
    segments: list[str] = []
    end = len(cleaned)
    while end > 0:
        for start in range(max(0, end - _MAX_WORD_LENGTH), end):
            if best[start] == best[end] - 1 and cleaned[start:end] in COMMON_DOMAIN_WORDS:
                segments.append(cleaned[start:end])
                end = start
                break
        else:  # pragma: no cover - unreachable when best[-1] >= 0
            return []
    return list(reversed(segments))


class GeneratedDomainProfile:
    """Assessment of how machine-generated a host's leading label looks."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.entropy = char_entropy(label)
        self.length = len(label)
        self.word_based = decomposes_into_words(label)
        self.segments = _segments(label) if self.word_based else []
        self.digit_ratio = (sum(ch.isdigit() for ch in label) / len(label)) if label else 0.0
        self.vowel_ratio = (
            sum(ch in "aeiou" for ch in label.lower()) / len(label) if label else 0.0
        )
        self.alternating = bool(re.fullmatch(r"(?:[a-z]\d){2,}", label.lower()))

    @property
    def generated(self) -> bool:
        """True when the label does not look human-chosen."""
        if self.length < 8:
            return False
        if self.word_based:
            return False
        if self.alternating:
            return True
        if self.length >= 12 and self.entropy >= 3.55:
            return True
        if self.length >= 16:
            return True
        if self.length >= 10 and self.entropy >= 3.7 and self.digit_ratio > 0.15:
            return True
        return False

    @property
    def confidence(self) -> float:
        """0..1 confidence that the label is generated."""
        if not self.generated:
            return 0.0
        score = 0.55
        if self.length >= 14:
            score += 0.1
        if self.entropy >= 3.8:
            score += 0.1
        if self.alternating:
            score += 0.15
        if self.digit_ratio > 0.2:
            score += 0.05
        return min(0.95, score)

    def explanation(self) -> str:
        parts: list[str] = []
        if self.alternating:
            parts.append("letters and digits strictly alternate (a pattern produced by domain-generation algorithms)")
        if self.word_based:
            parts.append(f"decomposes into real words: {'+'.join(self.segments)}")
        else:
            parts.append(f"cannot be segmented into dictionary words")
        parts.append(f"character entropy {self.entropy:.2f} bits/char")
        parts.append(f"length {self.length}")
        return "; ".join(parts)

    def to_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "entropy": round(self.entropy, 3),
            "length": self.length,
            "word_based": self.word_based,
            "segments": self.segments,
            "digit_ratio": round(self.digit_ratio, 3),
            "vowel_ratio": round(self.vowel_ratio, 3),
            "alternating": self.alternating,
            "generated": self.generated,
            "confidence": round(self.confidence, 3),
        }


def looks_generated(label: str) -> bool:
    """Convenience predicate around :class:`GeneratedDomainProfile`."""
    return GeneratedDomainProfile(label).generated