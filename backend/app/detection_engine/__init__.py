"""Shared detection-engine utilities."""

from __future__ import annotations

from app.detection_engine.entropy import (
    char_entropy,
    dominant_byte_ratio,
    shannon_entropy,
    token_entropy,
)
from app.detection_engine.text import (
    contains_any,
    count_matches,
    extract_domains,
    extract_ips,
    extract_urls,
    normalise_text,
)

__all__ = [
    "char_entropy",
    "contains_any",
    "count_matches",
    "dominant_byte_ratio",
    "extract_domains",
    "extract_ips",
    "extract_urls",
    "normalise_text",
    "shannon_entropy",
    "token_entropy",
]