"""Entropy calculations used for obfuscation and packing detection.

Entropy is measured with Shannon's formula over byte or character frequencies.
It is a *supporting* signal only: packed, encrypted or compressed content all have
high entropy, as do ordinary images, so a high value alone is never treated as
proof of maliciousness.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Sequence

# Entropy ceiling for a uniformly distributed alphabet.
MAX_BYTE_ENTROPY = 8.0
MAX_CHAR_ENTROPY = 6.0  # log2(64) covers URL-safe character sets


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of ``data`` in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def char_entropy(text: str) -> float:
    """Return the Shannon entropy of ``text`` in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def normalised_entropy(data: bytes, ceiling: float = MAX_BYTE_ENTROPY) -> float:
    """Return byte entropy scaled to 0.0-1.0 against ``ceiling``."""
    if ceiling <= 0:
        return 0.0
    return max(0.0, min(1.0, shannon_entropy(data) / ceiling))


def token_entropy(tokens: Sequence[str]) -> float:
    """Average per-token character entropy.

    Homogenised, machine-generated tokens (e.g. DGA output) have unusually high
    average character entropy compared to human-readable words.
    """
    usable = [token for token in tokens if token]
    if not usable:
        return 0.0
    return sum(char_entropy(token) for token in usable) / len(usable)


def dominant_byte_ratio(data: bytes) -> float:
    """Fraction of the input taken by its most common byte value.

    Long runs of a single byte (classic XOR padding) push this towards 1.0 and
    are a useful packing indicator for otherwise low-entropy sections.
    """
    if not data:
        return 0.0
    return max(Counter(data).values()) / len(data)


def looks_packed(data: bytes, *, threshold: float = 7.2, min_size: int = 1024) -> bool:
    """Heuristic: does ``data`` look packed, encrypted or compressed?

    Deliberately conservative — it requires both near-maximal entropy *and* a
    non-trivial size, because short high-entropy blobs are routinely benign
    (images, archives, certificates).
    """
    if len(data) < min_size:
        return False
    return shannon_entropy(data) >= threshold