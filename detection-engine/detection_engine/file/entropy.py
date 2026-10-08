"""Shannon-entropy and byte-distribution analysis.

What entropy can and cannot tell us
-----------------------------------
High entropy (near 8 bits/byte) means the data is **compressed, encrypted or
already random**.  That is a *strong* indicator for malware - packers, encrypted
config payloads and packed sections all compress well above the ~6.5 typical of
text - but it is not proof: JPEG, PNG, ZIP and MP4 are *supposed* to look
random.  Every finding therefore states which of the two it is and the caller
combines it with the file type.

We compute entropy over the whole file and over a sliding window so a mostly
benign file with one encrypted blob is caught.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

from ..constants import ENTROPY_HIGH, ENTROPY_PACKED
from ..models import Finding, Severity, SignalSource

__all__ = ["EntropyReport", "shannon_entropy", "byte_histogram", "analyze_entropy", "chunk_entropies"]

#: Entropy below which data is effectively plaintext.
ENTROPY_LOW = 4.0
#: Window size for the sliding analysis.
_WINDOW = 4096
#: Number of windows sampled (bounded so huge files stay cheap).
_MAX_WINDOWS = 512


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of *data* in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def byte_histogram(data: bytes, *, bins: int = 16) -> list[float]:
    """Normalised 16-bucket histogram, useful for visualising byte spread."""
    if not data:
        return [0.0] * bins
    width = 256 / bins
    buckets = [0] * bins
    for byte in data:
        buckets[min(bins - 1, int(byte / width))] += 1
    total = len(data)
    return [count / total for count in buckets]


def chunk_entropies(data: bytes, *, window: int = _WINDOW) -> list[tuple[int, float]]:
    """Entropy of each sampled window, as ``(offset, entropy)``."""
    if not data:
        return []
    if len(data) <= window:
        return [(0, shannon_entropy(data))]
    step = max(1, len(data) // _MAX_WINDOWS)
    out: list[tuple[int, float]] = []
    for offset in range(0, len(data) - window + 1, step):
        out.append((offset, shannon_entropy(data[offset : offset + window])))
    return out


@dataclass(slots=True)
class EntropyReport:
    """Aggregate entropy picture of a file."""

    whole_file: float = 0.0
    windowed: list[tuple[int, float]] = field(default_factory=list)
    max_window: float = 0.0
    min_window: float = 0.0
    high_entropy_fraction: float = 0.0
    empty_fraction: float = 0.0
    null_fraction: float = 0.0
    printable_fraction: float = 0.0
    size: int = 0

    @property
    def packed(self) -> bool:
        return self.whole_file >= ENTROPY_PACKED

    def to_dict(self) -> dict[str, object]:
        return {
            "whole_file": round(self.whole_file, 4),
            "max_window": round(self.max_window, 4),
            "min_window": round(self.min_window, 4),
            "high_entropy_fraction": round(self.high_entropy_fraction, 4),
            "empty_fraction": round(self.empty_fraction, 4),
            "null_fraction": round(self.null_fraction, 4),
            "printable_fraction": round(self.printable_fraction, 4),
            "size": self.size,
            "packed": self.packed,
        }


def analyze_entropy(data: bytes, *, max_sample: int = 8 * 1024 * 1024) -> EntropyReport:
    """Compute a full entropy report for *data*."""
    report = EntropyReport(size=len(data))
    if not data:
        return report
    sample = data[:max_sample]
    report.whole_file = shannon_entropy(sample)
    report.windowed = chunk_entropies(sample)
    if report.windowed:
        values = [value for _, value in report.windowed]
        report.max_window = max(values)
        report.min_window = min(values)
        report.high_entropy_fraction = sum(1 for v in values if v >= ENTROPY_HIGH) / len(values)
    total = len(sample)
    report.empty_fraction = sum(1 for b in sample if b == 0) / total
    report.null_fraction = sum(1 for b in sample if b == 0) / total
    report.printable_fraction = sum(1 for b in sample if 0x20 <= b < 0x7F or b in (9, 10, 13)) / total
    return report


def entropy_findings(
    report: EntropyReport,
    *,
    family: str,
    object_type: str,
) -> list[Finding]:
    """Turn an entropy report into findings, accounting for the file's type."""
    findings: list[Finding] = []
    # Formats where high entropy is expected and therefore unremarkable.
    expected_high = family in {"zip", "ooxml", "apk", "gzip", "7z", "xz", "lz4", "zstd"}
    expected_moderate = family in {"jpeg", "png", "gif", "webp", "pdf", "mp4", "mp3"}

    if report.packed and not expected_high and not expected_moderate:
        findings.append(
            Finding(
                code="FILE.HIGH_ENTROPY",
                title="File content is packed or encrypted",
                detail=(
                    f"Entropy of {report.whole_file:.2f} bits/byte is close to the "
                    "theoretical maximum of 8, which means almost every byte is "
                    "unpredictable. For a text, Office or executable file this "
                    "indicates an encrypted or packed payload that hides its real "
                    "contents from inspection."
                ),
                severity=Severity.HIGH,
                source=SignalSource.FILE_ENTROPY,
                category="payload",
                weight=16.0,
                evidence=report.to_dict(),
            )
        )
    elif report.packed and expected_high:
        findings.append(
            Finding(
                code="FILE.ENTROPY_EXPECTED",
                title="Container is compressed (expected)",
                detail=(
                    f"Entropy of {report.whole_file:.2f} bits/byte is normal for a "
                    f"{family} container and is not itself suspicious."
                ),
                severity=Severity.INFO,
                source=SignalSource.FILE_ENTROPY,
                category="structure",
                weight=0.0,
            )
        )

    # A file that is mostly NUL bytes with a small dense blob is a classic
    # dropper shape: padding plus an encrypted stage-2 payload.
    if report.empty_fraction > 0.7 and report.max_window >= ENTROPY_HIGH and report.size > 4096:
        findings.append(
            Finding(
                code="FILE.PADDED_PAYLOAD",
                title="File is mostly padding with a dense payload",
                detail=(
                    f"{report.empty_fraction:.0%} of the file is null bytes while a "
                    "region reaches high entropy. This 'sparse then dense' layout is "
                    "typical of droppers and stagers that append an encrypted "
                    "second stage."
                ),
                severity=Severity.HIGH,
                source=SignalSource.FILE_ENTROPY,
                category="payload",
                weight=18.0,
                evidence=report.to_dict(),
            )
        )

    # One encrypted window inside an otherwise readable file.
    if not expected_high and report.windowed:
        readable = [v for v in (w for _, w in report.windowed) if v < ENTROPY_LOW]
        if readable and report.max_window >= ENTROPY_HIGH and report.high_entropy_fraction < 0.2:
            offset = next(o for o, v in report.windowed if v == report.max_window)
            findings.append(
                Finding(
                    code="FILE.EMBEDDED_ENCRYPTED_BLOB",
                    title="Encrypted or compressed data embedded in a readable file",
                    detail=(
                        f"Most of the file is plain text but a {self._window_size_phrase(report)} "
                        f"region starting near byte {offset} has entropy "
                        f"{report.max_window:.2f}. Embedded blobs are used to smuggle "
                        "payloads past content filters."
                    ),
                    severity=Severity.MEDIUM,
                    source=SignalSource.FILE_ENTROPY,
                    category="payload",
                    weight=12.0,
                    evidence={"offset": offset, "entropy": round(report.max_window, 3)},
                )
            )
    return findings


def _window_size_phrase(report: EntropyReport) -> str:
    return f"{_WINDOW}-byte"