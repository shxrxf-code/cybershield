"""Cryptographic hashing of files and strings.

SHA-256 is the primary integrity identifier used throughout CyberShield and for
internal lookups. MD5 and SHA-1 are computed **only** for compatibility with
threat-intelligence feeds and third-party databases that key on them; neither is
used for integrity decisions, and both are collision-broken.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

#: Read size for streaming digests (1 MiB balances syscall count and memory).
_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class FileHashes:
    """All digests computed for a single object."""

    md5: str
    sha1: str
    sha256: str
    size_bytes: int

    @property
    def ssdeep_compatible(self) -> str:
        """Placeholder for fuzzy-hash support; see docs/limitations.md."""
        return ""

    def as_dict(self) -> dict[str, str | int]:
        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


def hash_bytes(data: bytes) -> FileHashes:
    """Compute all supported digests for an in-memory buffer."""
    return FileHashes(
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


def hash_file(path: Path) -> FileHashes:
    """Stream a file and compute all supported digests."""
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    size = 0

    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return FileHashes(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        size_bytes=size,
    )


def hash_stream(stream: BinaryIO) -> FileHashes:
    """Compute digests for a binary stream without loading it into memory."""
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    size = 0

    while chunk := stream.read(_CHUNK_SIZE):
        size += len(chunk)
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)

    return FileHashes(
        md5=md5.hexdigest(), sha1=sha1.hexdigest(), sha256=sha256.hexdigest(), size_bytes=size
    )


def verify_integrity(path: Path, expected_sha256: str) -> bool:
    """Constant-time comparison of a file against an expected digest.

    Uses :func:`hmac.compare_digest` so the comparison does not leak timing
    information about the expected digest. ``hashlib`` has no
    ``compare_digest``; the previous implementation raised ``AttributeError``.
    """
    computed = hash_file(path).sha256
    return hmac.compare_digest(computed, expected_sha256.lower())


def is_valid_hash(value: str, algorithm: str = "sha256") -> bool:
    """Validate the shape of a hexadecimal digest string."""
    expected_lengths = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
    length = expected_lengths.get(algorithm.lower())
    if length is None or len(value) != length:
        return False
    return all(char in "0123456789abcdefABCDEF" for char in value)