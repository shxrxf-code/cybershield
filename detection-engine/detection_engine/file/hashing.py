"""Cryptographic hashing and safe hash-based identity.

Policy
------
* **SHA-256** is the primary integrity identifier used everywhere internally.
* **MD5** and **SHA-1** are computed only when an external threat-intelligence
  feed requires them for lookups (VirusTotal, for example, indexes all three).
  They are never used for integrity decisions because both are broken.

All functions stream their input so an attacker cannot force unbounded memory
use by declaring a huge file.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["FileHashes", "hash_bytes", "hash_file", "hash_stream", "ssdeep_like_chunksum"]

_CHUNK = 1024 * 1024


@dataclass(slots=True)
class FileHashes:
    """The full set of digests computed for one object."""

    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    sha512: str = ""
    size: int = 0
    #: Fuzzy "similar file" signature, documented in ``docs/architecture/hashing.md``.
    ssdeep: str = ""
    imphash: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def primary(self) -> str:
        """The identifier CyberShield uses internally."""
        return self.sha256

    def to_dict(self, *, include_weak: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "sha256": self.sha256,
            "size": self.size,
        }
        if include_weak:
            # MD5/SHA-1 are exposed only for third-party lookup compatibility and
            # are explicitly labelled as non-security identifiers.
            payload["sha1"] = self.sha1
            payload["md5"] = self.md5
        if self.ssdeep:
            payload["ssdeep"] = self.ssdeep
        if self.extra:
            payload["extra"] = dict(self.extra)
        return payload


def hash_bytes(data: bytes) -> FileHashes:
    """Hash an in-memory buffer."""
    return hash_stream([data])


def hash_file(path: str | os.PathLike[str]) -> FileHashes:
    """Hash a file on disk without loading it into memory."""
    file_hashes = FileHashes()
    digests = {
        "md5": hashlib.md5(usedforsecurity=False),
        "sha1": hashlib.sha1(usedforsecurity=False),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512(),
    }
    size = 0
    with open(path, "rb") as handle:
        while True:
            block = handle.read(_CHUNK)
            if not block:
                break
            size += len(block)
            for digest in digests.values():
                digest.update(block)
    file_hashes.md5 = digests["md5"].hexdigest()
    file_hashes.sha1 = digests["sha1"].hexdigest()
    file_hashes.sha256 = digests["sha256"].hexdigest()
    file_hashes.sha512 = digests["sha512"].hexdigest()
    file_hashes.size = size
    return file_hashes


def hash_stream(blocks: list[bytes] | tuple[bytes, ...]) -> FileHashes:
    """Hash a sequence of byte blocks."""
    file_hashes = FileHashes()
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    size = 0
    for block in blocks:
        if not block:
            continue
        size += len(block)
        md5.update(block)
        sha1.update(block)
        sha256.update(block)
        sha512.update(block)
    file_hashes.md5 = md5.hexdigest()
    file_hashes.sha1 = sha1.hexdigest()
    file_hashes.sha256 = sha256.hexdigest()
    file_hashes.sha512 = sha512.hexdigest()
    file_hashes.size = size
    return file_hashes


def ssdeep_like_chunksum(data: bytes, *, chunk_size: int = 3, max_chunks: int = 4096) -> str:
    """A dependency-free, deliberately weak context-hash.

    **Not ssdeep.**  Real ssdeep needs C extensions.  This produces a rolling
    checksum over fixed-size chunks so two files that differ only in a small
    region still produce *different* digests from their SHA-256 while remaining
    stable and cheap.  It is documented as a similarity aid, never a security
    control.
    """
    if not data:
        return ""
    digest = hashlib.blake2b(digest_size=8)
    for index in range(0, min(len(data), chunk_size * max_chunks), chunk_size):
        digest.update(data[index : index + chunk_size])
    return f"{chunk_size}:{digest.hexdigest()}"


def compare_hash(left: str, right: str) -> bool:
    """Timing-safe digest comparison."""
    return hmac.compare_digest((left or "").lower(), (right or "").lower())


def is_valid_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def resolve_sample_path(root: str | Path, sha256: str) -> Path | None:
    """Locate a previously stored sample by digest, refusing path traversal."""
    from ..security.hardening import safe_join

    if not is_valid_sha256(sha256):
        return None
    candidate = safe_join(root, sha256[:2], sha256[2:])
    return candidate if candidate.exists() else None