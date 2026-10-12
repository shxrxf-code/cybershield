"""File hashing helpers, including the constant-time integrity check.

Regression coverage for ``verify_integrity``, which previously called a
non-existent ``hashlib.compare_digest`` and would have raised ``AttributeError``
on first use. The fix uses ``hmac.compare_digest``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.detection_engine.file.hashing import (
    hash_bytes,
    hash_file,
    hash_stream,
    is_valid_hash,
    verify_integrity,
)


def _sha256_of(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def test_hash_bytes_matches_stdlib() -> None:
    data = b"CyberShield"
    hashes = hash_bytes(data)
    assert hashes.sha256 == _sha256_of(data)
    assert hashes.size_bytes == len(data)
    # MD5/SHA-1 are only for feed compatibility but must still be populated.
    assert len(hashes.md5) == 32
    assert len(hashes.sha1) == 40


def test_hash_file_and_stream_agree(tmp_path: Path) -> None:
    payload = b"the quick brown fox" * 1000
    target = tmp_path / "sample.bin"
    target.write_bytes(payload)

    from_file = hash_file(target)
    with target.open("rb") as handle:
        from_stream = hash_stream(handle)

    assert from_file.sha256 == _sha256_of(payload)
    assert from_file.as_dict() == from_stream.as_dict()


def test_verify_integrity_accepts_and_rejects(tmp_path: Path) -> None:
    target = tmp_path / "sample.txt"
    payload = b"integrity matters"
    target.write_bytes(payload)
    digest = _sha256_of(payload)

    assert verify_integrity(target, digest) is True
    # Case-insensitive on the expected digest.
    assert verify_integrity(target, digest.upper()) is True
    assert verify_integrity(target, "0" * 64) is False


def test_verify_integrity_does_not_raise_on_bad_digest(tmp_path: Path) -> None:
    """A malformed expected digest must return False, not blow up."""
    target = tmp_path / "sample.txt"
    target.write_bytes(b"x")
    assert verify_integrity(target, "not-a-hash") is False


@pytest.mark.parametrize(
    ("value", "algorithm", "expected"),
    [
        ("a" * 64, "sha256", True),
        ("A" * 64, "sha256", True),
        ("a" * 63, "sha256", False),
        ("z" * 64, "sha256", False),
        ("a" * 32, "md5", True),
        ("a" * 40, "sha1", True),
        ("a" * 64, "nope", False),
    ],
)
def test_is_valid_hash(value: str, algorithm: str, expected: bool) -> None:
    assert is_valid_hash(value, algorithm) is expected
