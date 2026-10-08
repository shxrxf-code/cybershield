"""Hardening helpers shared by the API, the workers and the detection engine.

Everything here is deliberately dependency-free so it can be unit tested and
reused by any entry point.
"""

from __future__ import annotations

import hashlib
import os
import re
import unicodedata
from pathlib import Path, PurePosixPath, PureWindowsPath

__all__ = [
    "sanitize_filename",
    "safe_join",
    "is_path_traversal",
    "hashed_object_key",
    "constant_time_equals",
    "truncate_utf8",
    "sanitize_header_value",
    "strip_ansi",
]

#: Characters that are unsafe in filenames on any supported platform.
_UNSAFE_CHARS = re.compile(r'[\x00-\x1f\x7f<>:"/\\|?*]')
_MULTI_DOT = re.compile(r"\.{2,}")
#: Windows reserved device names (illegal as filenames on Windows).
_RESERVED_NAMES = frozenset(
    {
        "con", "prn", "aux", "nul",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    }
)
_MAX_FILENAME = 200
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def sanitize_filename(
    raw: str | bytes | None,
    *,
    fallback: str = "upload.bin",
    max_length: int = _MAX_FILENAME,
) -> str:
    """Return a safe, printable filename derived from *raw*.

    Removes directory components (including Windows-style ones), control
    characters, reserved device names and traversal sequences.  The result never
    contains a path separator, so it is always safe to log or display.

    >>> sanitize_filename("../../etc/passwd")
    'passwd'
    >>> sanitize_filename("C:\\\\Windows\\\\System32\\\\cmd.exe")
    'cmd.exe'
    """
    if raw is None:
        return fallback
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    name = unicodedata.normalize("NFKC", raw)
    name = _ANSI_RE.sub("", name)
    name = name.replace("\x00", "")
    # Strip every path flavour: POSIX, Windows, mixed and encoded separators.
    name = name.replace("\\", "/")
    name = name.split("/")[-1]
    name = _UNSAFE_CHARS.sub("_", name)
    name = _MULTI_DOT.sub(".", name).strip()
    name = name.strip(". ")
    if not name:
        return fallback
    stem, dot, ext = name.rpartition(".")
    if dot and stem.lower() in _RESERVED_NAMES:
        name = f"{stem}_file.{ext}"
    elif name.lower() in _RESERVED_NAMES:
        name = f"{name}_file"
    if len(name) > max_length:
        stem, dot, ext = name.rpartition(".")
        if dot and len(ext) < 12:
            keep = max_length - len(ext) - 1
            name = f"{stem[:keep]}.{ext}"
        else:
            name = name[:max_length]
    return name or fallback


def is_path_traversal(candidate: str) -> bool:
    """True when *candidate* tries to escape a base directory."""
    if not candidate:
        return False
    if "\x00" in candidate:
        return True
    normalized = candidate.replace("\\", "/")
    if normalized.startswith("/"):
        return True
    depth = 0
    for part in normalized.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    # Windows drive-relative and UNC forms.
    return bool(re.match(r"^[A-Za-z]:", candidate)) or normalized.startswith("//")


def safe_join(base: str | os.PathLike[str], *parts: str) -> Path:
    """Join *parts* onto *base*, guaranteeing the result stays inside *base*.

    Raises:
        ValueError: if the resolved path would escape *base*.
    """
    root = Path(base).resolve()
    candidate = root
    for part in parts:
        cleaned = str(part).replace("\\", "/")
        if is_path_traversal(cleaned):
            raise ValueError(f"Path traversal attempt rejected: {part!r}")
        candidate = candidate / cleaned
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Resolved path escapes the base directory: {resolved}") from exc
    return resolved


def hashed_object_key(sha256: str, suffix: str = "") -> str:
    """Deterministic on-disk name for a quarantined object.

    Storing content under its SHA-256 makes quarantine idempotent and avoids
    attacker-controlled filenames ever touching the filesystem.
    """
    digest = sha256.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Expected a hex SHA-256 digest.")
    return f"{digest}{suffix}"


def constant_time_equals(left: str, right: str) -> bool:
    """Timing-safe string comparison."""
    import hmac

    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def truncate_utf8(data: bytes, limit: int) -> bytes:
    """Truncate *data* to at most *limit* bytes without splitting a character."""
    if len(data) <= limit:
        return data
    return data[:limit].decode("utf-8", errors="ignore").encode("utf-8")


def sanitize_header_value(value: str, *, max_length: int = 512) -> str:
    """Strip CR/LF and control characters from a value destined for a header."""
    cleaned = _CONTROL_RE.sub(" ", value or "")
    return cleaned[:max_length]


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from untrusted text (YARA/ClamAV output)."""
    return _ANSI_RE.sub("", text or "")


def extract_archive_member_names(data_or_path: bytes | str, *, limit: int = 5000) -> list[str]:
    """Read member names from a zip-like container without extracting anything."""
    try:
        if isinstance(data_or_path, bytes):
            import io

            with __import__("zipfile").ZipFile(io.BytesIO(data_or_path)) as zf:
                return zf.namelist()[:limit]
        with __import__("zipfile").ZipFile(data_or_path) as zf:
            return zf.namelist()[:limit]
    except Exception:
        return []


def posix_member_path(name: str) -> str:
    """Normalise an archive member path for traversal inspection."""
    return PurePosixPath(name.replace("\\", "/")).as_posix()


def windows_member_path(name: str) -> str:
    """Normalise an archive member path as Windows would interpret it."""
    return PureWindowsPath(name.replace("/", "\\")).as_posix()