"""Input sanitisation for filenames, paths and free text.

The single rule enforced here
-----------------------------
**A client-supplied string is never used to build a filesystem path or a shell
argument.** Filenames are sanitised for *display*; the stored name is a
server-generated opaque key. Even if sanitisation were bypassed, containment is
re-checked by :func:`safe_join`, so defence does not rest on one layer.

Windows-specific care is deliberate: the backend container is Linux, but a
scan's metadata may be rendered by a Windows client, and reserved device names
(``CON``, ``NUL``, ``COM1``) plus drive/UNC syntax remain meaningful after
transplant. ``os.path.basename`` alone does not handle ``..\\..\\etc\\passwd``
because that separator is not a path separator on Linux.
"""

from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path

from app.core.exceptions import CyberShieldError

#: Anything outside this set is replaced. Restricted to a conservative
#: allow-list rather than a denylist, because denylists of ``< > : " / \ | ? *``
#: miss Unicode look-alikes and future special names.
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._ -]")

#: Windows reserved device names, which are unusable as filenames.
_RESERVED_NAMES: frozenset[str] = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

MAX_FILENAME_LENGTH = 120
MAX_STORED_NAME_LENGTH = 64

#: Path traversal markers checked after separator normalisation.
_TRAVERSAL_RE = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)")


class UnsafePathError(CyberShieldError):
    """Raised when a path escapes its permitted root."""

    status_code = 400
    code = "unsafe_path"
    message = "The requested path is not permitted."


def normalise_separators(value: str) -> str:
    """Convert Windows separators to ``/`` so traversal checks see the whole path.

    Without this, ``..\\..\\etc\\passwd`` is one path segment on Linux and no
    amount of Linux-side traversal checking would catch it.
    """
    return value.replace("\\", "/")


def sanitize_filename(
    filename: str | None,
    *,
    fallback: str = "upload",
    max_length: int = MAX_FILENAME_LENGTH,
) -> str:
    """Turn an arbitrary client filename into a safe **display** name.

    This is for labels and logs only - it is not a security boundary. The stored
    name is a separate server-generated key.

    >>> sanitize_filename("../../etc/passwd")
    'passwd'
    >>> sanitize_filename("invoice 2024.pdf")
    'invoice 2024.pdf'
    >>> sanitize_filename("CON.txt")
    '_CON.txt'
    >>> sanitize_filename("")
    'upload'

    Args:
        filename: Raw value from a multipart header or API payload.
        fallback: Used when nothing usable remains.
        max_length: Truncated on a character boundary, keeping the extension.

    Returns:
        A filename containing only ``[A-Za-z0-9._ -]``, with leading dots and
        traversal components removed and reserved names prefixed.
    """
    if not filename:
        return fallback

    # NFKD collapses full-width and accented look-alikes, so a filename cannot
    # impersonate a different name purely through Unicode.
    candidate = unicodedata.normalize("NFKD", filename)
    candidate = "".join(char for char in candidate if not unicodedata.combining(char))
    candidate = normalise_separators(candidate)

    # Strip directory components for *every* platform's separator convention.
    candidate = candidate.rsplit("/", 1)[-1]
    candidate = candidate.strip().strip(".")
    candidate = _SAFE_FILENAME_RE.sub("_", candidate)
    candidate = re.sub(r"_{2,}", "_", candidate).strip(" ._")

    if not candidate:
        return fallback

    stem, dot, extension = candidate.rpartition(".")
    if not dot:
        stem, extension = candidate, ""
    if stem.upper() in _RESERVED_NAMES or candidate.upper() in _RESERVED_NAMES:
        candidate = f"_{candidate}"

    if len(candidate) > max_length:
        if extension:
            ext = extension[-10:]
            stem = candidate[: max(1, max_length - len(ext) - 1)]
            candidate = f"{stem}.{ext}"
        else:
            candidate = candidate[:max_length]

    return candidate or fallback


def contains_traversal(value: str) -> bool:
    """Whether a path attempts to escape its base directory.

    >>> contains_traversal("a/../../etc/passwd")
    True
    >>> contains_traversal("a/b/c.txt")
    False
    >>> contains_traversal("..\\\\windows\\\\system32")
    True
    """
    if not value:
        return False
    normalised = normalise_separators(value)
    if "\x00" in normalised:
        return True
    return bool(_TRAVERSAL_RE.search(normalised))


def safe_join(root: Path, *parts: str) -> Path:
    """Join ``parts`` under ``root``, refusing any result outside ``root``.

    This is the containment check that must be present even if every caller
    sanitises its input: it resolves the final path and compares it against the
    resolved root, which also defeats symlink escapes planted inside ``root``.

    Raises:
        UnsafePathError: If the resolved path is not under ``root``.
    """
    root_resolved = root.resolve()
    candidate = root_resolved
    for part in parts:
        if contains_traversal(part):
            raise UnsafePathError("Path traversal sequences are not permitted.")
        if os.path.isabs(part) or (len(part) > 1 and part[1] == ":"):
            raise UnsafePathError("Absolute paths are not permitted.")
        candidate = candidate / part

    final = candidate.resolve()
    if final != root_resolved and root_resolved not in final.parents:
        raise UnsafePathError("Resolved path escapes the permitted directory.")

    return final


def generate_storage_key(suffix: str = "") -> str:
    """Server-generated, opaque filename for a stored object.

    The untrusted part of the name is *never* reused, so a malicious filename
    cannot influence where bytes land even if sanitisation were removed.
    """
    import secrets

    safe_suffix = _SAFE_FILENAME_RE.sub("", suffix.lower())[:8]
    key = secrets.token_hex(16)
    return f"{key}{('.' + safe_suffix) if safe_suffix else ''}"


def defang(value: str) -> str:
    """Make an indicator non-clickable for display in a report.

    Prevents an analyst reading a report from accidentally visiting a malicious
    host, and stops a rendered report from auto-linking a live IOC.

    >>> defang("http://evil.example.com/a")
    'hxxp://evil[.]example[.]com/a'
    """
    if not value:
        return value
    out = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    out = out.replace(".", "[.]").replace("@", "[at]")
    return out


#: HTML-significant sequences stripped before free text is stored or echoed.
_HTML_ESCAPES: tuple[tuple[str, str], ...] = (
    ("<", "&lt;"),
    (">", "&gt;"),
    ('"', "&quot;"),
    ("'", "&#x27;"),
    ("`", "&#x60;"),
)


def escape_for_display(value: str | None, max_length: int = 5000) -> str:
    """HTML-escape and truncate text destined for a report or log.

    Used in addition to, not instead of, template auto-escaping: escaping at the
    point of storage means a value cannot become active content on a later
    rendering path that forgets to escape.
    """
    if not value:
        return ""
    truncated = value[:max_length]
    for raw, encoded in _HTML_ESCAPES:
        truncated = truncated.replace(raw, encoded)
    return truncated


def sanitize_email_address(value: str | None) -> str | None:
    """Normalise an email address for storage and lookup.

    Only the local part is case-folded. The domain is lowercased because it is
    case-insensitive by RFC; local parts are *not*, because folding them would
    merge genuinely distinct mailboxes on servers that are case-sensitive.
    """
    if not value:
        return None
    cleaned = value.strip().strip("<>").strip()
    if "@" not in cleaned:
        return cleaned.lower() or None
    local, _, domain = cleaned.rpartition("@")
    return f"{local}@{domain.lower()}"


__all__ = [
    "MAX_FILENAME_LENGTH",
    "UnsafePathError",
    "contains_traversal",
    "defang",
    "escape_for_display",
    "generate_storage_key",
    "normalise_separators",
    "safe_join",
    "sanitize_email_address",
    "sanitize_filename",
]