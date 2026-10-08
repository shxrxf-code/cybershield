"""Indicator extraction from a parsed message.

Separated from :mod:`detection_engine.email.analyzer` because it is a pure
data-transformation step: everything it returns is something a human or another
tool could check independently, with no scoring or interpretation applied.

What counts as an indicator
---------------------------
An indicator is a value that is *reusable*: feeding it back into a scanner, a
blocklist or a search should find the sender's other infrastructure.  That is why
attachment filenames and body prose are not extracted here, while addresses,
message identifiers, URLs and infrastructure hostnames are.

Values are normalised but never invented.  If a field is absent it is simply not
returned, and the caller reports the gap rather than substituting a guess.
"""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .analyzer import ParsedEmail

__all__ = ["extract_indicators", "normalize_domain"]

#: Hosts whose presence in a body is not interesting on its own.
_INFRA_HOSTS = frozenset(
    {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
        "yahoo.com", "icloud.com", "me.com", "aol.com", "protonmail.com",
        "proton.me", "microsoft.com", "office.com", "office365.com",
    }
)

#: Characters legal in a hostname, plus the IDNA lead character.
_HOST_RE = re.compile(r"^[a-z0-9¡-￿](?:[a-z0-9_¡-￿-]*[a-z0-9¡-￿])?$", re.IGNORECASE)


def normalize_domain(host: str) -> str:
    """Lowercase, strip brackets/port/trailing dot and IDNA-encode *host*.

    >>> normalize_domain("  WWW.Example.COM:443. ")
    'www.example.com'
    >>> normalize_domain("")
    ''
    """
    if not host:
        return ""
    value = host.strip().strip("[]").lower().rstrip(".")
    if "@" in value:
        value = value.rpartition("@")[2]
    if value.count(":") == 1 and value.rsplit(":", 1)[1].isdigit():
        value = value.rsplit(":", 1)[0]
    value = value.rstrip(".")
    if not value:
        return ""
    try:
        ipaddress.ip_address(value.strip("[]"))
        return value.strip("[]")
    except ValueError:
        pass
    if value.endswith(".xn--") or value.startswith("xn--") or ".xn--" in value:
        return value
    try:
        return value.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return value


def _usable_domain(host: str) -> bool:
    """True when *host* is worth reporting as an indicator."""
    if not host:
        return False
    if _is_ip(host):
        return True
    if not _HOST_RE.match(host):
        return False
    # A bare label such as "localhost" or a single-word internal host is not
    # externally resolvable intelligence.
    return "." in host and len(host) > 4


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _url_hosts(url: str) -> list[str]:
    """Hostnames referenced by *url*, ignoring userinfo and the path."""
    raw = re.sub(r"^[a-z][a-z0-9+.-]*://", "", url, flags=re.IGNORECASE)
    raw = raw.split("/")[0].split("?")[0].split("#")[0]
    host = raw.rpartition("@")[2].split(":")[0]
    return [normalize_domain(host)] if host else []


def extract_indicators(
    parsed: ParsedEmail, urls: list[str] | None = None
) -> list[dict[str, str]]:
    """Return every reusable indicator found in a parsed message.

    Each entry is ``{"type": ..., "value": ..., "context": ...}``.  The result is
    deduplicated case-insensitively and ordered by type so that two runs over the
    same message produce identical output.

    *urls* are the links the caller already extracted from the body; they are
    passed in rather than re-parsed so that the caller and this module can never
    disagree about which links were present.
    """
    found: dict[tuple[str, str], dict[str, str]] = {}

    def add(kind: str, raw: str, context: str) -> None:
        value = (raw or "").strip()
        if not value:
            return
        key = (kind, value.lower())
        if key not in found:
            found[key] = {"type": kind, "value": value, "context": context}

    # ---- sender-side identifiers ---------------------------------- #
    for kind, raw, context in (
        ("email", parsed.from_address, "From header"),
        ("email", parsed.reply_to, "Reply-To header"),
        ("email", parsed.sender, "Sender header"),
        ("email", parsed.return_path, "Return-Path header"),
    ):
        if not raw:
            continue
        _, _, domain = raw.rpartition("@")
        add(kind, raw, context)
        add("domain", normalize_domain(domain), f"domain of {context}")

    if parsed.message_id:
        add("message_id", parsed.message_id, "Message-ID header")

    # Received headers name every relay the message passed through; those hosts
    # are infrastructure and belong in an indicator set.
    for index, hop in enumerate(parsed.received_chain):
        match = re.search(r"\bfrom\s+([A-Za-z0-9._-]+)", hop)
        if match:
            add("domain", normalize_domain(match.group(1)),
                f"relay host in Received chain (hop {index + 1})")

    # ---- link infrastructure --------------------------------------- #
    for url in urls or ():
        for host in _url_hosts(url):
            if _usable_domain(host) and host not in _INFRA_HOSTS:
                add("domain", host, "link target in message body")
        if url.lower().startswith(("http://", "https://")):
            add("url", url, "link in message body")

    # The list-unsubscribe address is a real sender-side endpoint even when the
    # From domain is spoofed, so it is worth capturing on its own.
    for key in ("list-unsubscribe", "list-unsubscribe-post"):
        for value in parsed.all_headers(key):
            for match in re.finditer(r"<([^>]+)>", value):
                target = match.group(1)
                if target.lower().startswith("mailto:"):
                    add("email", target[7:].split("?")[0], f"{key} header")

    return [found[key] for key in sorted(found)]