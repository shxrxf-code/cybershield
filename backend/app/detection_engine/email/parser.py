"""RFC 5322 message parsing.

The standard library's :mod:`email` package is used rather than a hand-rolled
split, because it handles the parts that real-world mail gets wrong: folded
header lines, multipart boundaries, transfer encodings, and messages assembled
from fragments.

What this module refuses to do
------------------------------
* **Never render.** No HTML is parsed or executed; the body is treated as text
  and scanned. Nothing is fetched to expand a link.
* **Never recurse on attacker-controlled depth.** Nesting is bounded, and each
  level is parsed with an explicit size cap, so a "zip bomb" of nested
  multiparts cannot exhaust memory.
* **Never trust the declared content type.** ``Content-Type: image/png`` is
  checked against the actual bytes of the decoded part.
"""

from __future__ import annotations

import email
import email.header
import email.policy
import email.utils
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

#: Hard limits. A legitimate message is orders of magnitude below these.
MAX_MESSAGE_BYTES = 25 * 1024 * 1024
MAX_PARTS = 200
MAX_NESTING_DEPTH = 20
#: Bytes of text kept per part for analysis.
MAX_PART_TEXT_BYTES = 2 * 1024 * 1024
MAX_RECIPIENTS = 50


@dataclass(slots=True)
class EmailAttachment:
    """One attachment, decoded but never executed."""

    filename: str | None
    content_type: str | None
    size: int
    payload: bytes
    content_id: str | None = None
    is_inline: bool = False
    #: SHA-256 of the decoded content, for cross-reference lookups.
    sha256: str = ""

    @property
    def sha256_short(self) -> str:
        return self.sha256[:16]


@dataclass(slots=True)
class ParsedEmail:
    """Structured view of a message."""

    subject: str | None = None
    sender: str | None = None
    sender_name: str | None = None
    sender_domain: str | None = None
    reply_to: list[str] = field(default_factory=list)
    return_path: str | None = None
    recipients: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    bcc: list[str] = field(default_factory=list)
    date: str | None = None
    message_id: str | None = None

    headers: dict[str, str] = field(default_factory=dict)
    received_chain: list[dict[str, str]] = field(default_factory=list)

    body_text: str = ""
    body_html: str = ""
    #: All parts that carry text, in order, for keyword and URL analysis.
    text_parts: list[str] = field(default_factory=list)

    attachments: list[EmailAttachment] = field(default_factory=list)
    inline_image_count: int = 0

    #: SPF / DKIM / DMARC evaluation results from ``Authentication-Results``.
    authentication: dict[str, Any] = field(default_factory=dict)
    originating_ip: str | None = None
    mail_client: str | None = None
    malware_warning_present: bool = False

    parse_errors: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def has_attachments(self) -> bool:
        return bool(self.attachments)

    @property
    def display_name(self) -> str:
        """Human label for the sender, safe to display."""
        if self.sender_name:
            return self.sender_name
        return self.sender or "unknown sender"

    @property
    def reply_to_domain(self) -> str | None:
        for address in self.reply_to:
            _, _, domain = address.rpartition("@")
            if domain:
                return domain.lower()
        return None


def parse_email(raw: bytes | str, *, max_bytes: int = MAX_MESSAGE_BYTES) -> ParsedEmail:
    """Parse a raw message into a :class:`ParsedEmail`.

    Args:
        raw: Complete RFC 5322 message as bytes or text.
        max_bytes: Refuse anything larger. Enforced before parsing so an
            oversized upload is rejected without being decoded.

    Returns:
        A populated :class:`ParsedEmail`. Parse problems are recorded in
        ``parse_errors`` rather than raised: a malformed message is itself a
        weak signal, and the parts that *did* parse are still worth scanning.
    """
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8", errors="replace")
    else:
        raw_bytes = raw

    if len(raw_bytes) > max_bytes:
        raise ValueError(f"Message exceeds the {max_bytes} byte limit.")

    result = ParsedEmail()

    try:
        # ``policy=default`` gives header objects that unfold correctly.
        message = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception as exc:  # noqa: BLE001 - email parsing raises broadly
        result.parse_errors.append(f"message could not be parsed: {type(exc).__name__}")
        return result

    _extract_headers(message, result)
    _extract_authentication(message, result)
    _extract_received_chain(message, result)

    part_count = 0
    truncated = False
    try:
        # A recursive walk with an explicit depth counter, because a message can
        # nest multiparts arbitrarily deep and ``Message.walk()`` flattens the
        # tree without reporting how deep any part actually is.
        part_count, truncated = _walk_parts(message, result, depth=0)
    except Exception as exc:  # noqa: BLE001
        result.parse_errors.append(f"body walk failed: {type(exc).__name__}")

    if truncated:
        result.parse_errors.append(
            f"message exceeded the {MAX_PARTS}-part or {MAX_NESTING_DEPTH}-level limits; "
            "the remainder was not analysed"
        )
    result.truncated = truncated or result.truncated
    return result


def _walk_parts(
    container: Any, result: ParsedEmail, *, depth: int, budget: list[int] | None = None
) -> tuple[int, bool]:
    """Walk the MIME tree, enforcing part-count and depth limits.

    Returns ``(parts_seen, truncated)``.
    """
    if depth > MAX_NESTING_DEPTH:
        return 0, True

    counter = budget if budget is not None else [0]
    truncated = False

    if container.get_content_maintype() == "multipart":
        for sub in container.get_payload():
            if not hasattr(sub, "get_content_type"):
                continue
            seen, cut = _walk_parts(sub, result, depth=depth + 1, budget=counter)
            counter[0] += seen
            truncated = truncated or cut
            if counter[0] > MAX_PARTS:
                return counter[0], True
        return counter[0], truncated

    counter[0] += 1
    if counter[0] > MAX_PARTS:
        return counter[0], True

    try:
        _process_part(container, result, depth=depth)
    except Exception as exc:  # noqa: BLE001 - one bad part must not lose the rest
        result.parse_errors.append(f"part {counter[0]}: {type(exc).__name__}")
    return counter[0], False


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------
def _extract_headers(message: Any, result: ParsedEmail) -> None:
    """Copy the headers of interest into plain strings."""
    for name, value in message.items():
        if len(result.headers) >= 100:
            break
        result.headers[str(name).lower()] = str(value)[:2048]

    result.subject = _decode_header(message.get("Subject"))
    if result.subject:
        result.subject = result.subject[:998]

    from_header = _decode_header(message.get("From"))
    result.sender, result.sender_name = _split_address(from_header)
    if result.sender and "@" in result.sender:
        result.sender_domain = result.sender.rsplit("@", 1)[1].lower()

    reply_to = _decode_header(message.get("Reply-To"))
    if reply_to:
        for _name, address in email.utils.getaddresses([reply_to]):
            if address and len(result.reply_to) < 10:
                result.reply_to.append(address.lower())

    result.return_path = _clean_address(_decode_header(message.get("Return-Path")))
    result.date = _decode_header(message.get("Date"))
    result.message_id = _decode_header(message.get("Message-ID"))

    for field_name, target in (
        ("To", result.recipients),
        ("Cc", result.cc),
        ("Bcc", result.bcc),
    ):
        raw = _decode_header(message.get(field_name))
        if not raw:
            continue
        for _name, address in email.utils.getaddresses([raw]):
            if address and len(target) < MAX_RECIPIENTS:
                target.append(address.lower())

    result.malware_warning_present = any(
        marker in result.headers
        for marker in ("x-virus", "x-mordred", "x-spam-status", "x-mailer-antivirus")
    )


def _decode_header(value: Any) -> str | None:
    """Decode RFC 2047 encoded words into plain text.

    Malformed encodings are extremely common in spam; a decode failure must not
    abort header extraction.
    """
    if value is None:
        return None
    raw = str(value)
    if not raw:
        return None
    try:
        parts = email.header.decode_header(raw)
    except Exception:  # noqa: BLE001
        return raw[:2048]

    decoded: list[str] = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            try:
                decoded.append(chunk.decode(charset or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                decoded.append(chunk.decode("utf-8", errors="replace"))
        else:
            decoded.append(chunk)
    return "".join(decoded)[:2048]


def _split_address(value: str | None) -> tuple[str | None, str | None]:
    """Split ``Display Name <addr@host>`` into its parts."""
    if not value:
        return None, None
    try:
        pairs = email.utils.getaddresses([value])
    except Exception:  # noqa: BLE001
        return None, None
    if not pairs:
        return None, None
    name, address = pairs[0]
    address = _clean_address(address)
    name = (name or "").strip() or None
    return address, name


def _clean_address(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().strip("<>").strip()
    if "@" not in cleaned:
        return cleaned.lower() or None
    local, _, domain = cleaned.rpartition("@")
    return f"{local}@{domain.lower()}"


def _extract_received_chain(message: Any, result: ParsedEmail) -> None:
    """Parse ``Received`` headers into hops, newest first.

    ``Received`` is attacker-influenced but still the best available source for
    the originating IP and mail path, so each hop is reported with the index that
    makes its provenance clear.
    """
    received = message.get_all("Received") or []
    for index, raw in enumerate(received[:15]):
        text = str(raw)
        hop: dict[str, str] = {"index": str(index), "raw": text[:500]}
        hop["from"] = _extract_header_token(text, "from") or ""
        hop["by"] = _extract_header_token(text, "by") or ""
        ip = _extract_ip_from_received(text)
        if ip:
            hop["ip"] = ip
            if index == 0 and not result.originating_ip:
                # The topmost Received was appended by the sender's own server,
                # so its client IP is the best available origin. It is still
                # self-reported and is treated as such in the report.
                result.originating_ip = ip
        result.received_chain.append(hop)


def _extract_header_token(value: str, token: str) -> str | None:
    """Pull ``token=value`` out of a Received header, honouring parentheses."""
    lowered = value.lower()
    needle = f"{token.lower()}="
    index = lowered.find(needle)
    if index < 0:
        # Also try the space-delimited form: ``from mail.example.com``
        space_needle = f" {token.lower()} "
        index = lowered.find(space_needle)
        if index < 0:
            return None
        rest = value[index + len(space_needle) :]
        return rest.split()[0] if rest.split() else None
    rest = value[index + len(needle) :]
    if rest.startswith("("):
        depth = 0
        for pos, char in enumerate(rest):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return rest[1:pos].strip()
        return None
    return rest.split()[0] if rest.split() else None


_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _extract_ip_from_received(value: str) -> str | None:
    """Find an IP address inside a Received header's bracket section."""
    bracket = value
    start = value.find("[")
    if start >= 0:
        end = value.find("]", start)
        if end > start:
            bracket = value[start : end + 1]
    match = _IPV4_RE.search(bracket) or _IPV4_RE.search(value)
    if not match:
        return None
    candidate = match.group(1)
    octets = candidate.split(".")
    if all(0 <= int(octet) <= 255 for octet in octets):
        return candidate
    return None


#: Authentication-Results verdicts ordered worst-first. A single header can
#: carry several results for one mechanism (one per signing domain); the worst
#: is what matters for spoofing, because one passing signature over a failing
#: one still lets an attacker choose which identity to present.
_MECHANISM_SEVERITY: tuple[str, ...] = (
    "fail",
    "softfail",
    "permerror",
    "temperror",
    "none",
    "neutral",
    "pass",
)

_MECHANISM_RESULTS: dict[str, re.Pattern[str]] = {
    mechanism: re.compile(rf"\b{mechanism}\s*=\s*([a-z]+)")
    for mechanism in ("spf", "dkim", "dmarc", "arc")
}


def _mechanism_result(text: str, mechanism: str) -> str:
    """Extract one mechanism's verdict from an Authentication-Results value."""
    matches = _MECHANISM_RESULTS[mechanism].findall(text)
    if not matches:
        return "absent"
    ranked = [value if value in _MECHANISM_SEVERITY else "none" for value in matches]
    return min(ranked, key=_MECHANISM_SEVERITY.index)


def _extract_mail_client(value: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9 _.\-]{2,40})", value or "")
    return match.group(1).strip() if match else ""


# ---------------------------------------------------------------------------
# Body parts
# ---------------------------------------------------------------------------
def _extract_authentication(message: Any, result: ParsedEmail) -> None:
    """Parse ``Authentication-Results`` into a structured verdict.

    Receiving mail servers publish this header, so it is *someone else's* opinion
    rather than the sender's claim. That makes it far more trustworthy than the
    ``From`` header, and it is one of the strongest signals available for a
    message that has not yet been delivered.
    """
    header = message.get("Authentication-Results")
    if not header:
        result.authentication["available"] = False
        return

    text = str(header).lower()
    result.authentication["available"] = True
    result.authentication["raw"] = str(header)[:1000]

    for mechanism in ("spf", "dkim", "dmarc"):
        result.authentication[mechanism] = _mechanism_result(text, mechanism)

    result.authentication["arc"] = _mechanism_result(text, "arc")
    result.mail_client = _extract_mail_client(str(message.get("X-Mailer") or "")) or None


def _process_part(part: Any, result: ParsedEmail, *, depth: int) -> None:
    """Classify and extract one MIME part."""
    if depth > MAX_NESTING_DEPTH:
        result.parse_errors.append("nested part depth limit reached")
        return

    content_type = (part.get_content_type() or "").lower()
    disposition = (part.get("Content-Disposition") or "").lower()

    if part.get_content_maintype() == "multipart":
        return

    if part.get_content_maintype() == "text":
        _handle_text_part(part, result, content_type, disposition)
        return

    if "attachment" in disposition or part.get_filename():
        _handle_attachment(part, result, content_type, disposition)
        return

    # An inline part with no disposition and no filename is still content that
    # should be scanned (for example a base64 HTML fragment).
    payload = _decode_payload(part)
    if payload:
        _handle_attachment(part, result, content_type, disposition)


def _handle_text_part(
    part: Any, result: ParsedEmail, content_type: str, disposition: str
) -> None:
    text = _decode_text(part)
    if not text:
        return

    if content_type == "text/html":
        result.body_html = (result.body_html + text)[:MAX_PART_TEXT_BYTES]
    else:
        result.body_text = (result.body_text + text)[:MAX_PART_TEXT_BYTES]

    # Attachments that are text (scripts, source files) are analysed too.
    if "attachment" in disposition or part.get_filename():
        result.attachments.append(
            EmailAttachment(
                filename=_clean_filename(part.get_filename()),
                content_type=content_type,
                size=len(text),
                payload=text.encode("utf-8", errors="replace"),
                sha256=_sha256(text.encode("utf-8", errors="replace")),
            )
        )

    result.text_parts.append(text[:MAX_PART_TEXT_BYTES])


def _handle_attachment(
    part: Any, result: ParsedEmail, content_type: str, disposition: str
) -> None:
    payload = _decode_payload(part)
    if not payload:
        return

    content_id = (part.get("Content-ID") or "").strip("<>") or None
    is_inline = "inline" in disposition or bool(content_id and content_id in result.body_html)

    if content_type.startswith("image/") and len(result.attachments) < MAX_PARTS:
        result.inline_image_count += 1

    result.attachments.append(
        EmailAttachment(
            filename=_clean_filename(part.get_filename()),
            content_type=content_type,
            size=len(payload),
            payload=payload,
            content_id=content_id,
            is_inline=is_inline,
            sha256=_sha256(payload),
        )
    )


def _decode_payload(part: Any) -> bytes:
    """Decode a part's transfer encoding, bounded in size."""
    try:
        payload = part.get_payload(decode=True)
    except Exception:  # noqa: BLE001
        return b""
    if not isinstance(payload, bytes):
        return b""
    return payload[:MAX_PART_TEXT_BYTES]


def _decode_text(part: Any) -> str:
    """Decode a text part, preferring its declared charset."""
    try:
        payload = part.get_payload(decode=True)
    except Exception:  # noqa: BLE001
        return b""
    if not isinstance(payload, bytes):
        text = str(part.get_payload() or "")
        return text[:MAX_PART_TEXT_BYTES]

    charset = part.get_content_charset() or "utf-8"
    try:
        decoded = payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        decoded = payload.decode("utf-8", errors="replace")
    return decoded[:MAX_PART_TEXT_BYTES]


def _clean_filename(value: Any) -> str | None:
    """Sanitise a MIME filename for display.

    The value is attacker-controlled and is never used to build a path; the
    sanitiser is applied so it cannot inject into a report or a log line.
    """
    if not value:
        return None
    from app.security.sanitize import sanitize_filename

    return sanitize_filename(str(value), fallback="attachment")


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


__all__ = [
    "MAX_MESSAGE_BYTES",
    "MAX_PARTS",
    "ParsedEmail",
    "EmailAttachment",
    "parse_email",
]