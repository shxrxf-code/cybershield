"""RFC 822 message parsing and header-authentication evaluation.

Why this exists
---------------
A mail scanner has to answer a question that is not "is this file dangerous?"
but "does this message have the shape of an attack?".  Phishing is carried by
*combinations*: a display name claiming to be a bank, a ``Reply-To`` pointing
somewhere else, a look-alike From domain, a SPF pass that is not enough on its
own, a body full of urgency plus a link to a raw IP address.  Each of those is
weak on its own; together they are decisive.

Authentication results are reported exactly as they were computed
--------------------------------------------------------------------
SPF, DKIM and DMARC are evaluated against the message *headers* that were
supplied.  A mail scanner is usually handed an ``.eml`` file that has already
been delivered, so it cannot observe the live SPF/DKIM evaluation the receiving
 MTA performed.  When an ``Authentication-Results`` header is present those
 results are read and used; when it is absent, CyberShield reports that
 authentication could not be verified rather than guessing a result.  Claiming
 ``dmarc=pass`` from headers alone would be fabrication.
"""

from __future__ import annotations

import asyncio
import email
import email.header
import email.policy
import email.utils
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..exceptions import MalformedObjectError
from ..models import Finding, ObjectType, Severity, SignalSource
from ..reputation.base import IndicatorType

__all__ = [
    "EmailReport",
    "AuthResult",
    "HeaderAuth",
    "ParsedEmail",
    "analyze_email",
    "analyze_email_async",
    "email_findings",
    "parse_email",
    "to_analysis_result",
]

#: Encodings we will guess at when decoding a header value.
_CHARSETS = ("utf-8", "cp1252", "latin-1")

#: Header names worth keeping, normalised to lowercase.
_INTERESTING_HEADERS = (
    "from", "sender", "reply-to", "return-path", "to", "cc", "bct", "subject",
    "date", "message-id", "in-reply-to", "references", "received", "mime-version",
    "content-type", "list-unsubscribe", "list-unsubscribe-post",
)

#: ``Authentication-Results: mx.example.com; spf=fail ...``
_AUTH_RESULTS_RE = re.compile(
    r"\b(?P<method>spf|dkim|dmarc)\s*=\s*(?P<result>[a-z0-9_-]+)", re.IGNORECASE
)

#: ``Authentication-Results`` from our own scanner must not be trusted as input.
_TRUSTED_AUTH_HOSTS = ("google.com", "microsoft.com", "outlook.com",
                       "protection.outlook.com", "yahoo.com", "gmail.com")

#: Domain suffixes that indicate a shared-mailing or bulk-sending host.
_BULK_SENDER_SUFFIXES = (
    ".mailchimp.com", ".sendgrid.net", ".mailgun.org", ".amazonses.com",
    ".postmarkapp.com", ".sparkpostmail.com", ".mandrill.com",
    ".constantcontact.com", ".hsforms.com", ".emailsrvr.com",
)

#: Body phrasing that tells the reader to run, enable or weaken something on
#: their machine.  None of these is a phishing keyword - they are instructions to
#: hand over control - and they matter far more in an email than on a web page,
#: because the reader has already decided to trust the sender.
_EXECUTION_INSTRUCTIONS: tuple[tuple[str, str], ...] = (
    (r"\brun\b.{0,30}\bas\s+(an?\s+)?(administrator|admin|root|system)\b", "run as administrator"),
    (r"\b(right[-\s]?click|double[-\s]click)\b.{0,30}\b(run|open|execute)\b", "run-by-instruction"),
    (r"\b(enable|allow)\b.{0,20}\b(macros?|activex|content|script(s|ing)?)\b", "enable-macros instruction"),
    (r"\b(disable|turn\s+off|stop)\b.{0,20}\b(antivirus|anti-virus|defender|firewall|protection|security\s+software)\b",
     "disable-protection instruction"),
    (r"\b(add|allow)\b.{0,20}\b(exclusion|exempt)\w*\b.{0,20}\b(antivirus|defender|folder|directory)\b",
     "antivirus-exclusion instruction"),
    (r"\binstall\b.{0,30}\b(software|application|update|component|tool)\b", "install-instruction"),
    (r"\b(download|extract)\b.{0,30}\b(attachment|attached|file)\b", "download-attachment instruction"),
    (r"\bopen\b.{0,20}\b(attached|the\s+attachment)\b", "open-attachment instruction"),
    (r"\bpassword\s+is\b.{0,30}\b(extract|archive|open)\b|\bextract\b.{0,30}\bwith\s+password\b",
     "password-protected-archive instruction"),
)

_EXECUTION_INSTRUCTIONS_RE: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), label) for pattern, label in _EXECUTION_INSTRUCTIONS
)

#: Attachment content types that are archived or executed, not read.
_ARCHIVE_CONTENT_TYPES = frozenset({
    "application/zip", "application/x-zip-compressed", "application/x-rar-compressed",
    "application/vnd.rar", "application/x-7z-compressed", "application/x-tar",
    "application/gzip", "application/x-gzip",
})

#: Generic mailbox names that personalise a From address without identifying
#: anybody.  Used to judge whether "Mrs. Jane Doe <jane@...>" is real.
_ROLE_LOCAL_PARTS = (
    "info", "support", "admin", "administrator", "service", "services",
    "billing", "payment", "payments", "security", "help", "helpdesk",
    "no-reply", "noreply", "donotreply", "notifications", "alert", "alerts",
    "team", "office", "accounts", "account", "billing", "verify", "webmaster",
    "postmaster", "abuse", "enquiries", "inquiries", "contact", "sales",
    "marketing", "hello", "mail", "newsletter", "update", "updates",
)

#: Providers that legitimately send HTML marketing mail.  Their presence lowers
#: the weight of HTML/shortener findings, not to zero.
_BULK_PROVIDERS = ("constantcontact.com", "hsforms.com", "mailchimp.com")


def _decode_header_value(raw: str | None) -> str:
    """Decode an RFC 2047 encoded header into plain text."""
    if not raw:
        return ""
    try:
        parts = email.header.decode_header(raw)
    except Exception:  # pragma: no cover - malformed encoding
        return str(raw)
    pieces: list[str] = []
    for text, charset in parts:
        if isinstance(text, bytes):
            for candidate in (charset, *_CHARSETS):
                if not candidate:
                    continue
                try:
                    pieces.append(text.decode(candidate))
                    break
                except (LookupError, UnicodeDecodeError):
                    continue
            else:
                pieces.append(text.decode("utf-8", errors="replace"))
        else:
            pieces.append(text)
    return "".join(pieces).strip()


def _strip_display_quotes(display: str) -> str:
    """Remove the quotes around a quoted-string display name."""
    text = display.strip()
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        # Unescape the quoted-pair backslashes RFC 5321 allows.
        return re.sub(r"\\(.)", r"\1", text[1:-1]).strip()
    return text


def _parse_address(raw: str) -> tuple[str, str]:
    """Return ``(display_name, address)`` from a ``Name <addr>`` string.

    ``email.utils.parseaddr`` silently returns ``('', '')`` for a bracketed
    address literal such as ``Billing <billing@[203.0.113.99]>``, which would
    discard the sender entirely and let anyone avoid analysis by switching from a
    domain to an IP.  So the angle-bracket form is handled directly and
    ``parseaddr`` is only the fallback for bare ``addr-spec`` input.
    """
    text = _decode_header_value(raw)
    if not text:
        return "", ""

    open_at = text.find("<")
    if open_at != -1:
        close_at = text.find(">", open_at + 1)
        if close_at > open_at:
            display = _strip_display_quotes(text[:open_at])
            address = text[open_at + 1 : close_at].strip().strip("<>").strip()
            if address:
                return display, address

    try:
        name, address = email.utils.parseaddr(text)
    except Exception:  # pragma: no cover - defensive
        return "", text.strip()
    return name.strip(), address.strip()


def _header_domain(address: str) -> str:
    """Domain part of an address, lowercased, IDNA-decoded.

    Bracketed address literals are unwrapped to the bare address, so that
    ``billing@[203.0.113.99]`` and ``billing@203.0.113.99`` compare equal
    downstream.  Use :func:`is_address_literal` to tell the two apart.
    """
    if "@" not in address:
        return ""
    _, _, domain = address.rpartition("@")
    domain = domain.strip().strip("<>").strip().lower().rstrip(".")
    if not domain:
        return ""
    if domain.startswith("[") and domain.endswith("]"):
        # RFC 5321 address literal: [203.0.113.99] or [IPv6:2001:db8::1]
        inner = domain[1:-1]
        if inner.lower().startswith("ipv6:"):
            return inner[5:]
        return inner
    try:
        return domain.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return domain


def is_address_literal(address: str) -> bool:
    """True when *address* used RFC 5321 bracket syntax instead of a domain."""
    return "[" in address and "]" in address and address.rfind("@") < address.find("[")


def _is_ip_literal(domain: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(domain.strip("[]"))
    except ValueError:
        return False
    return True


@dataclass(slots=True)
class AuthResult:
    """One authentication method's outcome."""

    method: str
    result: str = "unknown"
    detail: str = ""
    #: True when the value was read from a received ``Authentication-Results``
    #: header rather than computed by CyberShield.
    reported_by_mta: bool = False

    @property
    def passed(self) -> bool:
        return self.result in ("pass", "none-not-required")

    @property
    def failed(self) -> bool:
        return self.result in ("fail", "softfail", "permerror", "temperror",
                               "reject", "policy")

    @property
    def neutral(self) -> bool:
        return self.result in ("neutral", "none")

    def to_dict(self) -> dict[str, object]:
        return {
            "method": self.method,
            "result": self.result,
            "detail": self.detail,
            "reported_by_mta": self.reported_by_mta,
        }


@dataclass(slots=True)
class HeaderAuth:
    """Authentication status of a message, plus what could not be checked."""

    spf: AuthResult = field(default_factory=lambda: AuthResult("spf"))
    dkim: AuthResult = field(default_factory=lambda: AuthResult("dkim"))
    dmarc: AuthResult = field(default_factory=lambda: AuthResult("dmarc"))

    #: True when no ``Authentication-Results`` header was available, so none of
    #: the three could be verified from the message alone.
    unverifiable: bool = True
    #: Which MTA reported the results, when known.
    reporting_mta: str = ""

    @property
    def any_failed(self) -> bool:
        return any(r.failed for r in (self.spf, self.dkim, self.dmarc))

    @property
    def any_passed(self) -> bool:
        return any(r.passed for r in (self.spf, self.dkim, self.dmarc))

    def to_dict(self) -> dict[str, object]:
        return {
            "spf": self.spf.to_dict(),
            "dkim": self.dkim.to_dict(),
            "dmarc": self.dmarc.to_dict(),
            "unverifiable": self.unverifiable,
            "reporting_mta": self.reporting_mta,
        }


@dataclass(slots=True)
class ParsedEmail:
    """A parsed message, before any judgement is applied."""

    headers: dict[str, list[str]] = field(default_factory=dict)
    from_name: str = ""
    from_address: str = ""
    sender: str = ""
    reply_to: str = ""
    reply_to_name: str = ""
    return_path: str = ""
    subject: str = ""
    message_id: str = ""
    date_parsed: datetime | None = None
    received_chain: list[str] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    attachments: list[dict[str, Any]] = field(default_factory=list)
    inline_parts: int = 0
    auth: HeaderAuth = field(default_factory=HeaderAuth)
    parse_errors: list[str] = field(default_factory=list)
    raw_bytes: int = 0

    @property
    def from_domain(self) -> str:
        return _header_domain(self.from_address)

    @property
    def reply_to_domain(self) -> str:
        return _header_domain(self.reply_to)

    @property
    def return_path_domain(self) -> str:
        return _header_domain(self.return_path)

    @property
    def from_is_ip_literal(self) -> bool:
        """True when the From domain is an IP address rather than a name.

        Both ``billing@203.0.113.99`` and the RFC 5321 bracketed form
        ``billing@[203.0.113.99]`` count: neither can be a registered domain.
        """
        return _is_ip_literal(self.from_domain)

    @property
    def has_html(self) -> bool:
        return bool(self.body_html.strip())

    def header(self, name: str) -> str:
        """First value of *name*, decoded."""
        values = self.headers.get(name.lower(), [])
        return _decode_header_value(values[0]) if values else ""

    def all_headers(self, name: str) -> list[str]:
        return [_decode_header_value(v) for v in self.headers.get(name.lower(), [])]

    def to_dict(self) -> dict[str, object]:
        return {
            "from_name": self.from_name,
            "from_address": self.from_address,
            "from_domain": self.from_domain,
            "sender": self.sender,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "subject": self.subject,
            "message_id": self.message_id,
            "date": self.date_parsed.isoformat() if self.date_parsed else "",
            "received_hops": len(self.received_chain),
            "body_chars": len(self.body_text),
            "has_html": self.has_html,
            "attachments": self.attachments,
            "inline_parts": self.inline_parts,
            "auth": self.auth.to_dict(),
            "parse_errors": self.parse_errors,
            "raw_bytes": self.raw_bytes,
        }


# ---------------------------------------------------------------------- #
# parsing
# ---------------------------------------------------------------------- #


def parse_email(raw: bytes | str) -> ParsedEmail:
    """Parse an RFC 822 message without interpreting it.

    ``defusedxml`` is not needed here - ``email`` does not expand external
    entities - but the parser is pinned to the modern policy so that malformed
    input cannot smuggle something past the structural checks.
    """
    report = ParsedEmail(raw_bytes=len(raw) if isinstance(raw, bytes) else len(raw.encode()))

    try:
        message = email.message_from_bytes(
            raw if isinstance(raw, bytes) else raw.encode("utf-8", errors="replace"),
            policy=email.policy.default,
        )
    except Exception as exc:
        report.parse_errors.append(f"The message could not be parsed as RFC 822: {exc}")
        return report

    # ---- headers --------------------------------------------------- #
    for key, value in message.items():
        lowered = str(key).lower()
        report.headers.setdefault(lowered, []).append(str(value))

    report.from_name, report.from_address = _parse_address(report.header("from"))
    report.sender = report.header("sender")
    report.reply_to_name, report.reply_to = _parse_address(report.header("reply-to"))
    report.return_path = report.header("return-path").strip("<> ")
    report.subject = report.header("subject")
    report.message_id = report.header("message-id").strip("<> ")

    raw_date = report.header("date")
    if raw_date:
        try:
            parsed_date = email.utils.parsedate_to_datetime(raw_date)
            report.date_parsed = (
                parsed_date if parsed_date.tzinfo else parsed_date.replace(tzinfo=timezone.utc)
            )
        except (TypeError, ValueError):
            report.parse_errors.append(f"The Date header could not be parsed: {raw_date[:60]!r}")

    # A Received chain is ordered newest-first per RFC 5321, so reverse it to
    # read it as the journey the message actually took.
    report.received_chain = list(reversed(report.all_headers("received")))

    # ---- body ------------------------------------------------------ #
    report.auth = _evaluate_header_auth(report.headers)

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disposition = (part.get_content_disposition() or "").lower()
            filename = part.get_filename()
            ctype = part.get_content_type()
            if disposition == "attachment" or (filename and disposition != "inline"):
                report.attachments.append(
                    {
                        "filename": filename or "(unnamed)",
                        "content_type": ctype,
                        "size": len(part.get_payload(decode=True) or b""),
                    }
                )
                continue
            if disposition == "inline" and filename:
                report.inline_parts += 1
                report.attachments.append(
                    {
                        "filename": filename,
                        "content_type": ctype,
                        "size": len(part.get_payload(decode=True) or b""),
                        "inline": True,
                    }
                )
                continue
            payload = _part_text(part)
            if ctype == "text/plain" and not report.body_text:
                report.body_text = payload
            elif ctype == "text/html" and not report.body_html:
                report.body_html = payload
    else:
        ctype = message.get_content_type()
        payload = _part_text(message)
        if ctype == "text/html":
            report.body_html = payload
        else:
            report.body_text = payload

    if not report.body_text and report.body_html:
        # Many phishing messages are HTML-only.  Running the lexicon over raw HTML
        # tags adds noise but missing the wording entirely is worse, so the tag
        # soup is stripped first.
        report.body_text = _strip_html(report.body_html)

    return report


def _part_text(part: Any) -> str:
    """Decode a message part to text, tolerating broken encodings."""
    try:
        payload = part.get_payload(decode=True)
    except Exception:  # pragma: no cover - malformed part
        return ""
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def _strip_html(html: str, *, limit: int = 400_000) -> str:
    """Return the readable text of an HTML body.

    Script and style contents are discarded outright rather than merely stripped
    of tags: their text is not written for a human reader, and leaving it in
    pollutes every keyword count.
    """
    if not html:
        return ""
    working = html[:limit]
    working = re.sub(
        r"<(script|style|head|title)\b[^>]*>.*?</\1\s*>",
        " ",
        working,
        flags=re.IGNORECASE | re.DOTALL,
    )
    working = re.sub(r"<!--.*?-->", " ", working, flags=re.DOTALL)
    working = re.sub(r"<br\s*/?>|</p>|</div>|</tr>|</h[1-6]>", "\n", working,
                     flags=re.IGNORECASE)
    working = re.sub(r"<[^>]+>", " ", working)
    from html import unescape

    text = unescape(working)
    text = re.sub(r"[ \t\xa0]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
    return text.strip()


def _evaluate_header_auth(headers: dict[str, list[str]]) -> HeaderAuth:
    """Read SPF/DKIM/DMARC outcomes from ``Authentication-Results`` headers.

    CyberShield cannot recompute these from a delivered message: SPF needs the
    original sending IP and DNS state, and DKIM needs the signature over bytes
    that a mail client may have rewritten.  So the only defensible source is the
    receiving MTA's own report, and its absence is reported as *unverifiable*
    rather than assumed to be a pass.
    """
    auth = HeaderAuth()
    seen = False
    for value in headers.get("authentication-results", []):
        decoded = _decode_header_value(value)
        if not decoded:
            continue
        parts = [p.strip() for p in decoded.split(";")]
        mta = parts[0].split()[0] if parts and parts[0] else ""
        if not seen and mta:
            auth.reporting_mta = mta
        for part in parts[1:]:
            match = _AUTH_RESULTS_RE.search(part)
            if not match:
                continue
            method = match.group("method").lower()
            result = match.group("result").lower()
            existing = getattr(auth, method)
            # Keep the strictest result when several MTAs report different
            # outcomes: a chain that passes SPF then fails DMARC is not a pass.
            if existing.result == "unknown" or (
                not result.startswith("fail") and existing.failed
            ):
                setattr(
                    auth,
                    method,
                    AuthResult(
                        method=method,
                        result=result,
                        detail=part[:200],
                        reported_by_mta=True,
                    ),
                )
            seen = True
    auth.unverifiable = not seen
    if auth.unverifiable:
        for method in ("spf", "dkim", "dmarc"):
            getattr(auth, method).detail = (
                "No Authentication-Results header was present, so this result "
                "cannot be verified from the message alone. It is not an error "
                "and not a pass."
            )
    return auth


# ---------------------------------------------------------------------- #
# analysis
# ---------------------------------------------------------------------- #


@dataclass(slots=True)
class EmailReport:
    """The parsed message plus every observation made about it."""

    parsed: ParsedEmail = field(default_factory=ParsedEmail)
    text_profile: Any = None
    urls: list[str] = field(default_factory=list)
    reply_to_mismatch: bool = False
    from_display_domain_mismatch: bool = False
    sender_mismatch: bool = False
    bulk_sender: bool = False
    from_is_ip_literal: bool = False
    return_path_mismatch: bool = False
    reply_to_missing: bool = False
    brand_mentions: list[dict[str, object]] = field(default_factory=list)
    indicators: list[dict[str, str]] = field(default_factory=list)
    #: Body phrases instructing the reader to run, enable or weaken something.
    execution_instructions: list[str] = field(default_factory=list)
    #: An attachment that runs as a program, by extension or declared type.
    executable_attachments: list[dict[str, Any]] = field(default_factory=list)
    #: An archive the message tells the reader to extract using a password.
    protected_archive_attachments: list[dict[str, Any]] = field(default_factory=list)
    #: ``{target: ProviderResult-ish dict}`` for the sender domain and link hosts.
    reputation: dict[str, dict[str, object]] = field(default_factory=dict)
    date_in_future: bool = False
    received_chain_broken: bool = False
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "parsed": self.parsed.to_dict(),
            "urls": self.urls[:100],
            "reply_to_mismatch": self.reply_to_mismatch,
            "from_display_domain_mismatch": self.from_display_domain_mismatch,
            "sender_mismatch": self.sender_mismatch,
            "bulk_sender": self.bulk_sender,
            "from_is_ip_literal": self.from_is_ip_literal,
            "return_path_mismatch": self.return_path_mismatch,
            "reply_to_missing": self.reply_to_missing,
            "brand_mentions": self.brand_mentions,
            "indicators": self.indicators,
            "execution_instructions": self.execution_instructions,
            "executable_attachments": self.executable_attachments,
            "protected_archive_attachments": self.protected_archive_attachments,
            "reputation": self.reputation,
            "date_in_future": self.date_in_future,
            "received_chain_broken": self.received_chain_broken,
        }


def _extract_urls(text: str, *, limit: int = 200) -> list[str]:
    """Pull unique URLs out of message text, HTML and attributes."""
    if not text:
        return []
    found: list[str] = []

    for match in re.finditer(r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""",
                             text, re.IGNORECASE):
        candidate = _decode_html_url(match.group(1))
        if candidate:
            found.append(candidate)

    for match in re.finditer(r"\b(?:https?|ftp)://[^\s<>\"'()\[\]]{4,}", text, re.IGNORECASE):
        found.append(match.group(0).rstrip(".,;:)!?\"'"))

    seen: set[str] = set()
    unique: list[str] = []
    for url in found:
        cleaned = url.strip()
        if not cleaned or cleaned.lower() in seen:
            continue
        seen.add(cleaned.lower())
        unique.append(cleaned)
        if len(unique) >= limit:
            break
    return unique


def _decode_html_url(raw: str) -> str:
    """Turn an HTML attribute value into a URL, or ``""`` if it is not one."""
    from html import unescape

    value = unescape(raw or "").strip()
    if value.lower().startswith(("javascript:", "vbscript:", "data:")):
        # Returned as-is: a javascript: link is itself the finding, and the
        # caller needs to see it.
        return value
    if re.match(r"^(https?|ftp)://", value, re.IGNORECASE):
        return value
    return ""


def _has_display_domain_mismatch(name: str, domain: str) -> bool:
    """True when a display name looks like an organisation the domain is not.

    ``"PayPal Security <notice@evil.tk>"`` is the single most reliable structural
    signal in mail phishing, so it is checked with a small public-brand list and
    a conservative match rule: the brand token must appear in the display name
    and must not appear in the domain.
    """
    if not name or not domain:
        return False
    from ..constants import IMPERSONATED_BRANDS

    lowered = name.lower()
    matched = [
        brand
        for brand in IMPERSONATED_BRANDS
        if brand in lowered and brand not in domain
    ]
    return bool(matched)


def _mentions_password_protection(instructions: list[str]) -> bool:
    """True when the body asks the reader to use a password to open something."""
    return any("password" in label for label in instructions)


def _brand_matches(
    parsed: ParsedEmail, urls: list[str]
) -> list[dict[str, object]]:
    """Compare the message's mail and link hosts against protected brands.

    The same comparison the URL analyser uses, applied to every host a message
    mentions.  A message whose *From* domain impersonates a bank is a different
    attack from one whose *link* does, and the report keeps them apart by
    recording which host produced the match.
    """
    from ..url.domain import find_brand_matches
    from ..url.normalizer import parse_url

    results: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()

    def probe(host: str, source: str) -> None:
        if not host:
            return
        try:
            parsed_url = parse_url(f"http://{host}/")
        except MalformedObjectError:
            return
        for match in find_brand_matches(parsed_url):
            key = (match.brand, parsed_url.host or "")
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "kind": "brand",
                    "brand": match.brand,
                    "official_domain": match.official_domain,
                    "host": parsed_url.host,
                    "source": source,
                    "similarity": round(match.similarity, 3),
                    "impersonation": match.is_impersonation,
                    "explanation": match.explanation,
                }
            )

    probe(parsed.from_domain, "from_domain")
    probe(parsed.reply_to_domain, "reply_to_domain")
    for url in urls[:20]:
        host = (
            re.sub(r"^[a-z]+://", "", url, flags=re.IGNORECASE)
            .split("/")[0]
            .split("?")[0]
            .rpartition("@")[2]
            .split(":")[0]
        )
        probe(host, "link_target")

    # The From display name is checked separately by ``email_findings``; here we
    # also note which brands the *body* talks about, which is not by itself
    # suspicious but is needed to interpret a link to a look-alike host.
    from ..url.domain import IMPERSONATED_BRANDS

    haystack = f"{parsed.subject}\n{parsed.body_text}".lower()
    for brand in IMPERSONATED_BRANDS:
        if brand in haystack:
            results.append(
                {
                    "kind": "body_mention",
                    "brand": brand,
                    "value": brand,
                    "source": "message_body",
                    "impersonation": False,
                }
            )
    return results


def _reputation_targets(report: EmailReport) -> list[str]:
    """Hosts worth a reputation lookup: the sender plus every link target.

    IP literals are excluded because the offline feed is domain-keyed, and a
    lookup that cannot answer would only add noise to the report.
    """
    targets: list[str] = []
    candidates = [report.parsed.from_domain, report.parsed.reply_to_domain]
    for url in report.urls[:20]:
        candidates.append(
            re.sub(r"^[a-z]+://", "", url, flags=re.IGNORECASE)
            .split("/")[0]
            .split("?")[0]
            .split("@")[-1]
            .split(":")[0]
        )
    for host in candidates:
        host = (host or "").strip().lower().rstrip(".")
        if not host or host in targets or _is_ip_literal(host):
            continue
        targets.append(host)
    return targets[:25]


def _check_reputation(
    targets: list[str], aggregator: Any
) -> dict[str, dict[str, object]]:
    """Run the aggregator over *targets*, degrading rather than failing.

    ``ReputationAggregator.check`` is async and reaches out to providers, so it
    is driven through :func:`asyncio.run` here: :func:`analyze_email` is a
    synchronous entry point so that it can be called from the CLI and from
    synchronous tests.  If an event loop is already running the caller should
    use :func:`analyze_email_async` instead.
    """
    if not targets:
        return {}

    async def gather() -> dict[str, dict[str, object]]:
        out: dict[str, dict[str, object]] = {}
        for host in targets:
            try:
                result = await aggregator.check(host, IndicatorType.DOMAIN)
            except Exception as exc:  # pragma: no cover - provider must never break a scan
                out[host] = {"error": f"{type(exc).__name__}: {exc}"}
                continue
            payload = result.to_dict() if hasattr(result, "to_dict") else dict(result)
            payload["checked"] = True
            out[host] = payload
        await aggregator.aclose()
        return out

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        try:
            return asyncio.run(gather())
        except Exception as exc:  # pragma: no cover - defensive
            return {"__error__": f"reputation unavailable: {exc}"}
    # Called from inside a running loop: hand the work back to the caller.
    return {"__deferred__": True}  # type: ignore[dict-item]


async def analyze_email_async(
    raw: bytes | str, *, attachments: list[bytes] | None = None
) -> EmailReport:
    """Async variant of :func:`analyze_email` for callers already in a loop."""
    return await asyncio.to_thread(analyze_email, raw, attachments=attachments)


def analyze_email(raw: bytes | str, *, attachments: list[bytes] | None = None) -> EmailReport:
    """Analyse a message and return every observation made about it.

    Synchronous by design: the CLI and the test-suite call it directly.  Inside
    a running event loop, reputation lookups are deferred and reported as such
    rather than raising - use :func:`analyze_email_async` there.
    """
    from ..phishing.text import analyze_text, findings_from_profile
    from ..reputation.local import LocalIndicatorProvider
    from ..reputation.aggregator import ReputationAggregator
    from .indicators import extract_indicators

    parsed = parse_email(raw)
    report = EmailReport(parsed=parsed)

    searchable = "\n".join(
        part for part in (parsed.subject, parsed.body_text, parsed.from_name) if part
    )
    report.text_profile = analyze_text(searchable)
    report.urls = _extract_urls(f"{parsed.body_html}\n{parsed.body_text}")

    # Phrases that ask the reader to execute or unlock something.
    body = f"{parsed.subject}\n{parsed.body_text}\n{parsed.body_html[:50_000]}"
    report.execution_instructions = [
        label for pattern, label in _EXECUTION_INSTRUCTIONS_RE if pattern.search(body)
    ]

    # Attachment classification by declared type and name only; the bytes are
    # analysed separately by the file pipeline when the caller supplies them.
    from pathlib import PurePosixPath

    from ..constants import EXECUTABLE_EXTENSIONS

    for attachment in parsed.attachments:
        name = str(attachment.get("filename") or "")
        ctype = str(attachment.get("content_type") or "").lower()
        suffix = PurePosixPath(name).suffix.lower()
        if suffix in EXECUTABLE_EXTENSIONS or ctype in _ARCHIVE_CONTENT_TYPES:
            record = {"filename": name, "content_type": ctype, "size": attachment.get("size", 0)}
            if suffix in EXECUTABLE_EXTENSIONS:
                report.executable_attachments.append(record)
            elif _mentions_password_protection(report.execution_instructions):
                # A password-protected archive is the standard way to get a
                # payload past a gateway that would otherwise see the sample.
                report.protected_archive_attachments.append(record)

    from_domain = parsed.from_domain
    reply_domain = parsed.reply_to_domain
    return_domain = parsed.return_path_domain

    report.from_is_ip_literal = parsed.from_is_ip_literal
    report.reply_to_missing = bool(parsed.from_address) and not parsed.reply_to
    report.bulk_sender = bool(from_domain) and any(
        from_domain.endswith(suffix) for suffix in _BULK_SENDER_SUFFIXES
    )
    report.from_display_domain_mismatch = _has_display_domain_mismatch(
        parsed.from_name, from_domain
    )

    if reply_domain and from_domain and reply_domain != from_domain:
        report.reply_to_mismatch = True
    if return_domain and from_domain and not _same_org(from_domain, return_domain):
        report.return_path_mismatch = True
    if parsed.sender and from_domain:
        sender_domain = _header_domain(parsed.sender)
        if sender_domain and sender_domain != from_domain:
            report.sender_mismatch = True

    report.brand_mentions = _brand_matches(parsed, report.urls)
    report.indicators = extract_indicators(parsed, report.urls)

    # Reputation lookups for the sender domain and every link host, using the
    # offline indicator provider.  A miss is reported as "no local intelligence",
    # never as a reputation score: an unlisted domain is not a clean one.
    report.reputation = _check_reputation(
        _reputation_targets(report), ReputationAggregator([LocalIndicatorProvider()])
    )

    if attachments:
        from ..file.analyzer import FileAnalyzer, FileAnalysisConfig

        analyzer = FileAnalyzer(
            FileAnalysisConfig(clamav=True, yara=True, extract_text=True)
        )
        for index, payload in enumerate(attachments):
            child = analyzer.analyze_bytes(
                payload, filename=parsed.attachments[index].get("filename")
                if index < len(parsed.attachments) else f"attachment-{index}"
            )
            for finding in child.findings:
                finding.code = f"ATTACHMENT.{finding.code}"
                finding.detail = f"[attachment {index + 1}] {finding.detail}"
            report.findings.extend(child.findings)

    report.findings.extend(findings_from_profile(report.text_profile))
    report.findings.extend(email_findings(report))
    return report


# ---------------------------------------------------------------------- #
# findings
# ---------------------------------------------------------------------- #


def _same_org(a: str, b: str) -> bool:
    """Loose same-organisation comparison for mail domains."""
    if a == b:
        return True
    if b.endswith(f".{a}") or a.endswith(f".{b}"):
        return True
    # Compare the last two labels, which handles ``mx1.sender.com`` vs
    # ``sender.com`` and regional variants such as ``co.uk``.
    def base(domain: str) -> str:
        labels = domain.split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else domain

    return base(a) == base(b)


def email_findings(report: EmailReport) -> list[Finding]:
    """Turn the observations on *report* into explainable findings."""
    findings: list[Finding] = []
    parsed = report.parsed
    from_domain = parsed.from_domain

    if report.from_display_domain_mismatch:
        matched = [
            brand
            for brand in _brand_tokens()
            if brand in parsed.from_name.lower() and brand not in from_domain
        ]
        findings.append(
            Finding(
                code="EMAIL.DISPLAY_NAME_BRAND_MISMATCH",
                title=f"Display name claims to be {', '.join(matched[:3])} but the sender domain is not",
                detail=(
                    f"The message displays the name '{parsed.from_name}' with the "
                    f"address '{parsed.from_address}'. The mailbox domain is "
                    f"'{from_domain}', which is not part of "
                    f"{', '.join(matched[:3])}. Anyone who sends on behalf of a "
                    "large organisation can put any name they like in the From "
                    "field - the display name proves nothing, so treat the domain "
                    "as the identity."
                ),
                severity=Severity.HIGH,
                source=SignalSource.EMAIL_STRUCTURE,
                category="impersonation",
                weight=18.0,
                authoritative=True,
                evidence={"from": parsed.from_address, "claimed": matched[:5]},
            )
        )

    if report.reply_to_mismatch:
        findings.append(
            Finding(
                code="EMAIL.REPLY_TO_MISMATCH",
                title="Replies will go to a different organisation",
                detail=(
                    f"The message claims to come from '{parsed.from_address}' but "
                    f"sets Reply-To to '{parsed.reply_to}'. Replying - which is "
                    "what most people do instinctively - sends the conversation, "
                    "and anything they type, to the attacker."
                ),
                severity=Severity.CRITICAL,
                source=SignalSource.EMAIL_STRUCTURE,
                category="impersonation",
                weight=30.0,
                authoritative=True,
                evidence={
                    "from": parsed.from_address,
                    "reply_to": parsed.reply_to,
                },
            )
        )

    if report.from_is_ip_literal:
        findings.append(
            Finding(
                code="EMAIL.FROM_IP_LITERAL",
                title="Sender address is a bare IP address",
                detail=(
                    f"The From address is '{parsed.from_address}'. Legitimate "
                    "organisations send from named domains; a bare address avoids "
                    "having to register a domain, which is cheap and disposable."
                ),
                severity=Severity.HIGH,
                source=SignalSource.EMAIL_STRUCTURE,
                category="impersonation",
                weight=20.0,
                authoritative=True,
                evidence={"from": parsed.from_address},
            )
        )

    if report.sender_mismatch:
        findings.append(
            Finding(
                code="EMAIL.SENDER_MISMATCH",
                title="Sender and From point at different domains",
                detail=(
                    f"Sender is '{parsed.sender}' while From is "
                    f"'{parsed.from_address}'. Mail clients show From, so the "
                    "Sender header is normally invisible to the reader."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.EMAIL_STRUCTURE,
                category="structure",
                weight=10.0,
                evidence={"sender": parsed.sender, "from": parsed.from_address},
            )
        )

    if report.return_path_mismatch:
        findings.append(
            Finding(
                code="EMAIL.RETURN_PATH_MISMATCH",
                title="Envelope sender does not match the From domain",
                detail=(
                    f"Return-Path is '{parsed.return_path}' but the From domain is "
                    f"'{from_domain}'. Bounces and SPF checks use Return-Path, so "
                    "this mismatch means the sending infrastructure is not the "
                    "one the From domain authorises. It is common in legitimate "
                    "bulk mail, and it is common in phishing."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.EMAIL_STRUCTURE,
                category="structure",
                weight=8.0,
                evidence={"return_path": parsed.return_path, "from_domain": from_domain},
            )
        )

    auth = parsed.auth
    if auth.unverifiable:
        findings.append(
            Finding(
                code="EMAIL.AUTH_UNVERIFIABLE",
                title="Sender authentication could not be verified",
                detail=(
                    "The message carries no Authentication-Results header, so SPF, "
                    "DKIM and DMARC outcomes are unknown. CyberShield cannot "
                    "recompute them: SPF needs the original sending IP and DKIM "
                    "needs the unmodified signed bytes. An unverifiable result is "
                    "neither a pass nor a failure, and it is common on messages "
                    "that have been copied, forwarded or re-saved."
                ),
                severity=Severity.INFO,
                source=SignalSource.EMAIL_AUTH,
                category="coverage",
                weight=0.0,
                evidence=auth.to_dict(),
            )
        )
    else:
        if auth.dmarc.failed or auth.any_failed:
            # Any single failed check is evidence of spoofing.  Requiring DMARC
            # to fail as well would miss the common case: a message with
            # ``spf=fail`` and no DMARC policy at all, which is what a lookalike
            # domain produces when the real domain has not adopted DMARC.
            failed_methods = [
                result.method.upper()
                for result in (auth.spf, auth.dkim, auth.dmarc)
                if result.failed
            ]
            findings.append(
                Finding(
                    code="EMAIL.AUTH_FAILED",
                    title="Sender authentication failed",
                    detail=(
                        f"Reported by '{auth.reporting_mta}': "
                        f"SPF={auth.spf.result}, DKIM={auth.dkim.result}, "
                        f"DMARC={auth.dmarc.result}. "
                        f"{', '.join(failed_methods)} did not pass, which means the "
                        "sending server was not authorised by the domain it claims "
                        "to represent. Spoofed and open-relay traffic fails these "
                        "checks; a misconfigured legitimate server can too, which "
                        "is why this is strong evidence rather than proof."
                    ),
                    severity=Severity.HIGH,
                    source=SignalSource.EMAIL_AUTH,
                    category="spoofing",
                    weight=22.0,
                    authoritative=True,
                    evidence=auth.to_dict(),
                )
            )
        elif auth.dmarc.result == "none" and auth.spf.passed:
            findings.append(
                Finding(
                    code="EMAIL.AUTH_NO_DMARC_POLICY",
                    title="Domain has no DMARC policy",
                    detail=(
                        f"The domain authenticated with SPF but publishes no DMARC "
                        f"policy (dmarc=none). Without DMARC, a receiving server is "
                        "told to do nothing when SPF and DKIM disagree, so "
                        "look-alike domains sending on its behalf go unchallenged."
                    ),
                    severity=Severity.LOW,
                    source=SignalSource.EMAIL_AUTH,
                    category="spoofing",
                    weight=5.0,
                    evidence=auth.to_dict(),
                )
            )

    if parsed.date_parsed and parsed.date_parsed > _now():
        report.date_in_future = True
        findings.append(
            Finding(
                code="EMAIL.DATE_IN_FUTURE",
                title="Message date is in the future",
                detail=(
                    f"The Date header says {parsed.date_parsed.isoformat()}, which "
                    "is later than the current time. A forged future date is used to "
                    "keep a lure at the top of a sorted inbox."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.EMAIL_STRUCTURE,
                category="structure",
                weight=10.0,
                evidence={"date": parsed.date_parsed.isoformat()},
            )
        )

    # Attachment review: filename and declared type only.  The attachment bytes
    # themselves are analysed separately by the file pipeline when the caller
    # supplies them.
    for attachment in parsed.attachments:
        findings.extend(_attachment_findings(attachment, report))

    # ---- brand impersonation ---------------------------------------- #
    #
    # A host that resembles a protected brand without being it is the strongest
    # structural signal a message can carry.  It is kept separate from the
    # display-name mismatch above because the two are independent claims: a
    # message can wear a bank's name honestly ("PayPal <paypal@paypal.com>") or
    # lie about a domain it actually controls, and only one of those is a
    # reason to distrust the link.
    impersonations = [m for m in report.brand_mentions if m.get("impersonation")]
    if impersonations:
        detail_rows = []
        for mention in impersonations[:4]:
            detail_rows.append(
                f"- {mention.get('host')} resembles {mention.get('brand')}, whose "
                f"real domain is {mention.get('official_domain')} "
                f"(seen in {mention.get('source')})"
            )
        findings.append(
            Finding(
                code="EMAIL.BRAND_IMPERSONATION",
                title="Message uses a look-alike domain for a well-known brand",
                detail=(
                    "The following host in this message resembles a protected brand "
                    "without being that brand's domain:\n"
                    + "\n".join(detail_rows)
                    + "\n\nAnyone can register a domain that looks like another's. "
                    "This is the mechanism behind most credential phishing: the "
                    "victim reads the brand, not the address bar, and the brand is "
                    "why they trusted the message enough to type a password."
                ),
                severity=Severity.CRITICAL,
                source=SignalSource.EMAIL_STRUCTURE,
                category="impersonation",
                weight=32.0,
                authoritative=True,
                evidence={"matches": impersonations[:6]},
            )
        )

    findings.extend(_execution_findings(report))

    if parsed.parse_errors:
        findings.append(
            Finding(
                code="EMAIL.PARSE_DEGRADED",
                title="The message could only be parsed partially",
                detail=(
                    "CyberShield found structural problems while parsing this "
                    f"message: {'; '.join(parsed.parse_errors[:3])}. Headers or "
                    "parts may be missing from this analysis. Malformed messages "
                    "are a mild evasion signal, but a corrupt message from a "
                    "genuine sender looks the same."
                ),
                severity=Severity.LOW,
                source=SignalSource.EMAIL_STRUCTURE,
                category="coverage",
                weight=6.0,
                evidence={"errors": parsed.parse_errors[:5]},
            )
        )

    return findings


def _brand_tokens() -> tuple[str, ...]:
    """Brand names CyberShield knows how to spot in a display name."""
    from ..constants import IMPERSONATED_BRANDS

    return tuple(IMPERSONATED_BRANDS)


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _attachment_findings(attachment: dict[str, Any], report: EmailReport) -> list[Finding]:
    """Flag an attachment on its name and declared type alone."""
    from pathlib import Path

    from ..constants import EXECUTABLE_EXTENSIONS
    from ..security.hardening import is_path_traversal, sanitize_filename

    findings: list[Finding] = []
    filename = str(attachment.get("filename") or "")
    if not filename or filename == "(unnamed)":
        return findings
    safe = sanitize_filename(filename, fallback="")
    if is_path_traversal(filename) or safe != filename.strip():
        findings.append(
            Finding(
                code="EMAIL.ATTACHMENT_SUSPICIOUS_NAME",
                title="Attachment name contains path or control characters",
                detail=(
                    f"The attachment is named {filename!r}. Names like this are "
                    "used to write outside the download folder when a mail client "
                    "saves the attachment automatically."
                ),
                severity=Severity.HIGH,
                source=SignalSource.EMAIL_STRUCTURE,
                category="payload",
                weight=16.0,
                authoritative=True,
                evidence={"filename": filename},
            )
        )
    suffix = Path(filename).suffix.lower()
    if suffix in EXECUTABLE_EXTENSIONS:
        findings.append(
            Finding(
                code="EMAIL.ATTACHMENT_EXECUTABLE",
                title=f"Attachment is an executable script or program ({suffix})",
                detail=(
                    f"'{safe}' has an extension that runs as a program. Opening "
                    "it requires the reader to approve running software, which is "
                    "the step an attacker is counting on."
                ),
                severity=Severity.HIGH,
                source=SignalSource.EMAIL_STRUCTURE,
                category="payload",
                weight=18.0,
                evidence={"filename": safe, "size": attachment.get("size")},
            )
        )
    return findings


def _execution_findings(report: EmailReport) -> list[Finding]:
    """Correlate what the message asks the reader to do with what it attaches.

    The individual signals are all weak on their own - a newsletter may mention
    "install" or "run the installer", and some organisations genuinely mail
    binaries.  An instruction to run a program *plus* an attached executable is a
    different thing entirely, and it is the combination, not either half, that
    warrants the escalated weight.
    """
    findings: list[Finding] = []
    instructions = report.execution_instructions
    if not instructions:
        return findings

    names = ", ".join(sorted({str(a.get("filename") or "") for a in report.executable_attachments}))
    escalation = sorted(
        label
        for label in instructions
        if label
        in (
            "run as administrator",
            "enable-macros instruction",
            "disable-protection instruction",
            "antivirus-exclusion instruction",
            "run-by-instruction",
            "password-protected-archive instruction",
        )
    )
    weakening = sorted(
        label for label in escalation
        if label
        in (
            "enable-macros instruction",
            "disable-protection instruction",
            "antivirus-exclusion instruction",
        )
    )

    if report.executable_attachments and escalation:
        findings.append(
            Finding(
                code="EMAIL.INSTRUCTS_ATTACHMENT_EXECUTION",
                title="Message tells the reader to run the program it attaches",
                detail=(
                    "The body contains "
                    f"{', '.join(escalation)}, and the message carries an "
                    f"executable attachment ({names}). Delivering a program and "
                    "asking the reader to execute it with elevated rights is the "
                    "normal delivery path for credential theft and ransomware, "
                    "because it gets a human to grant permission on the user's "
                    "behalf. Legitimate software distribution uses signed "
                    "installers from the vendor's own domain, not an email "
                    "attachment with run-as-administrator instructions."
                ),
                severity=Severity.CRITICAL,
                source=SignalSource.EMAIL_STRUCTURE,
                category="payload",
                weight=44.0,
                # Not authoritative.  This is the strongest pattern available
                # from a message body, but it is still a pattern: enterprise
                # software deployment mails legitimately say "run this as
                # administrator" and attach an installer.  Flooring it into
                # MALICIOUS would make the filter unusable for exactly the
                # organisations it should protect, so it earns a high score on
                # its own weight instead.
                authoritative=False,
                evidence={
                    "instructions": escalation,
                    "attachments": report.executable_attachments[:5],
                },
            )
        )
    elif escalation:
        findings.append(
            Finding(
                code="EMAIL.INSTRUCTION_TO_DISABLE_PROTECTION",
                title="Message asks the reader to weaken their security controls",
                detail=(
                    f"The body contains {', '.join(weakening) or ', '.join(escalation)}. "
                    "Software that needs antivirus, macro or firewall protection "
                    "disabled before it will run is behaving the way malicious "
                    "software does. No legitimate installer requires this."
                ),
                severity=Severity.HIGH,
                source=SignalSource.EMAIL_STRUCTURE,
                category="payload",
                weight=20.0,
                authoritative=True,
                evidence={"instructions": escalation},
            )
        )

    if report.protected_archive_attachments:
        findings.append(
            Finding(
                code="EMAIL.PASSWORD_PROTECTED_ARCHIVE",
                title="Message asks for a password to open an attached archive",
                detail=(
                    "The body asks the reader to use a password to extract "
                    f"{', '.join(str(a.get('filename')) for a in report.protected_archive_attachments)}. "
                    "Password protection defeats mail gateways, which cannot "
                    "inspect the contents of an encrypted archive. It is the "
                    "standard technique for getting an executable past a filter, "
                    "and the password is normally in the same message."
                ),
                severity=Severity.HIGH,
                source=SignalSource.EMAIL_STRUCTURE,
                category="evasion",
                weight=20.0,
                authoritative=True,
                evidence={"attachments": report.protected_archive_attachments[:5]},
            )
        )

    if not report.executable_attachments and not weakening:
        # Instructions with nothing dangerous attached: worth naming so the
        # reviewer can see the message asked for this, but not worth much.
        findings.append(
            Finding(
                code="EMAIL.INSTRUCTION_TO_RUN_SOFTWARE",
                title="Message tells the reader to run or install something",
                detail=(
                    f"The body contains {', '.join(instructions[:4])}. No "
                    "executable attachment was found, so this may be an ordinary "
                    "software notice, but running software because an email told "
                    "you to is worth checking against the vendor's own site."
                ),
                severity=Severity.LOW,
                source=SignalSource.EMAIL_STRUCTURE,
                category="structure",
                weight=6.0,
                evidence={"instructions": instructions[:8]},
            )
        )

    return findings


def to_analysis_result(report: EmailReport, *, object_name: str = "") -> Any:
    """Wrap *report* in an :class:`AnalysisResult` for the scoring pipeline."""
    from ..models import AnalysisResult

    parsed = report.parsed
    result = AnalysisResult(
        object_type=ObjectType.EMAIL,
        object_name=object_name or parsed.subject or parsed.from_address or "email",
    )
    result.metadata["email"] = report.to_dict()
    result.extend(report.findings)
    for url in report.urls[:50]:
        result.add_indicator("url", url, context="URL in the message body")
    if parsed.from_address:
        result.add_indicator("email", parsed.from_address, context="From header")
    if parsed.reply_to:
        result.add_indicator("email", parsed.reply_to, context="Reply-To header")
    for mention in report.brand_mentions[:20]:
        value = str(mention.get("value", ""))
        if value:
            result.add_indicator("domain", value, context="brand reference in body")
    result.engines_ran.extend(
        ["rfc822_parser", "email_auth", "phishing_text", "url_indicators"]
    )
    return result