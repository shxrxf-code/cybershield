"""URL normalization and safe structural parsing.

The parser is deliberately paranoid.  Attackers rely on the gap between how a
*browser* and how a *scanner* interpret a URL, so this module resolves several
classic evasion tricks explicitly and records them as evidence:

* ``http://evil.com\\@good.com`` - backslash/userinfo confusion
* ``https://good.com@evil.com`` - userinfo used to disguise the real host
* ``https://good。com`` / ``xn--`` - IDN homograph domains
* ``https://good.com%2f@evil.com`` - percent-encoded separators
* ``https://good.com.evil.com`` - suffix confusion
* ``javascript:``/``data:`` - non-HTTP schemes
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit, urlunsplit

from ..exceptions import MalformedObjectError

__all__ = ["ParsedUrl", "parse_url", "normalize_url", "registrable_domain", "is_ip_host"]

#: Schemes we will analyse.  Anything else is reported as unsupported.
SUPPORTED_SCHEMES = frozenset({"http", "https"})

#: Schemes that are outright dangerous and must never be auto-fetched.
DANGEROUS_SCHEMES = frozenset(
    {"javascript", "data", "vbscript", "file", "jar", "blob", "about", "chrome"}
)

#: Non-web schemes worth naming in a report without being fetched.
SPECIAL_SCHEMES = frozenset(
    {"mailto", "tel", "sms", "callto", "skype", "whatsapp", "market", "intent",
     "view-source", "ms-word", "msteams", "zoommtg"}
)

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_USERINFO_MARKERS = ("@",)


def _clean(raw: str) -> str:
    """Strip control characters, surrounding whitespace and unicode confusables."""
    text = unicodedata.normalize("NFKC", raw or "")
    text = _CONTROL_RE.sub("", text)
    return text.strip()


def _map_confusables(text: str) -> tuple[str, list[dict[str, str]]]:
    """Replace common full-width / homoglyph characters and report the swaps.

    Full-width Latin (``ｇｏｏｇｌｅ.com``) and Cyrillic lookalikes are a standard
    way to spoof domains in display text.  Flagging them is more useful than
    silently normalising, so we return both forms.
    """
    swaps: list[dict[str, str]] = []
    out: list[str] = []
    # Cyrillic/Greek lookalikes that render identically to ASCII letters.
    homoglyph_map = {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
        "х": "x", "у": "y", "і": "i", "һ": "h", "ԁ": "d",
        "ο": "o", "α": "a", "ρ": "p", "ν": "v",
    }
    for char in text:
        replacement = homoglyph_map.get(char.lower())
        if replacement is not None and char != replacement:
            swaps.append({"character": char, "codepoint": f"U+{ord(char):04X}",
                          "looks_like": replacement})
            out.append(replacement)
        else:
            out.append(char)
    return "".join(out), swaps


def is_ip_host(host: str) -> bool:
    """True when *host* is a bare IPv4/IPv6 literal (not a DNS name)."""
    if not host:
        return False
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


@dataclass(slots=True)
class ParsedUrl:
    """Fully normalized URL plus every structural observation made about it."""

    raw: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str
    username: str | None
    password: str | None

    # Derived / observed
    hostname_raw: str = ""
    ascii_host: str = ""
    is_ip_literal: bool = False
    ip_version: int | None = None
    ip_address: str | None = None
    is_punycode: bool = False
    decoded_host: str | None = None
    confusables: list[dict[str, str]] = field(default_factory=list)
    double_encoded: bool = False
    percent_encoded: bool = False
    has_userinfo: bool = False
    embedded_credentials: bool = False
    backslash_confusion: bool = False
    encoded_separators: bool = False
    subdomain_count: int = 0
    registrable: str = ""
    public_suffix: str = ""
    tld: str = ""
    full_url_length: int = 0
    host_length: int = 0
    path_length: int = 0
    query_params: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def host_port(self) -> str:
        if self.port is None:
            return self.host
        return f"{self.host}:{self.port}"

    @property
    def netloc(self) -> str:
        return self.host_port

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def is_supported_scheme(self) -> bool:
        return self.scheme in SUPPORTED_SCHEMES

    @property
    def normalized(self) -> str:
        """Canonical form: lowercase scheme/host, default port removed."""
        scheme = self.scheme.lower()
        netloc = self.host.lower()
        if self.port is not None and not (
            (scheme == "http" and self.port == 80) or (scheme == "https" and self.port == 443)
        ):
            netloc = f"{netloc}:{self.port}"
        path = self.path or "/"
        return urlunsplit((scheme, netloc, path, self.query, ""))

    @property
    def registrable_domain(self) -> str:
        return self.registrable or self.host

    def raw_host_labels(self) -> list[str]:
        """Host labels exactly as written by the submitter (may be punycode)."""
        if not self.hostname_raw:
            return []
        return [label for label in self.hostname_raw.strip("[]").lower().split(".") if label]


def registrable_domain(host: str) -> tuple[str, str]:
    """Best-effort eTLD+1 extraction.

    A full Public Suffix List implementation is overkill for a first release; we
    handle the common multi-label suffixes (``co.uk``, ``com.au``, ``co.jp`` ...)
    explicitly and fall back to "last two labels" otherwise.  Returning
    ``(registrable, suffix)`` so callers can show which rule was applied.
    """
    host = (host or "").lower().strip(".")
    if not host or is_ip_host(host):
        return host, ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host, ""
    two_label_suffixes = {
        "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "co.jp", "or.jp", "ne.jp",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "com.br", "com.cn",
        "com.tw", "com.hk", "com.sg", "co.in", "co.nz", "co.za", "com.mx",
        "com.ar", "co.kr", "com.tr", "com.ua", "com.pl", "co.il",
    }
    candidate_two = ".".join(labels[-2:])
    candidate_three = ".".join(labels[-3:])
    if candidate_three in two_label_suffixes:
        return candidate_three, candidate_three
    if candidate_two in two_label_suffixes:
        return candidate_two, candidate_two
    return candidate_two, labels[-1]


def _extract_query_params(query: str) -> dict[str, str]:
    params: dict[str, str] = {}
    if not query:
        return params
    for pair in query.split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        try:
            params[unquote(key)] = unquote(value)
        except Exception:  # pragma: no cover - unquote is total in practice
            params[key] = value
    return params


def _detect_double_encoding(text: str) -> tuple[bool, bool, str | None]:
    """Return ``(percent_encoded, double_encoded, decoded_once)``."""
    if not _PERCENT_RE.search(text):
        return False, False, None
    once = unquote(text)
    double = bool(_PERCENT_RE.search(once))
    return True, double, once


def parse_url(raw: str, *, add_scheme: bool = True) -> ParsedUrl:
    """Parse *raw* into a :class:`ParsedUrl`, recording evasion observations.

    Raises:
        MalformedObjectError: if the input cannot be interpreted as a URL at all.
    """
    original = raw or ""
    cleaned = _clean(original)
    if not cleaned:
        raise MalformedObjectError("The URL is empty.")

    confusable_text, confusables = _map_confusables(cleaned)
    backslash_confusion = "\\" in confusable_text

    # A bare host such as "example.com" or "example.com:8080/path" must gain a
    # scheme before it can be parsed.  A *real* scheme ("javascript:", "mailto:")
    # is left alone so the analyzer can report it as unsupported instead of
    # silently reinterpreting it as a host name.
    candidate = confusable_text
    has_authority = "//" in confusable_text
    scheme_match = _SCHEME_RE.match(confusable_text)
    declared_scheme = scheme_match.group(1).lower() if scheme_match else ""
    is_known_scheme = declared_scheme in DANGEROUS_SCHEMES or declared_scheme in SPECIAL_SCHEMES
    if add_scheme and not has_authority and (not declared_scheme or not is_known_scheme):
        candidate = f"http://{confusable_text}"

    try:
        split = urlsplit(candidate)
    except ValueError as exc:  # pragma: no cover - urlsplit rarely raises
        raise MalformedObjectError("The URL could not be parsed.") from exc

    scheme = (split.scheme or "").lower()
    if not scheme:
        raise MalformedObjectError("The URL is missing a scheme.")

    warnings: list[str] = []
    if scheme in DANGEROUS_SCHEMES:
        warnings.append(f"Non-web scheme '{scheme}' is never auto-fetched.")
    elif scheme in SPECIAL_SCHEMES:
        warnings.append(f"'{scheme}' launches an external application rather than a web page.")

    raw_netloc = split.netloc or ""
    percent_encoded, double_encoded, decoded_netloc = _detect_double_encoding(raw_netloc)
    decoded_host_source = decoded_netloc or raw_netloc
    encoded_separators = False
    host = ""
    port: int | None = None
    username: str | None = None
    password: str | None = None
    has_userinfo = False
    embedded_credentials = False

    if decoded_host_source:
        netloc = decoded_host_source.replace("\\", "/")
        if netloc != decoded_host_source:
            encoded_separators = True
        if "@" in netloc:
            userinfo, _, hostpart = netloc.rpartition("@")
            has_userinfo = True
            if ":" in userinfo:
                username, _, password = userinfo.partition(":")
                embedded_credentials = True
            else:
                username = userinfo
        else:
            hostpart = netloc
        # Reject anything with an embedded path/authority smuggled into the host.
        hostpart = hostpart.split("/")[0]
        if hostpart.startswith("["):
            closing = hostpart.find("]")
            host = hostpart[: closing + 1] if closing != -1 else hostpart
            remainder = hostpart[closing + 1 :] if closing != -1 else ""
            port_part = remainder.lstrip(":")
        else:
            host, _, port_part = hostpart.partition(":")
        if port_part:
            try:
                port = int(port_part)
                if not (0 < port < 65536):
                    warnings.append(f"Port {port} is outside the valid range.")
                    port = None
            except ValueError:
                warnings.append(f"Port '{port_part}' is not a valid port number.")

    hostname_raw = host
    host_lower = host.lower().strip("[]")
    ascii_host = host_lower
    decoded_host: str | None = None
    is_punycode = False

    if host_lower.startswith("xn--") or ".xn--" in host_lower:
        is_punycode = True
    if any(ord(ch) > 127 for ch in host_lower):
        try:
            ascii_host = host_lower.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            ascii_host = host_lower
            warnings.append("Host contains characters that are not valid IDNA.")
        if is_punycode or ascii_host.startswith("xn--") or ".xn--" in ascii_host:
            is_punycode = True
        decoded_host = host_lower

    if is_ip_host(host_lower):
        parsed_ip = _parse_ip(host_lower)
        if parsed_ip is not None:
            ascii_host = str(parsed_ip)
        if _IPV4_RE.match(host_lower) and parsed_ip is None:
            warnings.append("Host looks like an IPv4 address but is not valid.")

    registrable, suffix = registrable_domain(ascii_host)
    tld = ascii_host.rsplit(".", 1)[-1] if "." in ascii_host else ascii_host
    subdomain_count = max(0, len(ascii_host.split(".")) - len(registrable.split("."))) if registrable else 0

    labels = ascii_host.split(".") if ascii_host else []
    for label in labels:
        if not label or not _LABEL_RE.match(label):
            if label:
                warnings.append(f"Host label '{label}' contains unusual characters.")

    if backslash_confusion:
        warnings.append("Backslash used in the authority - browsers may parse this differently.")
    if encoded_separators:
        warnings.append("Encoded path separators found in the authority component.")

    return ParsedUrl(
        raw=original,
        scheme=scheme,
        host=ascii_host,
        port=port,
        path=split.path or "",
        query=split.query or "",
        fragment=split.fragment or "",
        username=username,
        password=password,
        hostname_raw=hostname_raw,
        ascii_host=ascii_host,
        is_ip_literal=is_ip_host(host_lower),
        ip_version=_parse_ip(host_lower).version if _parse_ip(host_lower) else None,
        ip_address=str(_parse_ip(host_lower)) if _parse_ip(host_lower) else None,
        is_punycode=is_punycode,
        decoded_host=decoded_host,
        confusables=confusables,
        double_encoded=double_encoded,
        percent_encoded=percent_encoded,
        has_userinfo=has_userinfo,
        embedded_credentials=embedded_credentials,
        backslash_confusion=backslash_confusion,
        encoded_separators=encoded_separators,
        subdomain_count=subdomain_count,
        registrable=registrable,
        public_suffix=suffix,
        tld=tld,
        full_url_length=len(original),
        host_length=len(host_lower),
        path_length=len(split.path or ""),
        query_params=_extract_query_params(split.query),
        warnings=warnings,
    )


def normalize_url(raw: str) -> str:
    """Convenience wrapper returning only the canonical string form."""
    return parse_url(raw).normalized