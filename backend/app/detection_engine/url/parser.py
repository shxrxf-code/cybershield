"""URL parsing, normalisation and feature extraction.

Design notes
------------
The parser is deliberately paranoid because it is the front door to the network
fetch layer. It mirrors browser resolution rules closely enough to detect
parser-differential attacks while never *fetching* anything itself.

Handled deliberately:

* Control characters and whitespace inside the URL (request-splitting defence).
* Backslashes, which several browsers normalise to ``/`` and which therefore let
  ``https://trusted.com\\@evil.com`` confuse naive validators.
* Embedded credentials (``user:pass@host``) which are almost always phishing.
* IDN/punycode hosts, so that ``аpple.com`` (Cyrillic а) is distinguishable from
  ``apple.com`` (Latin a).
* Percent-encoding, both to decode for display and to measure obfuscation.
* IPv4 literals including decimal/octal/hex encodings such as ``0x7f.1``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from app.detection_engine.entropy import char_entropy
from app.schemas.common import Severity

# ---------------------------------------------------------------------------
# Public suffix handling
# ---------------------------------------------------------------------------
# A full Public Suffix List is several thousand entries and changes daily. This
# module ships a curated set covering the multi-label suffixes most relevant to
# phishing (identity, government and finance TLDs), and falls back to "last label
# is the suffix" for everything else. The fallback is safe for our purpose
# because a wrong suffix boundary can only make eTLD+1 slightly wrong; it never
# causes a false negative on the *host* itself, which is what verdict logic uses.
MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk", "nhs.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "lg.jp", "ed.jp",
        "co.kr", "or.kr", "ne.kr", "go.kr", "re.kr", "pe.kr",
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
        "com.mx", "org.mx", "gob.mx", "edu.mx",
        "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "firm.in",
        "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
        "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk", "idv.hk",
        "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
        "co.za", "org.za", "net.za", "gov.za", "ac.za", "web.za",
        "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "k12.tr",
        "com.ru", "net.ru", "org.ru", "edu.ru", "gov.ru", "msk.ru", "spb.ru",
        "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua", "in.ua", "kiev.ua",
        "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl", "waw.pl",
        "co.il", "org.il", "net.il", "gov.il", "ac.il", "muni.il",
        "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
        "com.co", "net.co", "nom.co", "edu.co", "gov.co",
        "com.my", "net.my", "org.my", "gov.my", "edu.my",
        "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
        "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
        "co.id", "or.id", "ac.id", "go.id", "web.id",
        "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
        "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
        "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
        "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
        "co.ke", "or.ke", "ac.ke", "go.ke",
        "com.gr", "net.gr", "org.gr", "gov.gr", "edu.gr",
        "com.es", "org.es", "gob.es", "edu.es", "nom.es",
        "com.pt", "org.pt", "gov.pt", "edu.pt", "nom.pt",
        "com.de", "co.de",
        "co.uz", "com.uz", "org.uz",
        "com.by", "net.by",
        "github.io", "gitlab.io", "pages.dev", "workers.dev", "netlify.app",
        "vercel.app", "herokuapp.com", "web.app", "firebaseapp.com",
        "s3.amazonaws.com", "blob.core.windows.net", "azurewebsites.net",
        "000webhostapp.com", "repl.co", "glitch.me", "surge.sh",
        "duckdns.org", "no-ip.org", "ngrok.io", "ngrok-free.app",
        "trycloudflare.com", "serveo.net", "localtunnel.me",
        "sharepoint.com", "my.canva.site", "blogspot.com",
    }
)

#: Top-level domains disproportionately abused in phishing, graded by relative
#: abuse rate drawn from public phishing-feed statistics.
#:
#: The tier drives the severity the URL analyser assigns, so the two cannot drift
#: apart. Free and abuse-prone TLDs remain the legitimate home of many small
#: businesses, so this can never carry a verdict on its own: combined with a
#: deceptive structure it is a strong signal, alone it stays LOW at most.
ABUSE_TLD_TIERS: dict[str, tuple[Severity, float]] = {
    # Tier 1 - almost entirely disposable domains; the dominant choice for
    # throwaway phishing infrastructure.
    "tk": (Severity.MEDIUM, 0.55),
    "ml": (Severity.MEDIUM, 0.55),
    "ga": (Severity.MEDIUM, 0.50),
    "cf": (Severity.MEDIUM, 0.50),
    "gq": (Severity.MEDIUM, 0.50),
    "top": (Severity.MEDIUM, 0.45),
    "click": (Severity.MEDIUM, 0.45),
    "link": (Severity.MEDIUM, 0.42),
    "country": (Severity.MEDIUM, 0.42),
    "kim": (Severity.MEDIUM, 0.42),
    "gdn": (Severity.MEDIUM, 0.42),
    "icu": (Severity.MEDIUM, 0.45),
    "bond": (Severity.MEDIUM, 0.42),
    "wang": (Severity.MEDIUM, 0.42),
    "cyou": (Severity.MEDIUM, 0.42),
    "xyz": (Severity.MEDIUM, 0.40),
    "work": (Severity.MEDIUM, 0.40),
    "science": (Severity.MEDIUM, 0.40),
    "party": (Severity.MEDIUM, 0.40),
    "review": (Severity.MEDIUM, 0.40),
    "stream": (Severity.MEDIUM, 0.40),
    "bid": (Severity.MEDIUM, 0.40),
    "trade": (Severity.MEDIUM, 0.40),
    "win": (Severity.MEDIUM, 0.42),
    "men": (Severity.MEDIUM, 0.40),
    "loan": (Severity.MEDIUM, 0.40),
    "download": (Severity.MEDIUM, 0.42),
    "racing": (Severity.MEDIUM, 0.40),
    "faith": (Severity.MEDIUM, 0.40),
    "cricket": (Severity.MEDIUM, 0.40),
    "accountant": (Severity.MEDIUM, 0.40),
    "webcam": (Severity.MEDIUM, 0.40),
    "quest": (Severity.MEDIUM, 0.40),
    "sbs": (Severity.MEDIUM, 0.40),
    "date": (Severity.MEDIUM, 0.38),
    "cam": (Severity.MEDIUM, 0.38),
    "buzz": (Severity.MEDIUM, 0.38),
    "monster": (Severity.MEDIUM, 0.38),
    "rest": (Severity.MEDIUM, 0.40),
    "fit": (Severity.MEDIUM, 0.38),
    # Tier 2 - heavily targeted for brand abuse but with legitimate long-standing
    # use, so capped at LOW.
    "zip": (Severity.LOW, 0.30),
    "mov": (Severity.LOW, 0.30),
    "lol": (Severity.LOW, 0.25),
    "su": (Severity.LOW, 0.28),
    "ws": (Severity.LOW, 0.30),
    "ru": (Severity.LOW, 0.30),
    "cn": (Severity.LOW, 0.28),
    "me": (Severity.LOW, 0.25),
}

#: Convenience view for membership tests.
HIGH_RISK_TLDS: frozenset[str] = frozenset(ABUSE_TLD_TIERS)

#: TLDs belonging to government, military or civic namespaces. Impersonating
#: these is a strong phishing signal.
GOVERNMENT_TLDS: frozenset[str] = frozenset(
    {"gov", "mil", "int", "gov.uk", "gov.au", "gov.br", "gov.in", "gov.za", "gov.ng"}
)

# Known URL shorteners — an expanding list is maintained in threat_intel.
URL_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "lnkd.in", "t.ly",
        "shorte.st", "adf.ly", "bc.vc", "s.id", "tiny.cc", "soo.gd", "clck.ru",
        "v.gd", "qr.ae", "bit.do", "linktr.ee", "shorturl.gg", "soo.gd",
    }
)

_PUNYCODE_PREFIX = "xn--"

_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.\-]*):", re.IGNORECASE)

# Characters that should not appear literally in a hostname.
_HOST_ILLEGAL_RE = re.compile(r"[\s/@?#\\<>\"'`{}|^]")

# Hex/octal/decimal encoded IPv4 forms, e.g. 0x7f000001, 2130706433, 017700000001.
_NUMERIC_IPV4_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|0[0-7]+|\d+)$")

# Homoglyph / mixed-script detection. A hostname mixing Latin with Cyrillic or
# Greek is a classic IDN homograph attack against a Western brand.
_MIXED_SCRIPT_RE = re.compile(
    r"[Ѐ-ӿͰ-Ͽἀ-῿぀-ヿ가-힯]"
)

_SUSPICIOUS_QUERY_KEYS: frozenset[str] = frozenset(
    {
        "login", "signin", "log-in", "sign-in", "verify", "verification",
        "account", "auth", "authenticate", "session", "token", "password",
        "passwd", "pwd", "credential", "wallet", "billing", "payment",
        "update", "confirm", "secure", "security", "unlock", "validate",
        "2fa", "otp", "mfa", "recovery", "reset", "webscr", "cmd",
        "data", "dest", "redirect", "goto", "next", "return", "continue",
        "rurl", "url", "target", "dest", "redir", "continue", "window",
    }
)

_TRACKING_PARAMS: frozenset[str] = frozenset(
    {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "gclid", "fbclid", "msclkid", "mc_cid", "mc_eid", "ref", "referrer",
        "affiliate", "aff", "click_id", "igshid", "si", "spm",
    }
)


def get_public_suffix(host: str) -> tuple[str, str]:
    """Split ``host`` into ``(registered_domain, subdomain)``.

    >>> get_public_suffix("login.paypal.com.evil.co.uk")
    ('evil.co.uk', 'login.paypal.com')
    """
    host = host.lower().strip(".")
    if not host or _is_ip_literal(host):
        return host, ""

    labels = host.split(".")
    if len(labels) <= 2:
        return host, ""

    last_two = ".".join(labels[-2:])
    if last_two in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        suffix = last_two
        registered = ".".join(labels[-3:])
        return registered, ".".join(labels[:-3])

    return last_two, ".".join(labels[:-2])


def _is_ip_literal(host: str) -> bool:
    """True when ``host`` is an IPv4, IPv6 or obfuscated numeric address."""
    candidate = host.strip("[]").lower()
    if not candidate:
        return False
    if ":" in candidate:
        try:
            ipaddress.IPv6Address(candidate)
            return True
        except ValueError:
            return False
    try:
        ipaddress.IPv4Address(candidate)
        return True
    except ValueError:
        pass
    # Single-label numeric forms (decimal, hex, octal) resolve to loopback in
    # most stacks. Treat them as IP literals so the SSRF guard inspects them.
    return bool(_NUMERIC_IPV4_RE.fullmatch(candidate))


def decode_numeric_ipv4(host: str) -> str | None:
    """Decode ``0x7f.1``, ``2130706433`` and similar to dotted-quad form.

    Returns ``None`` when ``host`` is not a numeric address encoding.
    """
    candidate = host.strip("[]").lower()
    if not candidate or ":" in candidate:
        return None
    try:
        ipaddress.IPv4Address(candidate)
        return str(ipaddress.IPv4Address(candidate))
    except ValueError:
        pass

    parts = candidate.split(".")
    if not 1 <= len(parts) <= 4:
        return None

    last_index = len(parts) - 1
    values: list[int] = []
    for index, part in enumerate(parts):
        if not part:
            return None
        try:
            if part.lower().startswith("0x"):
                value = int(part, 16)
            elif len(part) > 1 and part.startswith("0"):
                value = int(part, 8)
            else:
                value = int(part, 10)
        except ValueError:
            return None
        # inet_aton() semantics: the leading n-1 fields are single bytes; the
        # final field absorbs the remaining 32 - 8*(n-1) bits. So "127.1" is
        # 127.0.0.1 and "1.2.3" is 1.2.0.3, while a lone label spans all 32 bits.
        width_bits = (32 - 8 * last_index) if index == last_index else 8
        if value < 0 or value > (1 << width_bits) - 1:
            return None
        values.append(value)

    total = 0
    for index, value in enumerate(values):
        if index == last_index:
            total += value
        else:
            total += value * (1 << (8 * (3 - index)))
    if total > 0xFFFFFFFF:
        return None
    return str(ipaddress.IPv4Address(total))


@dataclass(frozen=True)
class ParsedUrl:
    """Fully normalised view of a URL plus its structural features."""

    original: str
    normalized: str
    scheme: str
    hostname: str
    display_hostname: str
    port: int | None
    path: str
    query: str
    fragment: str
    username: str | None = None
    password: str | None = None
    registered_domain: str = ""
    public_suffix: str = ""
    subdomain: str = ""
    is_ip_literal: bool = False
    ip_version: int | None = None
    is_punycode: bool = False
    has_unicode: bool = False
    has_mixed_script: bool = False
    has_encoded_chars: bool = False
    is_https: bool = False
    is_suspicious_port: bool = False
    tld: str = ""
    features: dict[str, float | int | bool | str] = field(default_factory=dict)

    @property
    def effective_host(self) -> str:
        """Host used for reputation lookups: IP literal wins over hostname."""
        decoded = decode_numeric_ipv4(self.hostname) if self.is_ip_literal else None
        return decoded or self.hostname

    @property
    def subdomain_depth(self) -> int:
        return len([label for label in self.subdomain.split(".") if label]) if self.subdomain else 0

    @property
    def url_length(self) -> int:
        return len(self.normalized)

    @property
    def host_length(self) -> int:
        return len(self.hostname)


def parse_url(raw: str) -> ParsedUrl:
    """Parse and normalise ``raw`` into a :class:`ParsedUrl`.

    Never raises: an unparseable URL yields a record with an empty hostname so
    the caller can still report a meaningful verdict.
    """
    from app.detection_engine.text import strip_url_noise

    original = raw or ""
    working = strip_url_noise(original).replace("\\", "/")

    # Prepend a scheme so that "example.com/path" parses like a browser would.
    if not _SCHEME_RE.match(working):
        working = f"http://{working}"

    try:
        parts = urlsplit(working)
    except ValueError:
        return _empty_parsed(original, working)

    scheme = (parts.scheme or "http").lower()
    if scheme not in ("http", "https", "ftp", "ftps"):
        scheme = scheme or "http"

    raw_host = parts.hostname or ""
    # ``urlsplit.port`` raises ValueError for out-of-range or non-numeric ports,
    # so it is read defensively rather than trusted.
    try:
        port = parts.port
    except ValueError:
        port = None
    if not isinstance(port, int):
        port = None

    # ``urlsplit`` lowercases hostname but does not decode IDN.
    display_hostname = raw_host
    hostname = raw_host
    has_unicode = False
    is_punycode = False
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError:
        has_unicode = True
        try:
            hostname = raw_host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            hostname = raw_host.encode("ascii", "ignore").decode("ascii") or raw_host

    if any(label.startswith(_PUNYCODE_PREFIX) for label in hostname.split(".")):
        is_punycode = True
        # A punycode host only ever *appears* in ASCII form, so mixed-script and
        # unicode detection must run on the decoded labels. "xn--80ak6aa92e.com"
        # decodes to Cyrillic "аррӏе.com" - a homograph of "apple.com".
        decoded_labels = [_decode_punycode_label(label) for label in hostname.split(".")]
        display_hostname = ".".join(decoded_labels)
        has_unicode = any(not label.isascii() for label in decoded_labels)

    is_ip = _is_ip_literal(hostname)
    ip_version: int | None = None
    if is_ip:
        candidate = hostname.strip("[]")
        try:
            ip_version = ipaddress.ip_address(candidate).version
        except ValueError:
            decoded = decode_numeric_ipv4(candidate)
            ip_version = 4 if decoded else None
            if decoded:
                hostname = decoded

    registered_domain, subdomain = (
        ("", "") if is_ip else get_public_suffix(hostname)
    )
    public_suffix = (
        registered_domain[len(subdomain) + 1 :] if subdomain else registered_domain
    )

    path = parts.path or ""
    query = parts.query or ""
    fragment = parts.fragment or ""

    username: str | None = None
    password: str | None = None
    if parts.username is not None:
        username = unquote(parts.username)
    if parts.password is not None:
        password = unquote(parts.password)

    decoded_url = unquote(working)
    has_encoded = "%" in working

    normalized = _rebuild(scheme, hostname, port, path, query, fragment)
    tld = public_suffix.split(".")[-1] if public_suffix else ""

    features = _extract_features(
        original=original,
        normalized=normalized,
        working=working,
        decoded=decoded_url,
        hostname=hostname,
        display_hostname=display_hostname,
        path=path,
        query=query,
        fragment=fragment,
        registered_domain=registered_domain,
        subdomain=subdomain,
        is_ip=is_ip,
        scheme=scheme,
        port=port,
    )

    return ParsedUrl(
        original=original,
        normalized=normalized,
        scheme=scheme,
        hostname=hostname,
        display_hostname=display_hostname or hostname,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        username=username,
        password=password,
        registered_domain=registered_domain,
        public_suffix=public_suffix,
        subdomain=subdomain,
        is_ip_literal=is_ip,
        ip_version=ip_version,
        is_punycode=is_punycode,
        has_unicode=has_unicode,
        has_mixed_script=bool(_MIXED_SCRIPT_RE.search(display_hostname)),
        has_encoded_chars=has_encoded,
        is_https=scheme == "https",
        is_suspicious_port=bool(port and port not in (80, 443, 8080, 8443)),
        tld=tld,
        features=features,
    )


def _decode_punycode_label(label: str) -> str:
    """Decode a single punycode label back to Unicode for display and analysis.

    Returns the label unchanged when it is not punycode or cannot be decoded.
    """
    if not label.lower().startswith(_PUNYCODE_PREFIX):
        return label
    try:
        # IDNA decoding is applied per label so that the ASCII TLD is preserved.
        decoded = label.encode("ascii").decode("idna")
        return decoded or label
    except (UnicodeError, ValueError):
        return label


def _rebuild(scheme: str, host: str, port: int | None, path: str, query: str, fragment: str) -> str:
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    return urlunsplit((scheme, netloc, path or "/", query, fragment))


def _empty_parsed(original: str, working: str) -> ParsedUrl:
    return ParsedUrl(
        original=original,
        normalized=working,
        scheme="",
        hostname="",
        display_hostname="",
        port=None,
        path="",
        query="",
        fragment="",
        features=_extract_features(
            original, working, working, working, "", "", "", "", "", "", False, "", None, ""
        ),
    )


def _extract_features(
    *,
    original: str,
    normalized: str,
    working: str,
    decoded: str,
    hostname: str,
    display_hostname: str,
    path: str,
    query: str,
    fragment: str,
    registered_domain: str,
    subdomain: str,
    is_ip: bool,
    scheme: str,
    port: int | None,
) -> dict[str, float | int | bool | str]:
    """Compute the numeric feature vector consumed by heuristics and the ML model."""
    # Features are computed on the Unicode form so that script mixing and character
    # counts reflect what the user actually sees in the address bar.
    host_for_features = display_hostname or hostname
    domain_part = registered_domain or hostname

    query_keys = [pair.split("=", 1)[0].lower() for pair in query.split("&") if pair] if query else []

    encoded_count = working.count("%")
    special_chars = sum(
        working.count(ch) for ch in "@<>\"'\\^`{|}[]~"
    )
    digits_in_host = sum(ch.isdigit() for ch in host_for_features)
    hyphens_in_host = host_for_features.count("-")

    labels = [label for label in (subdomain or "").split(".") if label]
    path_segments = [segment for segment in path.split("/") if segment]

    full_text = f"{subdomain} {path} {decoded}".lower()

    from app.detection_engine.phishing.keywords import KEYWORD_WEIGHTS

    keyword_hits = sum(1 for keyword in KEYWORD_WEIGHTS if keyword in full_text)
    suspicious_key_hits = sum(1 for key in query_keys if key in _SUSPICIOUS_QUERY_KEYS)
    tracking_key_hits = sum(1 for key in query_keys if key in _TRACKING_PARAMS)

    return {
        "url_length": len(original),
        "url_length_decoded": len(decoded),
        "host_length": len(host_for_features),
        "registered_domain_length": len(domain_part),
        "dot_count_host": host_for_features.count("."),
        "subdomain_depth": len(labels),
        "hyphen_count_host": hyphens_in_host,
        "digit_count_host": digits_in_host,
        "special_char_count": special_chars,
        "encoded_char_count": encoded_count,
        "path_segment_count": len(path_segments),
        "query_param_count": len(query_keys),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "host_entropy": round(char_entropy(host_for_features), 4),
        "path_entropy": round(char_entropy(path), 4),
        "phishing_keyword_count": keyword_hits,
        "suspicious_query_key_count": suspicious_key_hits,
        "tracking_param_count": tracking_key_hits,
        "has_at_symbol": "@" in working,
        "has_port": port is not None,
        "is_ip_host": is_ip,
        "is_https": scheme == "https",
        "is_long": len(original) > 120,
        "has_punycode": hostname.startswith(_PUNYCODE_PREFIX),
        "has_unicode": not hostname.isascii(),
        "has_encoded_chars": encoded_count > 0,
        "double_slash_in_path": "//" in path,
        "has_fragment": bool(working.split("#", 1)[1]) if "#" in working else False,
    }


def is_shortened_url(url: ParsedUrl) -> bool:
    """True when the registered domain is a known URL shortener."""
    return url.registered_domain.lower() in URL_SHORTENERS or url.hostname.lower() in URL_SHORTENERS


def get_suspicious_query_keys(query: str) -> list[str]:
    """Return query parameter names associated with credential/callback abuse."""
    if not query:
        return []
    return [
        pair.split("=", 1)[0].lower()
        for pair in query.split("&")
        if pair.split("=", 1)[0].lower() in _SUSPICIOUS_QUERY_KEYS
    ]


def get_tracking_query_keys(query: str) -> list[str]:
    """Return known tracking parameter names (context for shortening services)."""
    if not query:
        return []
    return [
        pair.split("=", 1)[0].lower()
        for pair in query.split("&")
        if pair.split("=", 1)[0].lower() in _TRACKING_PARAMS
    ]


def same_registered_domain(left: ParsedUrl, right: ParsedUrl) -> bool:
    """Compare two URLs by registrable domain, ignoring www and case."""
    return _canon_domain(left) == _canon_domain(right) and bool(_canon_domain(left))


def _canon_domain(url: ParsedUrl) -> str:
    domain = (url.registered_domain or url.hostname or "").lower()
    return domain[4:] if domain.startswith("www.") else domain


def safe_encode_url(url: str) -> str:
    """Percent-encode a URL for safe logging."""
    return quote(url, safe="", encoding="utf-8", errors="replace")