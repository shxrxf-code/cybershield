"""Structural (lexical) analysis of a URL.

These checks need no network access, which makes them fast, deterministic and
usable on air-gapped deployments.  Every check below is *individually* weak
evidence; the risk engine combines them.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import unquote

from ..constants import IMPERSONATED_BRANDS, PHISHING_KEYWORDS, SUSPICIOUS_PORTS
from ..models import Finding, Severity, SignalSource
from .dga import GeneratedDomainProfile
from .normalizer import ParsedUrl, parse_url

__all__ = ["analyze_url_syntax", "extract_phishing_tokens", "shannon_entropy"]

#: Generic, non-security query parameters.  Anything outside this set is unusual
#: for a legitimate link and may indicate parameter pollution / tracking abuse.
_GENERIC_QUERY_KEYS = frozenset(
    {
        "id", "page", "lang", "language", "locale", "utm_source", "utm_medium",
        "utm_campaign", "utm_term", "utm_content", "utm_id", "gclid", "fbclid",
        "ref", "referrer", "source", "src", "q", "query", "search", "s", "p",
        "v", "t", "time", "date", "sort", "order", "filter", "type", "format",
        "output", "next", "return", "returnUrl", "redirect", "redirect_uri",
        "continue", "url", "link", "token", "key", "session", "sid", "code",
        "state", "auth", "callback", "callback_url", "client_id", "view",
        "from", "to", "subject", "message", "body", "title", "name", "file",
        "download", "action", "cmd", "op", "do", "func", "load", "download",
    }
)

_HEX_RUN = re.compile(r"(?:0x[0-9a-fA-F]{4,}|%[0-9A-Fa-f]{4,})")
_AT_SYMBOLS = re.compile(r"[@%40]")
_SCRIPTISH_PATH = re.compile(r"\.(?:php|asp|aspx|jsp|cgi|pl|shtml)(?:$|\?)", re.IGNORECASE)
_HYPHEN_RUN = re.compile(r"-{2,}")
_HYPHENS = re.compile(r"-")
_DIGITS = re.compile(r"\d")
_DOTS = re.compile(r"\.")


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character (0.0 for empty input)."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_phishing_tokens(parsed: ParsedUrl) -> dict[str, list[str]]:
    """Locate phishing lexicon tokens in the URL.

    Returns the tokens grouped by where they occur.  Keywords in the *path* of a
    known brand domain are much less interesting than keywords in the *host* of a
    unfamiliar domain, so the caller weighs location accordingly.
    """
    haystacks = {
        "host": parsed.host.lower(),
        "path": unquote(parsed.path).lower(),
        "query": unquote(parsed.query).lower(),
        "fragment": unquote(parsed.fragment).lower(),
    }
    found: dict[str, list[str]] = {}
    for location, haystack in haystacks.items():
        hits = sorted({token for token in PHISHING_KEYWORDS if token in haystack})
        if hits:
            found[location] = hits
    return found


def analyze_url_syntax(parsed: ParsedUrl) -> list[Finding]:
    """Return findings describing structural anomalies in *parsed*."""
    findings: list[Finding] = []
    url = parsed.normalized
    host = parsed.host.lower()

    # ---------------------------------------------------------------- scheme
    if parsed.scheme == "http" and not parsed.is_ip_literal:
        findings.append(
            Finding(
                code="URL.NO_TLS",
                title="Connection is not encrypted",
                detail=(
                    "The URL uses plain HTTP, so content and any submitted "
                    "credentials travel unencrypted and can be intercepted or "
                    "modified in transit."
                ),
                severity=Severity.LOW,
                source=SignalSource.URL_SYNTAX,
                category="network",
                weight=7.0,
                evidence={"scheme": parsed.scheme},
            )
        )

    # ------------------------------------------------------------- IP literal
    if parsed.is_ip_literal:
        findings.append(
            Finding(
                code="URL.IP_LITERAL_HOST",
                title="Host is a raw IP address instead of a domain name",
                detail=(
                    "Legitimate services are almost always reached through a "
                    "domain name. A literal IP is used to hide the real owner "
                    "behind cheap hosting and to bypass domain-based blocklists."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.URL_SYNTAX,
                category="network",
                weight=14.0,
                evidence={"ip": parsed.ip_address, "version": parsed.ip_version},
            )
        )
        if parsed.ip_version == 6:
            findings.append(
                Finding(
                    code="URL.IPV6_LITERAL",
                    title="IPv6 literal host",
                    detail="IPv6 literals are rarely used by legitimate phishing infrastructure.",
                    severity=Severity.LOW,
                    source=SignalSource.URL_SYNTAX,
                    category="network",
                    weight=6.0,
                    evidence={"ip": parsed.ip_address},
                )
            )

    # ------------------------------------------------------------- userinfo
    if parsed.embedded_credentials:
        findings.append(
            Finding(
                code="URL.CREDENTIALS_IN_URL",
                title="Username and password embedded in the URL",
                detail=(
                    "The URL contains an inline 'user:password@' section. This "
                    "is a classic phishing pattern used to make a malicious host "
                    "look like a trusted one, and it leaks credentials if the "
                    "link is clicked or shared."
                ),
                severity=Severity.HIGH,
                source=SignalSource.URL_SYNTAX,
                category="phishing",
                weight=20.0,
                evidence={"username_present": bool(parsed.username)},
            )
        )
    elif parsed.has_userinfo:
        findings.append(
            Finding(
                code="URL.USERINFO_HOST_CONFUSION",
                title="Host disguised behind a user-info section",
                detail=(
                    "Everything before '@' is ignored by browsers. The real "
                    f"destination is '{host}'. Reading the link visually can "
                    "therefore show a trusted domain while the browser visits a "
                    "different one."
                ),
                severity=Severity.HIGH,
                source=SignalSource.URL_SYNTAX,
                category="phishing",
                weight=18.0,
                evidence={"declared_host": parsed.hostname_raw, "real_host": host},
            )
        )

    if parsed.backslash_confusion:
        findings.append(
            Finding(
                code="URL.BACKSLASH_CONFUSION",
                title="Backslash used to confuse URL parsing",
                detail=(
                    "Backslashes are treated as path separators by many URL "
                    "parsers but as literal characters by others, allowing the "
                    "apparent host to differ from the real one."
                ),
                severity=Severity.HIGH,
                source=SignalSource.URL_SYNTAX,
                category="phishing",
                weight=16.0,
            )
        )

    if parsed.encoded_separators:
        findings.append(
            Finding(
                code="URL.ENCODED_SEPARATORS",
                title="Percent-encoded path separators inside the authority",
                detail=(
                    "The authority component contains encoded '/' characters. "
                    "This is used to smuggle a different host past naive filters."
                ),
                severity=Severity.HIGH,
                source=SignalSource.URL_SYNTAX,
                category="phishing",
                weight=15.0,
            )
        )

    if parsed.double_encoded:
        findings.append(
            Finding(
                code="URL.DOUBLE_ENCODING",
                title="Double-encoded content",
                detail=(
                    "Percent-encoding is applied more than once. Legitimate links "
                    "are rarely double encoded; this is used to hide payloads "
                    "from intermediate filters and WAFs."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.URL_SYNTAX,
                category="payload",
                weight=10.0,
            )
        )

    # ------------------------------------------------------------------ punycode
    if parsed.is_punycode:
        findings.append(
            Finding(
                code="URL.PUNYCODE_HOST",
                title="Internationalised (punycode) domain",
                detail=(
                    f"The host is encoded as '{host}'. Punycode domains can "
                    "visually impersonate well-known brands using non-Latin "
                    "scripts, so the displayed name may differ from the "
                    "registered identity."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.URL_SYNTAX,
                category="phishing",
                weight=12.0,
                evidence={"host": host, "unicode_host": parsed.decoded_host},
            )
        )

    if parsed.confusables:
        findings.append(
            Finding(
                code="URL.HOMOGLYPH_CHARACTERS",
                title="Characters that visually impersonate Latin letters",
                detail=(
                    "The URL contains characters from other scripts that render "
                    "almost identically to ASCII letters, a homograph attack "
                    "used to spoof domains."
                ),
                severity=Severity.HIGH,
                source=SignalSource.URL_SYNTAX,
                category="phishing",
                weight=18.0,
                evidence={"characters": parsed.confusables[:10]},
            )
        )

    # ------------------------------------------------------------------ length
    if parsed.full_url_length > 120:
        findings.append(
            Finding(
                code="URL.EXCESSIVE_LENGTH",
                title="Unusually long URL",
                detail=(
                    f"The URL is {parsed.full_url_length} characters long. Long "
                    "URLs are frequently used to push the real domain out of "
                    "sight and to embed extra payload parameters."
                ),
                severity=Severity.LOW,
                source=SignalSource.URL_SYNTAX,
                category="structure",
                weight=8.0,
                evidence={"length": parsed.full_url_length},
            )
        )
    if parsed.host_length > 60:
        findings.append(
            Finding(
                code="URL.LONG_HOST",
                title="Unusually long host name",
                detail=f"The host is {parsed.host_length} characters long, which suggests generated domains.",
                severity=Severity.LOW,
                source=SignalSource.URL_SYNTAX,
                category="structure",
                weight=6.0,
                evidence={"length": parsed.host_length},
            )
        )

    # -------------------------------------------------------------- subdomains
    if parsed.subdomain_count >= 4:
        findings.append(
            Finding(
                code="URL.DEEP_SUBDOMAIN_CHAIN",
                title="Excessive number of subdomains",
                detail=(
                    f"{parsed.subdomain_count} subdomain levels were found. "
                    "Padding a URL with extra labels is a common way to make a "
                    "short brand name appear at the end of a long chain."
                ),
                severity=Severity.LOW,
                source=SignalSource.URL_SYNTAX,
                category="structure",
                weight=7.0,
                evidence={"subdomains": parsed.subdomain_count},
            )
        )

    # ------------------------------------------------------------------ hyphens
    hyphen_count = len(_HYPHENS.findall(host))
    if hyphen_count >= 4:
        findings.append(
            Finding(
                code="URL.HYPHEN_HEAVY_HOST",
                title="Host contains many hyphens",
                detail=(
                    f"{hyphen_count} hyphens appear in the host. Brand names "
                    "inserted into hyphenated domains ('secure-login-apple.com') "
                    "are a widespread phishing technique."
                ),
                severity=Severity.LOW,
                source=SignalSource.URL_SYNTAX,
                category="phishing",
                weight=7.0,
                evidence={"hyphens": hyphen_count},
            )
        )

    # ------------------------------------------------------------------- ports
    if parsed.port is not None:
        if parsed.port in SUSPICIOUS_PORTS and parsed.port not in (80, 443, 8080, 8443):
            findings.append(
                Finding(
                    code="URL.SUSPICIOUS_PORT",
                    title=f"Non-standard port ({parsed.port})",
                    detail=(
                        f"Port {parsed.port} is frequently used for command-and-control "
                        "panels or throwaway phishing servers. If the site is "
                        "legitimate this is unusual and worth verifying."
                    ),
                    severity=Severity.MEDIUM,
                    source=SignalSource.URL_SYNTAX,
                    category="network",
                    weight=10.0,
                    evidence={"port": parsed.port},
                )
            )
        if (parsed.scheme == "https" and parsed.port not in (443, 8443)) or (
            parsed.scheme == "http" and parsed.port not in (80, 8080)
        ):
            findings.append(
                Finding(
                    code="URL.PROTOCOL_PORT_MISMATCH",
                    title="Unusual port for the declared scheme",
                    detail=f"Scheme '{parsed.scheme}' on port {parsed.port} is an atypical combination.",
                    severity=Severity.LOW,
                    source=SignalSource.URL_SYNTAX,
                    category="network",
                    weight=5.0,
                )
            )

    # ------------------------------------------------------------- query params
    if parsed.query_params:
        suspicious_keys = [
            k for k in parsed.query_params
            if k.lower() not in _GENERIC_QUERY_KEYS and not k.lower().startswith("utm_")
        ]
        if suspicious_keys:
            findings.append(
                Finding(
                    code="URL.UNUSUAL_QUERY_PARAMETERS",
                    title="Query string contains unusual parameters",
                    detail=(
                        "Parameters such as "
                        f"{', '.join(sorted(suspicious_keys)[:5])} are not part of "
                        "typical web navigation and can be used to pass data to a "
                        "malicious endpoint."
                    ),
                    severity=Severity.LOW,
                    source=SignalSource.URL_SYNTAX,
                    category="structure",
                    weight=6.0,
                    evidence={"parameters": sorted(suspicious_keys)[:20]},
                )
            )
        for key, value in parsed.query_params.items():
            lowered = f"{key}={value}".lower()
            if any(token in lowered for token in ("password", "passwd", "secret", "token=", "api_key", "apikey")):
                findings.append(
                    Finding(
                        code="URL.CREDENTIAL_IN_QUERY",
                        title="Credential-like value in the query string",
                        detail=(
                            f"The parameter '{key}' carries a value that looks like "
                            "a secret. Query strings are logged by proxies and "
                            "browsers, so secrets should never travel this way."
                        ),
                        severity=Severity.MEDIUM,
                        source=SignalSource.URL_SYNTAX,
                        category="payload",
                        weight=10.0,
                        evidence={"parameter": key},
                    )
                )
                break

    # ------------------------------------------------------------- path shapes
    if _SCRIPTISH_PATH.search(parsed.path):
        findings.append(
            Finding(
                code="URL.SERVER_SIDE_SCRIPT_PATH",
                title="URL targets a server-side script",
                detail=(
                    "The path points at a script endpoint (.php/.asp/.jsp...). "
                    "Combined with credential-related keywords this is a common "
                    "shape for phishing login pages."
                ),
                severity=Severity.LOW,
                source=SignalSource.URL_SYNTAX,
                category="structure",
                weight=5.0,
                evidence={"path": parsed.path[:200]},
            )
        )
    if len(_HEX_RUN.findall(parsed.path + parsed.query)) >= 3:
        findings.append(
            Finding(
                code="URL.ENCODED_PAYLOAD",
                title="Multiple encoded blobs in the path or query",
                detail=(
                    "Repeated long percent- or hex-encoded sequences suggest an "
                    "obfuscated payload, redirect target or command."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.URL_SYNTAX,
                category="payload",
                weight=9.0,
            )
        )
    if _HYPHEN_RUN.search(parsed.path):
        findings.append(
            Finding(
                code="URL.SUSPICIOUS_PATH",
                title="Path contains repeated separators",
                detail="Repeated '---' sequences in a path are a known obfuscation trick.",
                severity=Severity.LOW,
                source=SignalSource.URL_SYNTAX,
                category="structure",
                weight=5.0,
            )
        )
    if parsed.fragment and any(token in parsed.fragment.lower() for token in PHISHING_KEYWORDS):
        findings.append(
            Finding(
                code="URL.PHISHING_IN_FRAGMENT",
                title="Credential-themed content in the fragment",
                detail=(
                    "The fragment contains credential-related language. Client-side "
                    "scripts on the page can read it and exfiltrate it."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.URL_SYNTAX,
                category="payload",
                weight=10.0,
            )
        )

    # ------------------------------------------------------------- entropy
    host_entropy = shannon_entropy(host)
    dga = GeneratedDomainProfile((parsed.host or "").split(".")[0])
    if dga.generated:
        findings.append(
            Finding(
                code="URL.GENERATED_DOMAIN",
                title="Domain name looks machine-generated",
                detail=(
                    f"The leading label '{dga.label}' {dga.explanation()}. "
                    "Algorithmically generated domains (DGA) are used at scale by "
                    "botnets and malware campaigns and are rarely registered by "
                    "hand."
                ),
                severity=Severity.HIGH if dga.confidence >= 0.7 else Severity.MEDIUM,
                source=SignalSource.URL_SYNTAX,
                category="structure",
                weight=10.0 + 12.0 * dga.confidence,
                evidence=dga.to_dict(),
            )
        )
    elif host_entropy >= 3.9 and len(host) >= 16 and not parsed.is_punycode:
        findings.append(
            Finding(
                code="URL.HIGH_HOST_ENTROPY",
                title="Host name has unusually high character entropy",
                detail=(
                    f"Character entropy of {host_entropy:.2f} bits/char across "
                    f"{len(host)} characters is unusual for human-chosen names."
                ),
                severity=Severity.LOW,
                source=SignalSource.URL_SYNTAX,
                category="structure",
                weight=7.0,
                evidence={"entropy": round(host_entropy, 3)},
            )
        )

    # ------------------------------------------------------------- metadata
    findings.extend(_host_metadata_findings(parsed))
    # --------------------------------------------------- credential lures
    findings.extend(_phishing_token_findings(parsed))
    # ------------------------------------------------------ internal hosts
    findings.extend(_internal_host_findings(parsed))
    return findings


def _phishing_token_findings(parsed: ParsedUrl) -> list[Finding]:
    """Flag credential-harvesting language, weighted by where it appears.

    Keywords in the *host* of an unfamiliar domain are the classic "look at my
    domain, it says secure-login" lure. Keywords in the path of a well-known
    domain are normal (``accounts.google.com/login``), so location is the whole
    story and the same token produces very different scores depending on it.
    """
    tokens = extract_phishing_tokens(parsed)
    if not tokens:
        return []
    findings: list[Finding] = []
    registrable_is_known_brand = any(
        (parsed.registrable or "").endswith(d)
        for domains in IMPERSONATED_BRANDS.values()
        for d in domains
    )
    # path and query are one observation, not two: reporting them separately
    # would let a single lure pattern contribute to the score twice.
    path_tokens = sorted(set(tokens.get("path", []) + tokens.get("query", [])))

    for location, hits in tokens.items():
        if location == "host":
            if registrable_is_known_brand:
                continue  # e.g. accounts.google.com - expected
            findings.append(
                Finding(
                    code="URL.CREDENTIAL_KEYWORDS_IN_HOST",
                    title=f"Host name contains credential lure words ({', '.join(hits[:4])})",
                    detail=(
                        f"The domain name itself is built from security-themed "
                        f"words: {', '.join(hits[:6])}. Domains are registered "
                        "individually, so this wording is a deliberate choice to "
                        "persuade a hurried reader. No major brand requires it."
                    ),
                    severity=Severity.MEDIUM,
                    source=SignalSource.URL_SYNTAX,
                    category="phishing",
                    weight=13.0,
                    evidence={"tokens": hits, "location": location},
                )
            )
        elif location in ("path", "query"):
            if not path_tokens or registrable_is_known_brand and location == "query":
                continue
            findings.append(
                Finding(
                    code="URL.CREDENTIAL_KEYWORDS_IN_PATH",
                    title=f"Link requests an account action ({', '.join(path_tokens[:4])})",
                    detail=(
                        f"The path or query string contains {', '.join(path_tokens[:6])}. "
                        "Combined with the other signals on this page this is a "
                        "credential-harvesting pattern. A single occurrence on a "
                        "known brand domain is entirely normal."
                    ),
                    severity=Severity.LOW,
                    source=SignalSource.URL_SYNTAX,
                    category="phishing",
                    weight=8.0,
                    evidence={"tokens": path_tokens, "location": location},
                )
            )
            break
        elif location == "fragment":
            findings.append(
                Finding(
                    code="URL.CREDENTIAL_KEYWORDS_IN_FRAGMENT",
                    title="Fragment contains credential-related language",
                    detail=(
                        f"{', '.join(hits[:4])} appear after '#'. Fragment data is "
                        "readable by client-side scripts and is used to hand "
                        "stolen input to an attacker's endpoint."
                    ),
                    severity=Severity.MEDIUM,
                    source=SignalSource.URL_SYNTAX,
                    category="phishing",
                    weight=10.0,
                    evidence={"tokens": hits, "location": location},
                )
            )

    # The classic combination: credential language + a domain nobody trusts.
    if tokens.get("host") and path_tokens and not registrable_is_known_brand:
        findings.append(
            Finding(
                code="URL.CREDENTIAL_LURE_PATTERN",
                title="Link is built as a credential-harvesting lure",
                detail=(
                    f"The domain is built from lure words ({', '.join(tokens['host'][:4])}) "
                    f"and the path continues the theme "
                    f"({', '.join(tokens['path'][:4])}). Security-themed wording in "
                    "both the domain and the path is the single most characteristic "
                    "shape of a phishing URL."
                ),
                severity=Severity.HIGH,
                source=SignalSource.URL_SYNTAX,
                category="phishing",
                weight=20.0,
                evidence={"host_tokens": tokens["host"], "path_tokens": path_tokens},
            )
        )
    return findings


def _internal_host_findings(parsed: ParsedUrl) -> list[Finding]:
    """Flag links that point at private, loopback or link-local addresses.

    A link to ``192.168.0.1`` or ``169.254.169.254`` arriving from outside is
    either internal reconnaissance or a cloud-credential theft attempt.
    """
    import ipaddress

    from ..security.constants import is_public_address

    host = parsed.host
    if not host or parsed.is_ip_literal is False:
        return []
    candidate = host.strip("[]")
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return []

    if is_public_address(candidate):
        return []

    if ip in ipaddress.ip_network("169.254.0.0/16"):
        title = "Link points at a link-local address (cloud metadata?)"
        detail = (
            f"'{ip}' is in 169.254.0.0/16, the range used by cloud instance "
            "metadata services. Links of this shape attempt to steal cloud "
            "credentials and are a well-known SSRF and phishing technique."
        )
        weight, severity = 28.0, Severity.HIGH
    elif ip.is_loopback:
        title = "Link points at the loopback interface"
        detail = "'{ip}' refers to the scanning machine itself. A link delivered to a user cannot legitimately be this."
        detail = detail.format(ip=ip)
        weight, severity = 22.0, Severity.HIGH
    else:
        title = f"Link points at a private network address ({ip})"
        detail = (
            f"'{ip}' is not routable on the public internet. Receiving a link to "
            "an internal address usually means network reconnaissance aimed at "
            "your own infrastructure."
        )
        weight, severity = 22.0, Severity.HIGH

    return [
        Finding(
            code="URL.INTERNAL_ADDRESS",
            title=title,
            detail=detail,
            severity=severity,
            source=SignalSource.URL_SYNTAX,
            category="network",
            weight=weight,
            evidence={"address": str(ip), "version": ip.version},
        )
    ]


def _host_metadata_findings(parsed: ParsedUrl) -> list[Finding]:
    """Detect providers that host known phishing/malware content."""
    findings: list[Finding] = []
    host = parsed.host.lower()
    risky_providers = {
        "000webhostapp.com": "free hosting frequently used for phishing",
        "web.app": "free hosting frequently used for phishing",
        "netlify.app": "static hosting used for throwaway phishing pages",
        "vercel.app": "static hosting used for throwaway phishing pages",
        "pages.dev": "static hosting used for throwaway phishing pages",
        "github.io": "user pages host arbitrary content with a trusted-looking domain",
        "glitch.me": "hosting used for throwaway campaigns",
        "replit.app": "hosting used for throwaway campaigns",
        "herokuapp.com": "hosting used for throwaway campaigns",
        "firebaseapp.com": "hosting used for throwaway campaigns",
        "blogspot.com": "blog platforms host arbitrary user content",
        "wordpress.com": "blog platforms host arbitrary user content",
        "weebly.com": "site builders host arbitrary user content",
        "wixsite.com": "site builders host arbitrary user content",
        "freewebsubdomain.com": "free hosting frequently used for phishing",
        "duckdns.org": "dynamic DNS commonly used for short-lived phishing",
        "ngrok.io": "tunneling service often used to expose malware",
        "ngrok-free.app": "tunneling service often used to expose malware",
        "trycloudflare.com": "tunneling service often used to expose malware",
        "loca.lt": "tunneling service often used to expose malware",
        "serveo.net": "tunneling service often used to expose malware",
        "discord.gg": "chat-platform link used for malware and phishing lures",
        "t.me": "chat-platform link used for malware and phishing lures",
    }
    registrable = parsed.registrable or host
    for suffix, reason in risky_providers.items():
        if host == suffix or host.endswith(f".{suffix}"):
            findings.append(
                Finding(
                    code="URL.RISKY_HOSTING_PROVIDER",
                    title=f"Hosted on {suffix}",
                    detail=(
                        f"This domain is served by {suffix}, a {reason}. The "
                        "domain itself carries no reputation, so the content "
                        "behind it is unverified."
                    ),
                    severity=Severity.LOW,
                    source=SignalSource.URL_DOMAIN,
                    category="reputation",
                    weight=6.0,
                    evidence={"host": host, "provider": suffix},
                )
            )
            break
    del registrable
    return findings


def quick_syntax_check(url: str) -> dict[str, object]:
    """Parse and run the lexical checks without producing a full result.

    Used by the ML feature extractor and by cheap synchronous call sites.
    """
    parsed = parse_url(url)
    findings = analyze_url_syntax(parsed)
    return {
        "host": parsed.host,
        "registrable_domain": parsed.registrable,
        "tld": parsed.tld,
        "url_length": parsed.full_url_length,
        "host_length": parsed.host_length,
        "subdomain_count": parsed.subdomain_count,
        "digits_in_host": len(_DIGITS.findall(parsed.host)),
        "dots_in_host": len(_DOTS.findall(parsed.host)),
        "hyphens_in_host": len(_HYPHENS.findall(parsed.host)),
        "special_characters": len(_AT_SYMBOLS.findall(url)),
        "is_https": parsed.is_https,
        "is_ip_host": parsed.is_ip_literal,
        "host_entropy": round(shannon_entropy(parsed.host), 4),
        "path_length": parsed.path_length,
        "query_param_count": len(parsed.query_params),
        "finding_codes": [f.code for f in findings],
    }