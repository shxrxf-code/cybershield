"""Structural and lexical analysis of a parsed URL.

Emits one signal per distinct concern so the report can explain exactly which
structural property triggered the assessment. Weights are intentionally low for
individually benign properties: most unusual URLs are not malicious.
"""

from __future__ import annotations

import re

from app.detection_engine.entropy import char_entropy, token_entropy
from app.detection_engine.phishing.heuristics import analyse_url_deception
from app.detection_engine.url.parser import (
    ABUSE_TLD_TIERS,
    GOVERNMENT_TLDS,
    ParsedUrl,
    get_suspicious_query_keys,
    get_tracking_query_keys,
    is_shortened_url,
)
from app.detection_engine.phishing.keywords import KEYWORD_WEIGHTS
from app.schemas.common import IndicatorType, Severity, SignalSource
from app.schemas.signal import DetectionSignal, Indicator

# Ports that are legitimate but unusual for public web traffic.
_SUSPICIOUS_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 6667: "IRC",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
    6379: "Redis", 8081: "alternate HTTP", 9001: "Tor/supervisor",
    9050: "Tor SOCKS", 1080: "SOCKS proxy", 31337: "backdoor convention",
}

_DANGEROUS_SCHEMES: frozenset[str] = frozenset(
    {"javascript", "data", "file", "vbscript", "jar", "blob", "about"}
)

#: Schemes that carry no host and exist purely to execute or embed content.
_HOSTLESS_ACTIVE_SCHEMES: frozenset[str] = frozenset(
    {"javascript", "data", "vbscript", "blob"}
)

# A filename-bearing path segment with a double extension is a common lure.
_DOUBLE_EXT_RE = re.compile(r"\.[a-z0-9]{1,10}\.(?:exe|scr|js|jar|hta|cmd|bat|ps1|vbs|com|pif|msi|apk|hta)$", re.I)

_EXECUTABLE_EXT_RE = re.compile(
    r"\.(?:exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|jar|ps1|psm1|msi|msp|apk|deb|rpm|dmg|app|elf|so|iso|img|cab|lnk|reg|chm)$",
    re.I,
)

#: Path segments that indicate an authentication or administrative surface.
_AUTH_PATH_RE = re.compile(
    r"/(?:login|log-in|signin|sign-in|auth|authenticate|oauth|sso|admin|administrator|"
    r"panel|control|cpanel|webmail|console|dashboard|account|accounts|user/users|"
    r"member|members|secure|security|verify|verification|recovery|password|reset)"
    r"(?:[/._-]|$)",
    re.I,
)


def _is_documentation_or_private_range(address: str) -> bool:
    """True when an IP literal cannot be a reachable public web host.

    Documentation, private, loopback, link-local and reserved ranges are never
    used by legitimate public services, which makes an IP-literal URL pointing
    at one a strong indicator of misdirection or an unreachable lure.
    """
    import ipaddress

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return bool(
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_reserved
        or parsed.is_multicast
        or parsed.is_unspecified
    )


def _has_auth_path(url: ParsedUrl) -> bool:
    """Does the URL path point at a login or administrative surface?"""
    return bool(_AUTH_PATH_RE.search(url.path or ""))


def analyse_url_structure(url: ParsedUrl, *, source_text: str = "") -> list[DetectionSignal]:
    """Run the full structural analysis pass over a parsed URL."""
    signals: list[DetectionSignal] = []

    if not url.hostname:
        # The scheme is checked first: "data:" and "javascript:" URLs carry no
        # host at all, so bailing out here would hide the strongest signal.
        signals.extend(_analyse_scheme(url))
        return signals + [
            DetectionSignal(
                code="url.unparsable",
                title="URL could not be parsed",
                description=(
                    "The submitted value is not a well-formed URL with a recognisable host. "
                    "It cannot be assessed structurally or resolved."
                ),
                severity=Severity.MEDIUM,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.9,
                evidence={"original_length": len(url.original)},
            )
        ]

    signals.extend(_analyse_scheme(url))
    signals.extend(_analyse_host(url))
    signals.extend(_analyse_path(url))
    signals.extend(_analyse_query(url))
    signals.extend(analyse_url_deception(url))
    if source_text:
        signals.extend(_analyse_url_text_context(url, source_text))
    return signals


def _analyse_scheme(url: ParsedUrl) -> list[DetectionSignal]:
    signals: list[DetectionSignal] = []
    if url.scheme in _DANGEROUS_SCHEMES:
        executable = url.scheme in _HOSTLESS_ACTIVE_SCHEMES
        signals.append(
            DetectionSignal(
                code="url.dangerous_scheme",
                title=f"Active content scheme ({url.scheme})",
                description=(
                    f"The URL uses the {url.scheme} scheme, which "
                    + (
                        "executes script or embeds content directly in the browser rather than "
                        "referencing a remote host. Attackers use this to bypass URL reputation "
                        "checks, because no domain is ever contacted and therefore no reputation "
                        "lookup is possible."
                        if executable
                        else "loads a local resource directly rather than referencing a remote host."
                    )
                ),
                severity=Severity.CRITICAL if executable else Severity.HIGH,
                category="deception" if executable else "structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.9 if executable else 0.8,
                weight=0.65 if executable else 0.5,
                evidence={
                    "scheme": url.scheme,
                    "has_host": bool(url.hostname),
                    "executable": executable,
                },
            )
        )
    elif not url.is_https:
        signals.append(
            DetectionSignal(
                code="url.insecure_transport",
                title="Connection is not encrypted",
                description=(
                    "The URL uses plain HTTP, so credentials and page content would be "
                    "transmitted without encryption and could be intercepted or modified in transit."
                ),
                severity=Severity.LOW,
                category="transport",
                source=SignalSource.STRUCTURAL,
                confidence=0.5,
                evidence={"scheme": url.scheme},
            )
        )
    return signals


def _analyse_host(url: ParsedUrl) -> list[DetectionSignal]:
    signals: list[DetectionSignal] = []

    if not url.is_ip_literal and "." not in url.hostname:
        signals.append(
            DetectionSignal(
                code="url.hostname_without_tld",
                title="Hostname has no top-level domain",
                description=(
                    f"The host '{url.hostname}' is a single label with no public suffix. Public "
                    "websites are addressed by a domain name, so this is either a malformed URL, "
                    "a bare intranet name, or an attempt to exploit lenient URL handling."
                ),
                severity=Severity.MEDIUM,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.6,
                evidence={"hostname": url.hostname[:253]},
            )
        )

    if url.username or url.password:
        signals.append(
            DetectionSignal(
                code="url.embedded_credentials",
                title="Credentials embedded in the URL",
                description=(
                    "The URL contains a username or password before the '@' separator. This is "
                    "used to disguise the real destination and to capture credentials, and it "
                    "frequently appears in phishing links."
                ),
                severity=Severity.HIGH,
                category="deception",
                source=SignalSource.STRUCTURAL,
                confidence=0.85,
                evidence={"has_username": url.username is not None, "has_password": url.password is not None},
            )
        )

    if url.is_ip_literal:
        decoded = url.effective_host
        is_reserved = _is_documentation_or_private_range(decoded)
        signals.append(
            DetectionSignal(
                code="url.ip_address_host",
                title="Host is a raw IP address",
                description=(
                    "The URL points directly at an IP address instead of a domain name. "
                    "Public services normally use hostnames; an IP literal is common in "
                    "exploit kits, credential-harvesting pages and redirectors. The address "
                    f"{decoded} was resolved from the literal form."
                    + (
                        " The address also falls in a reserved or private range, so it cannot "
                        "correspond to a legitimately reachable public website."
                        if is_reserved
                        else ""
                    )
                ),
                severity=Severity.MEDIUM,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.6,
                evidence={
                    "ip": decoded,
                    "ip_version": url.ip_version,
                    "reserved_or_private_range": is_reserved,
                },
                indicators=(Indicator(type=IndicatorType.IP_ADDRESS, value=decoded),),
            )
        )
        # A bare IP combined with a login surface is the standard shape of a
        # self-hosted credential-harvesting page.
        if is_reserved and _has_auth_path(url):
            signals.append(
                DetectionSignal(
                    code="url.ip_host_with_login_surface",
                    title="Non-public IP host serving a login page",
                    description=(
                        f"The URL targets {decoded}, an address in a reserved or private range, "
                        "at a path that serves an authentication interface. This combination - an "
                        "unreachable or internal address presenting a login form - is the standard "
                        "structure of a phishing or exploit-kit landing page."
                    ),
                    severity=Severity.HIGH,
                    category="deception",
                    source=SignalSource.STRUCTURAL,
                    confidence=0.8,
                    weight=0.55,
                    evidence={
                        "ip": decoded,
                        "reserved_or_private_range": True,
                        "path": url.path[:256],
                        "login_surface": True,
                    },
                    indicators=(Indicator(type=IndicatorType.IP_ADDRESS, value=decoded),),
                )
            )

        # A hostname hidden behind credentials plus an IP is a classic bait.
        if url.username:
            signals.append(
                DetectionSignal(
                    code="url.credential_deception_ip",
                    title="Credential bait combined with an IP host",
                    description=(
                        "The URL supplies apparent credentials followed by an IP address host. "
                        "This construction makes the visible text look like a trusted hostname "
                        "while the browser actually connects to an unrelated server."
                    ),
                    severity=Severity.CRITICAL,
                    category="deception",
                    source=SignalSource.STRUCTURAL,
                    confidence=0.9,
                    evidence={"ip": decoded, "username_present": True},
                )
            )

    if url.subdomain_depth >= 4:
        signals.append(
            DetectionSignal(
                code="url.excessive_subdomains",
                title="Unusually deep subdomain nesting",
                description=(
                    f"The hostname contains {url.subdomain_depth} subdomain levels "
                    f"({url.subdomain}). Attackers bury the real host in a long chain so the "
                    "legitimate domain appears at the end of a convincing-looking address."
                ),
                severity=Severity.MEDIUM,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.6,
                evidence={"subdomain": url.subdomain[:253], "depth": url.subdomain_depth},
            )
        )

    host_length = len(url.hostname)
    if host_length > 60:
        signals.append(
            DetectionSignal(
                code="url.long_hostname",
                title="Unusually long hostname",
                description=(
                    f"The hostname is {host_length} characters long. Long hostnames are used to "
                    "push the registrable domain out of view on mobile devices."
                ),
                severity=Severity.LOW,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.45,
                evidence={"hostname_length": host_length},
            )
        )

    if url.is_suspicious_port and url.port:
        service = _SUSPICIOUS_PORTS.get(url.port, "non-standard")
        signals.append(
            DetectionSignal(
                code="url.suspicious_port",
                title=f"Non-web service port ({url.port})",
                description=(
                    f"The URL targets port {url.port}, normally used for {service}. Browsing to "
                    "an administrative or backend service port from a link is unusual and can "
                    "expose an unprotected interface."
                ),
                severity=Severity.MEDIUM,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.65 if url.port in _SUSPICIOUS_PORTS else 0.4,
                evidence={"port": url.port, "service": service},
            )
        )

    tld_tier = ABUSE_TLD_TIERS.get(url.tld or "")
    if tld_tier is not None:
        tier_severity, abuse_rate = tld_tier
        signals.append(
            DetectionSignal(
                code="url.high_risk_tld",
                title=f"Top-level domain with elevated abuse rates (.{url.tld})",
                description=(
                    f"The .{url.tld} top-level domain carries one of the highest relative phishing "
                    "rates of any TLD, because registration is cheap and frequently anonymous. "
                    "Plenty of legitimate small businesses use these domains, so this is a risk "
                    "factor that gains meaning only alongside other evidence."
                ),
                severity=tier_severity,
                category="reputation_context",
                source=SignalSource.REPUTATION,
                confidence=abuse_rate,
                weight=abuse_rate * 0.5,
                evidence={"tld": url.tld, "relative_abuse_rate": abuse_rate},
            )
        )

    if url.tld and (url.tld in GOVERNMENT_TLDS or url.public_suffix.endswith(".gov")):
        signals.append(
            DetectionSignal(
                code="url.government_namespace",
                title="Government or civic namespace",
                description=(
                    "The URL uses a government namespace. Impersonating public institutions "
                    "is a common phishing pattern and is frequently the subject of takedowns."
                ),
                severity=Severity.MEDIUM,
                category="reputation_context",
                source=SignalSource.REPUTATION,
                confidence=0.5,
                evidence={"tld": url.tld, "public_suffix": url.public_suffix},
            )
        )

    if is_shortened_url(url):
        signals.append(
            DetectionSignal(
                code="url.shortened",
                title="Destination hidden behind a URL shortener",
                description=(
                    f"{url.registered_domain} is a URL shortening service. The true destination "
                    "cannot be determined from the URL alone, which prevents independent "
                    "verification before visiting."
                ),
                severity=Severity.LOW,
                category="transparency",
                source=SignalSource.STRUCTURAL,
                confidence=0.5,
                evidence={"shortener": url.registered_domain},
            )
        )

    entropy = char_entropy(url.hostname)
    labels = [label for label in url.hostname.split(".") if label]
    if url.subdomain_depth >= 2 and token_entropy(labels) > 3.4 and entropy > 3.0:
        signals.append(
            DetectionSignal(
                code="url.dga_like_hostname",
                title="Hostname resembles algorithmically generated output",
                description=(
                    "The subdomain labels have high character entropy and little dictionary "
                    "structure, which is characteristic of domains generated by a domain "
                    "generation algorithm (DGA) used for command-and-control infrastructure."
                ),
                severity=Severity.MEDIUM,
                category="structural",
                source=SignalSource.HEURISTIC,
                confidence=0.5,
                evidence={
                    "host_entropy": round(entropy, 3),
                    "average_token_entropy": round(token_entropy(labels), 3),
                },
            )
        )

    return signals


def _analyse_path(url: ParsedUrl) -> list[DetectionSignal]:
    signals: list[DetectionSignal] = []
    path = url.path or ""

    if len(path) > 150:
        signals.append(
            DetectionSignal(
                code="url.long_path",
                title="Unusually long URL path",
                description=(
                    f"The path component is {len(path)} characters long. Long paths are used to "
                    "obfuscate the real destination and to push content off-screen."
                ),
                severity=Severity.LOW,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.45,
                evidence={"path_length": len(path)},
            )
        )

    double_ext = _DOUBLE_EXT_RE.search(path)
    if double_ext:
        signals.append(
            DetectionSignal(
                code="url.double_extension",
                title="Double file extension in the URL path",
                description=(
                    f"The path ends in '{double_ext.group(0)}'. A double extension such as "
                    "'invoice.pdf.exe' is used to make an executable look like a document."
                ),
                severity=Severity.HIGH,
                category="deception",
                source=SignalSource.STRUCTURAL,
                confidence=0.8,
                evidence={"matched": double_ext.group(0)},
            )
        )

    exec_match = _EXECUTABLE_EXT_RE.search(path)
    if exec_match:
        signals.append(
            DetectionSignal(
                code="url.executable_download",
                title="URL links directly to an executable or script",
                description=(
                    f"The path references '{exec_match.group(0)}', a file type that can execute "
                    "code on the user's machine. Delivering executable content directly from a "
                    "link is a common malware delivery pattern."
                ),
                severity=Severity.MEDIUM,
                category="delivery",
                source=SignalSource.STRUCTURAL,
                confidence=0.65,
                evidence={"extension": exec_match.group(0)},
            )
        )

    if url.has_encoded_chars:
        encoded_count = url.features.get("encoded_char_count", 0)
        signals.append(
            DetectionSignal(
                code="url.percent_encoded",
                title="Percent-encoded characters in the URL",
                description=(
                    f"The URL contains {encoded_count} percent-encoded characters. Encoding is "
                    "legitimate but is also used to disguise a hostname or path from both users "
                    "and naive filters."
                ),
                severity=Severity.INFO if encoded_count < 6 else Severity.LOW,
                category="obfuscation",
                source=SignalSource.STRUCTURAL,
                confidence=0.3,
                evidence={"encoded_char_count": encoded_count},
            )
        )

    special = int(url.features.get("special_char_count", 0))
    if special >= 4:
        signals.append(
            DetectionSignal(
                code="url.special_characters",
                title="Unusual concentration of special characters",
                description=(
                    f"The URL contains {special} characters that are unusual in a legitimate link "
                    "(for example @, quotes, braces or pipes). This is a common obfuscation "
                    "technique to confuse parsers."
                ),
                severity=Severity.LOW,
                category="obfuscation",
                source=SignalSource.STRUCTURAL,
                confidence=0.45,
                evidence={"special_char_count": special},
            )
        )

    return signals


def _analyse_query(url: ParsedUrl) -> list[DetectionSignal]:
    signals: list[DetectionSignal] = []
    if not url.query:
        return signals

    suspicious_keys = get_suspicious_query_keys(url.query)
    if suspicious_keys:
        signals.append(
            DetectionSignal(
                code="url.suspicious_query_keys",
                title="Query parameters associated with credential capture",
                description=(
                    "The URL passes authentication-related state through the query string ("
                    + ", ".join(sorted(set(suspicious_keys))[:6])
                    + "). Credential-harvesting kits commonly accept the victim's data this way."
                ),
                severity=Severity.MEDIUM,
                category="deception",
                source=SignalSource.STRUCTURAL,
                confidence=0.55,
                evidence={"keys": sorted(set(suspicious_keys)), "count": len(suspicious_keys)},
            )
        )

    # Long, high-entropy, key=value pairs suggest an encoded payload.
    values = [pair.split("=", 1)[1] for pair in url.query.split("&") if "=" in pair]
    long_values = [value for value in values if len(value) >= 40]
    if long_values:
        avg_entropy = sum(char_entropy(value) for value in long_values) / len(long_values)
        if avg_entropy > 4.0:
            signals.append(
                DetectionSignal(
                    code="url.encoded_payload",
                    title="High-entropy data in the query string",
                    description=(
                        "One or more query parameters contain long, high-entropy values, which "
                        "indicates encoded or encrypted payload data rather than ordinary "
                        "application state."
                    ),
                    severity=Severity.LOW,
                    category="obfuscation",
                    source=SignalSource.HEURISTIC,
                    confidence=0.4,
                    evidence={
                        "long_value_count": len(long_values),
                        "average_entropy": round(avg_entropy, 3),
                    },
                )
            )

    tracking = get_tracking_query_keys(url.query)
    if is_shortened_url(url) and tracking:
        signals.append(
            DetectionSignal(
                code="url.shortener_tracking_params",
                title="Shortener service with campaign tracking parameters",
                description=(
                    "The shortened URL carries marketing tracking parameters, indicating a "
                    "campaign distribution rather than a genuine personal link."
                ),
                severity=Severity.INFO,
                category="transparency",
                source=SignalSource.STRUCTURAL,
                confidence=0.35,
                evidence={"tracking_keys": sorted(set(tracking))},
            )
        )

    return signals


def _analyse_url_text_context(url: ParsedUrl, source_text: str) -> list[DetectionSignal]:
    """Correlate a URL with the surrounding message text (used by email/phishing)."""
    signals: list[DetectionSignal] = []
    haystack = (url.subdomain + " " + url.path).lower()

    matched = sorted(
        (keyword for keyword in KEYWORD_WEIGHTS if keyword in haystack),
        key=lambda kw: KEYWORD_WEIGHTS[kw],
        reverse=True,
    )
    if len(matched) >= 3:
        signals.append(
            DetectionSignal(
                code="url.credential_keywords",
                title="Credential-related terms embedded in the URL",
                description=(
                    "The URL itself contains authentication vocabulary ("
                    + ", ".join(matched[:5])
                    + "). Attackers place these words in the path so the link appears "
                    "legitimate in a message listing or chat preview."
                ),
                severity=Severity.MEDIUM,
                category="lexical",
                source=SignalSource.HEURISTIC,
                confidence=min(0.75, 0.35 + 0.06 * len(matched)),
                evidence={"matched_keywords": matched[:10], "count": len(matched)},
            )
        )
    return signals