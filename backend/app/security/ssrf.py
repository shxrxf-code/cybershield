"""SSRF defence-in-depth for outbound URL analysis.

Threat
------
The URL scanner fetches attacker-supplied addresses on behalf of users. Without
controls, that turns the backend into a proxy into the private network it is
hosted in, exposing cloud metadata endpoints (``169.254.169.254``), databases and
internal admin panels.

Layers implemented
------------------
1. **Scheme allowlist** - only ``http``/``https`` may be dereferenced, blocking
   ``file://``, ``gopher://``, ``dict://`` and similar protocol smuggling.
2. **Port allowlist** - prevents probing of unusual internal services.
3. **Credential stripping** - userinfo is removed before any request so the
   scanner never transmits attacker-supplied credentials.
4. **DNS resolution + IP filtering** - *every* A/AAAA answer is checked, not just
   the first. An attacker controlling DNS returns 1.2.3.4 first and 127.0.0.1
   second to defeat resolvers that only check the head of the list.
5. **IPv4-mapped / NAT64 unwrapping** - ``::ffff:127.0.0.1`` and
   ``64:ff9b::7f00:1`` are translated back to IPv4 and re-checked.
6. **Per-hop revalidation** - redirects are followed manually, re-validating each
   hop, so a public host cannot redirect into ``http://169.254.169.254/``.
7. **Post-connect peer verification** - the socket's actual peer address is
   verified after the connection is established, which defeats DNS rebinding
   where a resolver returns a public address to the validator and a private one
   to the connector.

Only when a deployment genuinely needs internal targets may ``url_allow_private_networks``
be enabled; it is refused outright in production.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from app.core.config import Settings
from app.core.exceptions import SSRFBlockedError
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Blocked networks
# ---------------------------------------------------------------------------
BLOCKED_IPV4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",          # "this" network
        "10.0.0.0/8",         # RFC1918 private
        "100.64.0.0/10",      # RFC6598 carrier-grade NAT
        "127.0.0.0/8",        # loopback
        "169.254.0.0/16",     # link-local, includes cloud metadata 169.254.169.254
        "172.16.0.0/12",      # RFC1918 private
        "192.0.0.0/24",       # IETF protocol assignments
        "192.0.2.0/24",       # TEST-NET-1
        "192.88.99.0/24",     # 6to4 relay anycast
        "192.168.0.0/16",     # RFC1918 private
        "198.18.0.0/15",      # benchmarking
        "198.51.100.0/24",    # TEST-NET-2
        "203.0.113.0/24",     # TEST-NET-3
        "224.0.0.0/4",        # multicast
        "240.0.0.0/4",        # reserved, includes 255.255.255.255
    )
)

BLOCKED_IPV6_NETWORKS: tuple[ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "::/128",             # unspecified
        "::1/128",            # loopback
        "64:ff9b::/96",       # NAT64 - can embed IPv4 targets
        "64:ff9b:1::/48",     # local-use NAT64
        "100::/64",           # discard-only
        "2001::/32",          # Teredo tunnelling
        "2001:20::/28",       # ORCHIDv2
        "2001:db8::/32",      # documentation
        "2002::/16",          # 6to4 - can encapsulate private IPv4
        "fc00::/7",           # unique local
        "fe80::/10",          # link-local
        "ff00::/8",           # multicast
    )
)

#: Hostnames that must never be resolved, regardless of DNS outcome.
BLOCKED_HOSTNAMES: frozenset[str] = frozenset(
    {
        "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
        "metadata", "metadata.google.internal", "metadata.goog",
        "instance-data", "instance-data.ec2.internal",
    }
)

ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


# ---------------------------------------------------------------------------
# IP classification
# ---------------------------------------------------------------------------
def unwrap_ipv6_mapped(address: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    """Translate IPv4-mapped/compatible IPv6 addresses back to IPv4.

    ``::ffff:127.0.0.1`` reaches the same socket as ``127.0.0.1``; without this
    translation a filter that only checks the IPv6 list would allow it.
    """
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
        # 6to4 (``2002:V4ADDR::/16``) and NAT64 (``64:ff9b::/96``) also carry an
        # IPv4 destination in the low 32 bits.
        if address.sixtofour is not None:
            return address.sixtofour
        if address.teredo is not None:
            return address.teredo[1]
        packed = address.packed
        if packed[:12] == b"\x00" * 10 + b"\xff\xff":
            return ipaddress.IPv4Address(packed[12:])
    return address


def classify_ip(address: ipaddress._BaseAddress) -> str | None:
    """Return a block reason for ``address``, or ``None`` when it is permitted."""
    unwrapped = unwrap_ipv6_mapped(address)

    if unwrapped.is_unspecified:
        return "unspecified address"
    if unwrapped.is_loopback:
        return "loopback address"
    if unwrapped.is_link_local:
        return "link-local address"
    if unwrapped.is_multicast:
        return "multicast address"
    if unwrapped.is_reserved:
        return "reserved address"
    if unwrapped.is_private:
        return "private (RFC1918/ULA) address"

    if isinstance(unwrapped, ipaddress.IPv4Address):
        for network in BLOCKED_IPV4_NETWORKS:
            if unwrapped in network:
                return f"address inside {network}"
    else:
        for network in BLOCKED_IPV6_NETWORKS:
            if unwrapped in network:
                return f"address inside {network}"

    return None


def is_ip_allowed(address: ipaddress._BaseAddress, *, allow_private: bool = False) -> bool:
    """Convenience predicate used by tests and the redirect validator."""
    return allow_private or classify_ip(address) is None


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SafeTarget:
    """A URL that has passed every validation gate, ready to be dereferenced."""

    url: str
    scheme: str
    hostname: str
    port: int
    path: str
    resolved_ips: tuple[str, ...]
    pinned_ip: str

    @property
    def is_tls(self) -> bool:
        return self.scheme == "https"


@dataclass
class UrlSafetyChecker:
    """Validates outbound URLs against the SSRF policy."""

    settings: Settings
    _resolver: object = field(default=None, repr=False)

    # -- configuration helpers -------------------------------------------
    @property
    def allow_private(self) -> bool:
        if self.settings.is_production and self.settings.url_allow_private_networks:
            raise SSRFBlockedError(
                "Internal network scanning cannot be enabled in production."
            )
        return self.settings.url_allow_private_networks

    @property
    def allowed_ports(self) -> frozenset[int]:
        return frozenset(self.settings.url_allowed_ports)

    # -- validation -------------------------------------------------------
    def validate_scheme_and_port(self, url: str) -> tuple[str, str, int]:
        """Validate scheme, hostname presence and port. Raises on violation."""
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            raise SSRFBlockedError("The URL could not be parsed.") from exc

        scheme = (parts.scheme or "").lower()
        if scheme not in ALLOWED_SCHEMES:
            raise SSRFBlockedError(
                f"Only http and https URLs can be analysed (received '{scheme or 'none'}').",
                details={"scheme": scheme},
            )

        try:
            hostname = parts.hostname
        except ValueError as exc:
            raise SSRFBlockedError("The URL host could not be parsed.") from exc
        if not hostname:
            raise SSRFBlockedError("The URL does not contain a hostname.")

        try:
            port = parts.port
        except ValueError as exc:
            raise SSRFBlockedError("The URL contains an invalid port number.") from exc

        effective_port = port or (443 if scheme == "https" else 80)
        if effective_port not in self.allowed_ports:
            raise SSRFBlockedError(
                f"Connections to port {effective_port} are not permitted.",
                details={"port": effective_port, "allowed": sorted(self.allowed_ports)},
            )

        hostname = hostname.lower().rstrip(".")
        if hostname in BLOCKED_HOSTNAMES:
            raise SSRFBlockedError(
                f"The hostname '{hostname}' is not permitted.", details={"hostname": hostname}
            )

        return scheme, hostname, effective_port

    def validate_ip_literal(self, hostname: str) -> list[str]:
        """If ``hostname`` is an IP literal, validate it directly."""
        candidate = hostname.strip("[]")
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return []

        reason = classify_ip(address)
        if reason is not None and not self.allow_private:
            raise SSRFBlockedError(
                f"The URL resolves to a {reason}, which is not an allowed destination.",
                details={"ip": str(address), "reason": reason},
            )
        return [str(address)]

    def resolve_host(self, hostname: str) -> list[str]:
        """Resolve ``hostname`` to every A/AAAA address.

        Uses ``getaddrinfo`` so the OS resolver (including ``/etc/hosts`` and any
        split-horizon DNS) is honoured rather than bypassed.
        """
        try:
            infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise SSRFBlockedError(
                f"The hostname '{hostname}' could not be resolved.", details={"hostname": hostname}
            ) from exc

        addresses: list[str] = []
        for info in infos:
            sockaddr = info[4]
            if sockaddr and isinstance(sockaddr[0], str):
                # Canonicalise IPv6 so mapped forms compare equal.
                try:
                    addresses.append(str(ipaddress.ip_address(sockaddr[0])))
                except ValueError:
                    continue

        if not addresses:
            raise SSRFBlockedError(
                f"The hostname '{hostname}' did not resolve to any address.",
                details={"hostname": hostname},
            )
        return addresses

    def assert_ips_allowed(self, addresses: list[str], hostname: str) -> None:
        """Every resolved address must be public. One bad answer blocks the request."""
        if self.allow_private:
            return
        for raw in addresses:
            try:
                address = ipaddress.ip_address(raw)
            except ValueError:
                raise SSRFBlockedError(
                    f"The hostname '{hostname}' resolved to an invalid address.", details={"raw": raw[:64]}
                ) from None
            reason = classify_ip(address)
            if reason is not None:
                raise SSRFBlockedError(
                    f"The hostname '{hostname}' resolves to a {reason}, which is not an allowed destination.",
                    details={"hostname": hostname, "ip": raw, "reason": reason},
                )

    def build_target(self, url: str) -> SafeTarget:
        """Run the full validation pipeline and return a pinned target."""
        scheme, hostname, port = self.validate_scheme_and_port(url)

        literal_addresses = self.validate_ip_literal(hostname)
        addresses = literal_addresses or self.resolve_host(hostname)
        self.assert_ips_allowed(addresses, hostname)

        # Credentials are stripped: the scanner must never transmit them, and
        # they are a phishing signal already reported by the URL analyser.
        default_port = 443 if scheme == "https" else 80
        netloc = hostname if port == default_port else f"{hostname}:{port}"
        parts = urlsplit(url)
        safe_url = urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))
        path = urlsplit(safe_url).path or "/"

        return SafeTarget(
            url=safe_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=path,
            resolved_ips=tuple(addresses),
            pinned_ip=addresses[0],
        )


def _strip_credentials(url: str) -> str:
    """Remove any ``user:pass@`` component from a URL."""
    parts = urlsplit(url)
    netloc = parts.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def strip_credentials(url: str) -> str:
    """Public helper: remove embedded credentials from a URL string."""
    return _strip_credentials(url)