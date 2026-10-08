"""Blocked network ranges used by the SSRF guard.

These lists cover every non-globally-routable range that could let an attacker
pivot from the scanner into the deployment's private network, cloud metadata
service or loopback interfaces.
"""

from __future__ import annotations

import ipaddress
from typing import Final

__all__ = [
    "IPV4_BLOCKED_NETWORKS",
    "IPV6_BLOCKED_NETWORKS",
    "NATIVE_IPV6_BLOCKED_NETWORKS",
    "is_public_address",
    "unwrap_translated_ipv4",
]

_IPV4_BLOCKED: Final[tuple[str, ...]] = (
    # Loopback
    "127.0.0.0/8",
    # RFC1918 private space
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    # Link-local (includes cloud metadata at 169.254.169.254)
    "169.254.0.0/16",
    # Carrier-grade NAT
    "100.64.0.0/10",
    # IETF protocol assignments
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    # Documentation ranges
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "233.252.0.0/24",
    # Multicast + reserved + broadcast
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "0.0.0.0/8",
    # Shared address space / benchmarking (RFC 6598)
    "198.51.100.0/24",
    # TEST-NET / 6to4 relay anycast
    "192.31.196.0/24",
    # AS112 / deprecated
    "192.52.193.0/24",
    "192.175.48.0/24",
)

_IPV6_BLOCKED: Final[tuple[str, ...]] = (
    "::/128",        # unspecified
    "::1/128",       # loopback
    "fc00::/7",      # unique local
    "fe80::/10",     # link-local
    "fec0::/10",     # site-local (deprecated)
    "ff00::/8",      # multicast
    "2001:db8::/32", # documentation
    "2002::/16",     # 6to4
    "2001::/32",     # Teredo
    "100::/64",      # discard-only
    "::ffff:0:0/96",  # IPv4-mapped -> checked against IPv4 lists too
    "64:ff9b::/96",  # NAT64
    "64:ff9b:1::/48",
    "2001:20::/28",  # ORCHID
    "2001:10::/28",  # deprecated ORCHID
)

IPV4_BLOCKED_NETWORKS: Final[tuple[ipaddress.IPv4Network, ...]] = tuple(
    ipaddress.ip_network(cidr, strict=False) for cidr in _IPV4_BLOCKED
)

IPV6_BLOCKED_NETWORKS: Final[tuple[ipaddress.IPv6Network, ...]] = tuple(
    ipaddress.ip_network(cidr, strict=False) for cidr in _IPV6_BLOCKED
)

#: IPv6 ranges that must be unwrapped to their embedded IPv4 address *before*
#: any judgement is made, because they are only a container for an IPv4 target.
#:
#: Treating these as simply "blocked" is the obvious thing to do and it is
#: wrong: an IPv6-only deployment (or a NAT64/DNS64 network) hands out synthesised
#: ``64:ff9b::/96`` addresses for ordinary public hostnames, so blanket-blocking
#: them makes every HTTPS scan fail with a bogus SSRF error.  Unwrapping keeps
#: the protection intact - ``64:ff9b::7f00:1`` still resolves to loopback and is
#: still blocked - while letting real traffic through.
_TRANSLATION_PREFIXES: Final[tuple[ipaddress.IPv6Network, ...]] = (
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64 well-known prefix (RFC 6052)
    ipaddress.ip_network("2002::/16"),  # 6to4
)

#: NAT64 prefixes whose low 32 bits are the embedded IPv4 address.  Only /96
#: prefixes are listed: a /48 or /64 NAT64 prefix does not fix where the IPv4
#: address sits inside the remaining bits, so it cannot be unwrapped and those
#: ranges stay blocked outright.
_NAT64_PREFIXES: Final[tuple[ipaddress.IPv6Network, ...]] = (
    ipaddress.ip_network("64:ff9b::/96"),
)

#: Ranges blocked regardless of any IPv4 they embed.
NATIVE_IPV6_BLOCKED_NETWORKS: Final[tuple[ipaddress.IPv6Network, ...]] = tuple(
    ipaddress.ip_network(cidr, strict=False)
    for cidr in _IPV6_BLOCKED
    if cidr
    not in ("::ffff:0:0/96", "64:ff9b::/96", "2002::/16")
)


def unwrap_translated_ipv4(address: str | ipaddress._BaseAddress) -> str:
    """Return the IPv4 address an IPv6 address embeds, or ``""``.

    Handles the three translation mechanisms that matter for SSRF:

    * ``::ffff:a.b.c.d``   - IPv4-mapped, from ``getaddrinfo(AF_INET6)``
    * ``64:ff9b::a.b.c.d`` - NAT64 / DNS64 synthesis
    * ``2002:a.b.c.d::``   - 6to4, which embeds the *relay* IPv4 address

    >>> unwrap_translated_ipv4("64:ff9b::7f00:1")
    '127.0.0.1'
    >>> unwrap_translated_ipv4("2606:4700::1111")
    ''
    """
    try:
        ip = (
            address
            if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address))
            else ipaddress.ip_address(str(address).strip("[]"))
        )
    except ValueError:
        return ""
    if not isinstance(ip, ipaddress.IPv6Address):
        return ""

    if ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    if ip.sixtofour is not None:
        return str(ip.sixtofour)

    for prefix in _NAT64_PREFIXES:
        if ip in prefix:
            # A /96 prefix means the low 32 bits are the embedded IPv4 address.
            offset = prefix.prefixlen // 8
            return str(ipaddress.IPv4Address(ip.packed[offset : offset + 4]))
    return ""


def is_public_address(address: str) -> bool:
    """Return True when *address* is safe to contact from the scanner.

    An IPv6 address that merely *wraps* an IPv4 address is judged by that IPv4
    address, so a NAT64 or IPv4-mapped spelling of ``169.254.169.254`` is blocked
    exactly as the bare IPv4 address is.
    """
    try:
        ip = ipaddress.ip_address(address.strip("[]"))
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv6Address):
        embedded = unwrap_translated_ipv4(ip)
        if embedded:
            # The IPv6 form is only a wrapper; the IPv4 rules decide.
            return is_public_address(embedded)
        if any(ip in network for network in NATIVE_IPV6_BLOCKED_NETWORKS):
            return False

    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast:
        return False
    if ip.is_reserved or ip.is_unspecified:
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        if any(ip in network for network in IPV4_BLOCKED_NETWORKS):
            return False
    return True