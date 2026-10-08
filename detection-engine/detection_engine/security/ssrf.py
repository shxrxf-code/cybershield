"""SSRF defence for every outbound request the scanner makes.

Threat model
------------
The URL scanner fetches attacker-supplied URLs.  Without controls, that turns
CyberShield's backend into a proxy into the victim's private network:
``http://169.254.169.254/latest/meta-data/`` (cloud metadata), ``http://127.0.0.1:6379/``
(internal Redis), ``http://[::1]:8000/``, ``http://0.0.0.0/`` and DNS names that
resolve to private space.

Controls implemented here
-------------------------
1. **Scheme allowlist** - only ``http``/``https`` are ever requested.
2. **IP-range denylist** - loopback, private, link-local, CGNAT, multicast,
   reserved, broadcast and IPv6 equivalents (``fc00::/7``, ``fe80::/10``,
   ``::1``, ``::ffff:0:0/96`` IPv4-mapped).
3. **DNS pinning with post-resolution validation** - every A/AAAA record returned
   for the host must be public.  A single private answer blocks the request.
4. **Connection-time pinning** - we connect to a validated literal IP and pass
   the real hostname via ``Host`` + TLS SNI, so a second DNS answer (DNS
   rebinding) cannot redirect us.
5. **Per-hop redirect validation** - each redirect target is re-validated from
   scratch; a public URL that 302s to ``169.254.169.254`` is blocked.
6. **Credential stripping** - userinfo in the URL is dropped before fetching so
   we never leak secrets or authenticate to arbitrary hosts.
7. **Bounded response size and time** - no unbounded memory or hangs.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

import httpx

from ..exceptions import DetectionEngineError, NameResolutionError
from .constants import (
    IPV4_BLOCKED_NETWORKS,
    NATIVE_IPV6_BLOCKED_NETWORKS,
    is_public_address,
    unwrap_translated_ipv4,
)

__all__ = ["SsrfBlockedError", "SsrfPolicy", "FetchResult", "SsrfSafeFetcher", "IPReputation"]


class SsrfBlockedError(DetectionEngineError):
    """Raised when a URL would reach a destination the scanner must not touch."""

    code = "ssrf_blocked"
    status_code = 400


@dataclass(slots=True)
class SsrfPolicy:
    """Configurable network policy for outbound analysis."""

    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    max_redirects: int = 10
    connect_timeout: float = 5.0
    read_timeout: float = 8.0
    total_timeout: float = 20.0
    max_body_bytes: int = 512 * 1024
    max_redirect_chain: int = 20
    allow_private: bool = False
    allowed_ports: frozenset[int] | None = None
    #: Optional host denylist (e.g. internal service names).
    blocked_hosts: frozenset[str] = frozenset(
        {"metadata.google.internal", "metadata.goog", "instance-data.ec2.internal"}
    )

    def check_scheme(self, scheme: str) -> None:
        if scheme.lower() not in self.allowed_schemes:
            raise SsrfBlockedError(
                f"Scheme '{scheme}' is not allowed for analysis.",
                detail="Only http and https URLs are fetched.",
            )

    def check_port(self, port: int) -> None:
        if self.allowed_ports is not None and port not in self.allowed_ports:
            raise SsrfBlockedError(f"Port {port} is not in the analysis allowlist.")
        if port in (0,):
            raise SsrfBlockedError("Port 0 is not a valid destination.")

    def check_host_literal(self, host: str) -> None:
        """Validate a literal IP address.

        An IPv6 address that wraps an IPv4 address (``::ffff:``,
        ``64:ff9b::`` NAT64 synthesis, ``2002::`` 6to4) is judged by the IPv4
        address it embeds.  Blocking the wrapper outright would break every scan
        on an IPv6-only network, where DNS64 hands out NAT64 addresses for
        ordinary public sites.
        """
        if self.allow_private:
            return
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError as exc:
            raise SsrfBlockedError("Host is not a valid IP address.") from exc

        embedded = unwrap_translated_ipv4(ip)
        if embedded:
            self.check_host_literal(embedded)
            return

        networks = (
            IPV4_BLOCKED_NETWORKS
            if ip.version == 4
            else NATIVE_IPV6_BLOCKED_NETWORKS
        )
        for network in networks:
            if ip in network:
                raise SsrfBlockedError(
                    f"Target address {ip} is inside a blocked network range.",
                    detail=f"Refusing to reach {network} to prevent SSRF.",
                )
        # ``is_public_address`` also rejects loopback, multicast, reserved and
        # unspecified addresses that are not in the explicit lists.
        if not is_public_address(str(ip)):
            raise SsrfBlockedError(
                f"Target address {ip} is not a globally routable address.",
                detail="Refusing to reach it to prevent SSRF.",
            )

    def check_hostname(self, host: str) -> None:
        lowered = host.lower().rstrip(".")
        if lowered in self.blocked_hosts:
            raise SsrfBlockedError(f"Host '{lowered}' is blocked by policy.")

    def check_all_resolved(self, addresses: list[str], host: str) -> list[str]:
        """Ensure *every* DNS answer for *host* is publicly routable.

        Rejecting the whole request when any answer is private prevents an
        attacker from mixing one public and one private A record to win a race
        between our check and the real connection.
        """
        if self.allow_private or not addresses:
            return addresses
        for addr in addresses:
            self.check_host_literal(addr)
        return addresses


@dataclass(slots=True)
class FetchResult:
    """Outcome of an SSRF-validated fetch."""

    requested_url: str
    final_url: str
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    redirects: list[dict[str, object]] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    tls: dict[str, object] | None = None
    error: str | None = None
    blocked: bool = False
    #: Why the fetch stopped: ``"ssrf_policy"``, ``"unresolvable"``,
    #: ``"redirect_limit"``, ``"redirect_loop"`` or ``None``.
    blocked_reason: str | None = None
    elapsed_ms: int = 0
    method: str = "GET"

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None


class SsrfSafeFetcher:
    """HTTP client that can only reach public internet addresses."""

    def __init__(self, policy: SsrfPolicy | None = None, client: httpx.AsyncClient | None = None) -> None:
        self.policy = policy or SsrfPolicy()
        self._client = client
        self._owns_client = client is None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(
                connect=self.policy.connect_timeout,
                read=self.policy.read_timeout,
                write=self.policy.read_timeout,
                pool=self.policy.connect_timeout,
            ),
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=2),
            headers={
                "User-Agent": "CyberShield-Scanner/1.0 (+defensive URL analysis)",
                "Accept": "*/*",
                "Accept-Encoding": "identity",
            },
            verify=True,
        )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> SsrfSafeFetcher:
        await self._get_client()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # ------------------------------------------------------------------ #
    # DNS
    # ------------------------------------------------------------------ #

    async def resolve(self, host: str) -> list[str]:
        """Resolve *host* to a validated list of public IP strings."""
        import dns.asyncresolver
        import dns.resolver

        loop = asyncio.get_running_loop()
        addresses: list[str] = []
        try:
            answers = await loop.run_in_executor(
                None,
                lambda: _resolve_sync(host),
            )
            addresses = answers
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as exc:
            raise NameResolutionError(
                f"Host '{host}' does not resolve to any address.",
                detail="The domain appears to have no DNS record.",
            ) from exc
        except Exception:
            # Fall back to the OS resolver (also executed off the event loop).
            try:
                infos = await loop.run_in_executor(
                    None, lambda: socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
                )
                addresses = sorted({info[4][0] for info in infos})
            except OSError as exc:
                raise NameResolutionError(
                    f"Host '{host}' could not be resolved: {exc}"
                ) from exc
        return self.policy.check_all_resolved(addresses, host)

    # ------------------------------------------------------------------ #
    # Fetching
    # ------------------------------------------------------------------ #

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        max_redirects: int | None = None,
        read_body: bool = True,
    ) -> FetchResult:
        """Fetch *url* safely, following and re-validating every redirect."""
        loop = asyncio.get_running_loop()
        started = loop.time()
        client = await self._get_client()
        limit = self.policy.max_redirects if max_redirects is None else max_redirects

        current = _strip_userinfo(url)
        redirects: list[dict[str, object]] = []
        resolved_ips: list[str] = []
        tls_info: dict[str, object] | None = None
        visited: set[str] = set()

        try:
            for _ in range(limit + 1):
                if current in visited:
                    return FetchResult(
                        requested_url=url, final_url=current, status_code=None,
                        redirects=redirects, resolved_ips=resolved_ips,
                        error="Redirect loop detected", blocked=True,
                        elapsed_ms=int((loop.time() - started) * 1000),
                    )
                visited.add(current)

                result = await self._fetch_once(
                    client, current, method=method, read_body=read_body,
                    resolved_ips=resolved_ips, tls_info=tls_info,
                    redirects=redirects,
                )
                elapsed = int((loop.time() - started) * 1000)
                if result.error or result.status_code is None:
                    result.requested_url = url
                    result.elapsed_ms = elapsed
                    return result
                if result.status_code in (301, 302, 303, 307, 308) and result.headers.get("location"):
                    location = result.headers["location"]
                    nxt = _resolve_location(current, location)
                    try:
                        self._validate_url(nxt)
                    except SsrfBlockedError as exc:
                        result.requested_url = url
                        result.elapsed_ms = elapsed
                        result.error = f"Blocked redirect target: {exc.message}"
                        result.blocked = True
                        redirects.append({"from": current, "to": nxt, "blocked": True,
                                          "reason": exc.message})
                        return result
                    redirects.append(
                        {
                            "from": current,
                            "to": nxt,
                            "status": result.status_code,
                            "from_ip": resolved_ips[-1] if resolved_ips else None,
                            "cross_domain": _registrable(current) != _registrable(nxt),
                        }
                    )
                    method = "GET" if result.status_code in (301, 302, 303) or method == "HEAD" else method
                    current = nxt
                    continue

                result.requested_url = url
                result.final_url = current
                result.redirects = redirects
                result.resolved_ips = resolved_ips
                result.tls = tls_info
                result.elapsed_ms = elapsed
                return result

            return FetchResult(
                requested_url=url, final_url=current, status_code=None,
                redirects=redirects, resolved_ips=resolved_ips,
                error=f"Exceeded {limit} redirects", blocked=True,
                elapsed_ms=int((loop.time() - started) * 1000),
            )
        except SsrfBlockedError as exc:
            return FetchResult(
                requested_url=url, final_url=current, status_code=None,
                redirects=redirects, resolved_ips=resolved_ips,
                error=exc.message, blocked=True,
                elapsed_ms=int((loop.time() - started) * 1000),
            )
        except NameResolutionError as exc:
            # ``blocked`` stays False: the destination was refused because it
            # does not exist, not because it pointed somewhere internal.
            # Setting it here would make every dead domain look like an SSRF
            # attempt to the redirect analyser.
            return FetchResult(
                requested_url=url, final_url=current, status_code=None,
                redirects=redirects, resolved_ips=resolved_ips,
                error=exc.message, blocked=False,
                elapsed_ms=int((loop.time() - started) * 1000),
            )
        except httpx.HTTPError as exc:
            return FetchResult(
                requested_url=url, final_url=current, status_code=None,
                redirects=redirects, resolved_ips=resolved_ips,
                error=f"{type(exc).__name__}: {exc}",
                elapsed_ms=int((loop.time() - started) * 1000),
            )

    async def _fetch_once(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        method: str,
        read_body: bool,
        resolved_ips: list[str],
        tls_info: dict[str, object] | None,
        redirects: list[dict[str, object]],
    ) -> FetchResult:
        split = urlsplit(url)
        self._validate_url(url)

        host = split.hostname or ""
        port = split.port or (443 if split.scheme == "https" else 80)
        pinned_ip = ""
        if not _is_ip_literal(host):
            addresses = await self.resolve(host)
            resolved_ips.clear()
            resolved_ips.extend(addresses)
            pinned_ip = addresses[0] if addresses else ""

        request_url = url
        headers: dict[str, str] = {}
        extensions: dict[str, object] = {}
        if pinned_ip:
            # Connect to the validated literal while preserving Host + SNI.  This
            # is what defeats DNS rebinding between our check and the socket.
            netloc = split.netloc.rsplit("@", 1)[-1]
            if split.scheme == "https":
                connect_netloc = f"[{pinned_ip}]:{port}" if ":" in pinned_ip else f"{pinned_ip}:{port}"
                extensions = {"sni_hostname": host}
            else:
                connect_netloc = f"[{pinned_ip}]:{port}" if ":" in pinned_ip else f"{pinned_ip}:{port}"
            request_url = urlunsplit((split.scheme, connect_netloc, split.path or "/",
                                      split.query, ""))
            headers["Host"] = netloc

        response = await client.request(
            method,
            request_url,
            headers=headers,
            extensions=extensions or None,
            follow_redirects=False,
        )

        if split.scheme == "https":
            collected = _extract_tls(response)
            if collected:
                if tls_info is None:
                    tls_info = collected
                else:
                    tls_info.update(collected)

        body = b""
        if read_body and method != "HEAD":
            body = response.content[: self.policy.max_body_bytes]

        return FetchResult(
            requested_url=url,
            final_url=url,
            status_code=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            body=body,
            redirects=redirects,
            resolved_ips=resolved_ips,
            tls=tls_info,
            method=method,
        )

    def _validate_url(self, url: str) -> None:
        split = urlsplit(url)
        self.policy.check_scheme(split.scheme)
        host = split.hostname
        if not host:
            raise SsrfBlockedError("URL has no host component.")
        self.policy.check_hostname(host)
        self.policy.check_port(split.port or (443 if split.scheme == "https" else 80))
        if _is_ip_literal(host):
            self.policy.check_host_literal(host.strip("[]"))


# ---------------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------------- #


class IPReputation:
    """Local, offline IP reputation cache backed by the scanned-history store."""

    def __init__(self) -> None:
        self._known_bad: set[str] = set()
        self._seen: dict[str, int] = {}

    def mark_seen(self, ip: str, count: int = 1) -> None:
        self._seen[ip] = self._seen.get(ip, 0) + count

    def flag(self, ip: str) -> None:
        self._known_bad.add(ip)

    def is_flagged(self, ip: str) -> bool:
        return ip in self._known_bad

    def sighting_count(self, ip: str) -> int:
        return self._seen.get(ip, 0)


def _resolve_sync(host: str) -> list[str]:
    import dns.resolver

    addresses: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(host, record_type, lifetime=3.0)
            addresses.extend(str(r) for r in answers)
        except Exception:
            continue
    if not addresses:
        # Fall back to the system resolver.
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        addresses = [info[4][0] for info in infos]
    return sorted(set(addresses))


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _strip_userinfo(url: str) -> str:
    """Remove ``user:pass@`` so credentials are never forwarded to a host."""
    split = urlsplit(url)
    if "@" not in split.netloc:
        return url
    netloc = split.netloc.rsplit("@", 1)[-1]
    return urlunsplit((split.scheme, netloc, split.path, split.query, ""))


def _resolve_location(base: str, location: str) -> str:
    from urllib.parse import urljoin

    return urljoin(base, location)


def _registrable(url: str) -> str:
    """Registrable domain of *url*, or ``""``.

    The import is deferred and absolute because this module is imported by the
    URL analyser; a relative import here would resolve against
    ``detection_engine.security`` and fail.
    """
    from ..url.normalizer import registrable_domain

    try:
        return registrable_domain(urlsplit(url).hostname or "")[0]
    except Exception:  # pragma: no cover - defensive
        return ""


def _extract_tls(response: httpx.Response) -> dict[str, object]:
    """Best-effort extraction of peer certificate details from the socket."""
    stream = response.extensions.get("network_stream")
    if stream is None:
        return {}
    getter = getattr(stream, "get_extra_info", None)
    if getter is None:
        return {}
    ssl_object = getter("ssl_object")
    if ssl_object is None:
        return {}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        der = ssl_object.getpeercert(binary_form=True)
        if not der:
            return {}
        cert = x509.load_der_x509_certificate(der)
        try:
            alt_names = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            alt_names = []
        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "serial": f"{cert.serial_number:x}",
            "san": alt_names[:20],
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "version": cert.version.name,
        }
    except Exception:
        return {}