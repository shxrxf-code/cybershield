"""DNS analysis: resolution, records and namespace characteristics.

All lookups run in a thread pool so the async event loop is never blocked, and
every query has an explicit lifetime so a hostile authoritative server cannot
stall a scan.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from ..models import Finding, Severity, SignalSource

__all__ = ["DnsAnalysis", "analyze_dns"]

_QUERY_TIMEOUT = 4.0

#: Dynamic-DNS providers frequently abused to keep phishing infrastructure alive.
_DYNAMIC_DNS = frozenset(
    {
        "no-ip.com", "ddns.net", "hopto.org", "duckdns.org", "no-ip.org",
        "freedns.afraid.org", "afraid.org", "dynu.com", "ngrok.io",
        "serveo.net", "trycloudflare.com", "loca.lt", "tunnelto.dev",
        "zapto.org", "myftp.com", "chickenkiller.com",
    }
)

#: Providers with "catch-all" MX that accept mail for any address.
_CATCHALL_MX = frozenset({"mailinator.com", "guerrillamail.com", "10minutemail.com", "yopmail.com", "trashmail.com"})

_SPF_RECORDS = ("v=spf1",)
_DMARC_RECORDS = ("v=dmarc1",)


@dataclass(slots=True)
class DnsAnalysis:
    """Structured DNS intelligence for a hostname."""

    hostname: str
    addresses: list[str] = field(default_factory=list)
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    reverse_ptr: dict[str, str] = field(default_factory=dict)
    resolved: bool = False
    error: str | None = None
    ttl: int | None = None
    geolocation_hint: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "hostname": self.hostname,
            "resolved": self.resolved,
            "addresses": self.addresses,
            "a_records": self.a_records,
            "aaaa_records": self.aaaa_records,
            "cname": self.cname,
            "mx": self.mx_records,
            "ns": self.ns_records,
            "txt": self.txt_records[:10],
            "reverse_ptr": self.reverse_ptr,
            "ttl": self.ttl,
            "error": self.error,
        }


def _queries() -> None:  # pragma: no cover - import side effect guard
    """Ensure dnspython is importable before any query runs."""
    import dns.resolver  # noqa: F401


async def _resolve_many(hostname: str, record_types: tuple[str, ...]) -> dict[str, list[str]]:
    import dns.resolver

    loop = asyncio.get_running_loop()

    def _query() -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(hostname, rtype, lifetime=_QUERY_TIMEOUT)
                out[rtype] = [r.to_text().strip() for r in answers]
            except Exception:
                out[rtype] = []
        return out

    return await loop.run_in_executor(None, _query)


def _reverse_lookup(ip: str) -> str | None:
    import socket

    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, IndexError):
        return None


async def analyze_dns(hostname: str, *, skip: bool = False) -> tuple[DnsAnalysis, list[Finding]]:
    """Resolve *hostname* and derive DNS-based findings.

    Returns the raw :class:`DnsAnalysis` plus explainable findings.  Resolution
    failures produce an ``incomplete`` marker rather than an error so a scan can
    still be scored on its other evidence.
    """
    findings: list[Finding] = []
    analysis = DnsAnalysis(hostname=hostname)

    if skip or not hostname:
        analysis.error = "DNS resolution skipped"
        return analysis, findings

    # IP literals have no DNS profile worth analysing.
    import ipaddress

    try:
        ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        pass
    else:
        analysis.resolved = True
        analysis.addresses = [hostname]
        analysis.a_records = [hostname] if "." in hostname else []
        analysis.aaaa_records = [hostname] if ":" in hostname else []
        return analysis, findings

    records = await _resolve_many(
        hostname, ("A", "AAAA", "CNAME", "MX", "NS", "TXT")
    )
    analysis.a_records = records.get("A", [])
    analysis.aaaa_records = records.get("AAAA", [])
    analysis.cname = records.get("CNAME", [])
    analysis.mx_records = records.get("MX", [])
    analysis.ns_records = records.get("NS", [])
    analysis.txt_records = records.get("TXT", [])
    analysis.addresses = analysis.a_records + analysis.aaaa_records
    analysis.resolved = bool(analysis.addresses)

    if not analysis.resolved:
        analysis.error = "Host did not resolve (NXDOMAIN or no A/AAAA record)"
        findings.append(
            Finding(
                code="URL.NO_DNS_RECORD",
                title="Domain does not resolve",
                detail=(
                    f"'{hostname}' returned no A or AAAA record. A link that points "
                    "to a non-existent host is either offline, taken down, or was "
                    "never intended to deliver a working page. Treat it with "
                    "caution and do not retry repeatedly."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.URL_DNS,
                category="network",
                weight=10.0,
                evidence={"hostname": hostname},
            )
        )
        return analysis, findings

    # ---------------------------------------------------------- IP counts
    if len(analysis.addresses) > 8:
        findings.append(
            Finding(
                code="URL.MANY_ADDRESSES",
                title=f"Host resolves to {len(analysis.addresses)} addresses",
                detail=(
                    "A very high address count is typical of shared hosting or "
                    "fast-flux infrastructure used to keep malicious content "
                    "reachable."
                ),
                severity=Severity.LOW,
                source=SignalSource.URL_DNS,
                category="network",
                weight=6.0,
                evidence={"count": len(analysis.addresses)},
            )
        )

    # ------------------------------------------------------- dynamic DNS
    registrable_labels = hostname.lower().split(".")
    tail2 = ".".join(registrable_labels[-2:])
    tail3 = ".".join(registrable_labels[-3:])
    if tail2 in _DYNAMIC_DNS or tail3 in _DYNAMIC_DNS or any(
        d in hostname.lower() for d in ("ddns", "dynamic-dns", "no-ip")
    ):
        findings.append(
            Finding(
                code="URL.DYNAMIC_DNS",
                title="Hosted on a dynamic DNS provider",
                detail=(
                    "Dynamic DNS lets an attacker change the destination of a "
                    "domain between victims. Legitimate services rarely rely on it."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.URL_DNS,
                category="reputation",
                weight=10.0,
                evidence={"hostname": hostname},
            )
        )

    # ------------------------------------------------- catch-all mailboxes
    for mx in analysis.mx_records:
        mx_host = mx.split()[-1].lower() if mx.split() else mx.lower()
        if any(mx_host.endswith(c) for c in _CATCHALL_MX):
            findings.append(
                Finding(
                    code="URL.DISPOSABLE_EMAIL_PROVIDER",
                    title="Mail exchanger is a disposable email service",
                    detail=(
                        f"MX '{mx_host}' accepts mail for any address. Phishing "
                        "kits register throwaway addresses to receive stolen "
                        "credentials before the domain is reported."
                    ),
                    severity=Severity.MEDIUM,
                    source=SignalSource.URL_DNS,
                    category="phishing",
                    weight=9.0,
                    evidence={"mx": mx_host},
                )
            )

    # --------------------------------------------------------- SPF / DMARC
    txt_blob = " ".join(analysis.txt_records).lower()
    has_spf = any(record.lower().startswith(_SPF_RECORDS) for record in analysis.txt_records)
    has_dmarc = _dmarc_present(analysis.txt_records)
    if analysis.mx_records:
        if not has_spf:
            findings.append(
                Finding(
                    code="URL.NO_SPF_FOR_MAIL_DOMAIN",
                    title="Mail domain has no SPF record",
                    detail=(
                        "The domain accepts mail but publishes no SPF policy. "
                        "Spear-phishing impersonation of this domain is therefore "
                        "not restricted."
                    ),
                    severity=Severity.LOW,
                    source=SignalSource.URL_DNS,
                    category="phishing",
                    weight=5.0,
                )
            )
        if not has_dmarc:
            findings.append(
                Finding(
                    code="URL.NO_DMARC_FOR_MAIL_DOMAIN",
                    title="Mail domain has no DMARC policy",
                    detail=(
                        "Without DMARC, receivers have no published instruction "
                        "on what to do with messages claiming to be from this "
                        "domain."
                    ),
                    severity=Severity.LOW,
                    source=SignalSource.URL_DNS,
                    category="phishing",
                    weight=5.0,
                )
            )
        if has_dmarc and "p=reject" in txt_blob and has_spf:
            analysis.geolocation_hint = "strong_email_authentication"
    del txt_blob

    # ------------------------------------------------------- reverse DNS
    loop = asyncio.get_running_loop()
    for address in analysis.addresses[:4]:
        ptr = await loop.run_in_executor(None, _reverse_lookup, address)
        if ptr:
            analysis.reverse_ptr[address] = ptr

    return analysis, findings


def _dmarc_present(txt_records: list[str]) -> bool:
    for record in txt_records:
        candidate = record.strip('"').lower()
        if "v=dmarc1" in candidate or candidate.startswith("v=dmarc1"):
            return True
    return False


def extract_dmarc_record(txt_records: list[str]) -> dict[str, str] | None:
    """Parse the DMARC policy record from a TXT record list."""
    for record in txt_records:
        stripped = record.strip('"').strip()
        if not stripped.lower().startswith("v=dmarc1"):
            continue
        tags: dict[str, str] = {}
        for part in stripped.split(";"):
            key, _, value = part.strip().partition("=")
            if key:
                tags[key.strip().lower()] = value.strip()
        return tags
    return None