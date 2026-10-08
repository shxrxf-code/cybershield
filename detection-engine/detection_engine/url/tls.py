"""TLS / certificate analysis.

A valid, matching certificate is *necessary* but not *sufficient* for legitimacy:
phishing sites routinely obtain free DV certificates within minutes.  Findings
here therefore mostly push a verdict towards UNKNOWN or LOW RISK rather than
MALICIOUS.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..models import Finding, Severity, SignalSource
from .normalizer import ParsedUrl

__all__ = ["TlsAnalysis", "analyze_tls"]

#: Certificate profiles seen on legitimate sites (issuers with broad deployment).
_WELL_KNED_ISSUERS = (
    "let's encrypt",
    "lets encrypt",
    "digicert",
    "sectigo",
    "comodo",
    "globalsign",
    "entrust",
    "amazon",
    "google trust",
    "microsoft",
    "cloudflare",
    "zerossl",
    "buypass",
)

#: Signature algorithms considered weak/deprecated.
_WEAK_ALGORITHMS = frozenset({"sha1", "md5", "md2"})


@dataclass(slots=True)
class TlsAnalysis:
    """Certificate facts collected during the connection."""

    available: bool = False
    negotiated_protocol: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    san: list[str] = field(default_factory=list)
    fingerprint_sha256: str | None = None
    serial: str | None = None
    version: str | None = None
    days_remaining: int | None = None
    expired: bool = False
    self_signed: bool = False
    hostname_match: bool | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "protocol": self.negotiated_protocol,
            "cipher": self.cipher,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "san": self.san[:20],
            "fingerprint_sha256": self.fingerprint_sha256,
            "days_remaining": self.days_remaining,
            "expired": self.expired,
            "self_signed": self.self_signed,
            "hostname_match": self.hostname_match,
            "errors": self.errors,
        }


def _analyze_certificate_fields(
    tls: TlsAnalysis, parsed: ParsedUrl, findings: list[Finding]
) -> None:
    """Turn collected certificate fields into findings."""
    host = (parsed.host or "").lower()

    # ---------------------------------------------------------- expiry
    if tls.not_after:
        try:
            expiry = datetime.fromisoformat(str(tls.not_after).replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            remaining = (expiry - datetime.now(tz=timezone.utc)).days
            tls.days_remaining = remaining
            if remaining < 0:
                tls.expired = True
                findings.append(
                    Finding(
                        code="TLS.EXPIRED_CERTIFICATE",
                        title="TLS certificate has expired",
                        detail=(
                            f"The certificate expired on {tls.not_after}. An "
                            "expired certificate is a strong indicator that the "
                            "site is unmaintained, self-signed, or deliberately "
                            "avoiding proper certificate management."
                        ),
                        severity=Severity.MEDIUM,
                        source=SignalSource.URL_TLS,
                        category="certificate",
                        weight=12.0,
                        evidence={"not_after": tls.not_after},
                    )
                )
            elif remaining < 7:
                findings.append(
                    Finding(
                        code="TLS.CERTIFICATE_EXPIRING",
                        title="TLS certificate expires very soon",
                        detail=f"The certificate expires in {remaining} day(s).",
                        severity=Severity.INFO,
                        source=SignalSource.URL_TLS,
                        category="certificate",
                        weight=3.0,
                    )
                )
        except (ValueError, TypeError):
            tls.errors.append("Unparseable certificate expiry date")

    if tls.not_before:
        try:
            start = datetime.fromisoformat(str(tls.not_before).replace("Z", "+00:00"))
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            if start > datetime.now(tz=timezone.utc) + _clock_skew():
                findings.append(
                    Finding(
                        code="TLS.NOT_YET_VALID_CERTIFICATE",
                        title="TLS certificate is not yet valid",
                        detail=f"The certificate only becomes valid on {tls.not_before}.",
                        severity=Severity.HIGH,
                        source=SignalSource.URL_TLS,
                        category="certificate",
                        weight=16.0,
                    )
                )
        except (ValueError, TypeError):
            tls.errors.append("Unparseable certificate start date")

    # ------------------------------------------------------ self-signed
    if tls.self_signed:
        findings.append(
            Finding(
                code="TLS.SELF_SIGNED",
                title="Certificate is self-signed",
                detail=(
                    "Self-signed certificates provide no assurance about identity: "
                    "any party can generate one. Browsers warn about them because "
                    "they defeat the point of TLS authentication."
                ),
                severity=Severity.HIGH,
                source=SignalSource.URL_TLS,
                category="certificate",
                weight=18.0,
                evidence={"subject": tls.subject, "issuer": tls.issuer},
            )
        )

    # ------------------------------------------------- hostname mismatch
    if tls.hostname_match is False:
        findings.append(
            Finding(
                code="TLS.HOSTNAME_MISMATCH",
                title="Certificate does not cover this hostname",
                detail=(
                    "The certificate was issued for a different name. A browser "
                    "would show a full-page warning that users routinely click "
                    "through, which is how credential theft succeeds on an "
                    "encrypted connection."
                ),
                severity=Severity.HIGH,
                source=SignalSource.URL_TLS,
                category="certificate",
                weight=22.0,
                evidence={"host": host, "san": tls.san[:10]},
            )
        )

    # ------------------------------------------------------ random issuer
    issuer = (tls.issuer or "").lower()
    if issuer and not any(known in issuer for known in _WELL_KNED_ISSUERS):
        findings.append(
            Finding(
                code="TLS.UNCOMMON_ISSUER",
                title=f"Uncommon certificate issuer ({tls.issuer})",
                detail=(
                    "The certificate comes from an authority not commonly used for "
                    "public websites. Free or throwaway CAs are frequently "
                    "abused by phishing infrastructure."
                ),
                severity=Severity.LOW,
                source=SignalSource.URL_TLS,
                category="certificate",
                weight=6.0,
                evidence={"issuer": tls.issuer},
            )
        )

    # --------------------------------------------------- short validity
    if tls.not_before and tls.not_after and tls.days_remaining is not None:
        try:
            start = datetime.fromisoformat(str(tls.not_before).replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(tls.not_after).replace("Z", "+00:00"))
            lifetime = (end - start).days
            if 0 <= lifetime <= 15:
                findings.append(
                    Finding(
                        code="TLS.SHORT_VALIDITY_PERIOD",
                        title="Certificate was issued for a very short period",
                        detail=(
                            f"The certificate is valid for only {lifetime} day(s). "
                            "Bulk-issued short-lived certificates are a hallmark of "
                            "automated phishing campaigns that rotate domains "
                            "quickly."
                        ),
                        severity=Severity.MEDIUM,
                        source=SignalSource.URL_TLS,
                        category="certificate",
                        weight=10.0,
                        evidence={"lifetime_days": lifetime},
                    )
                )
        except (ValueError, TypeError):
            pass

    # ------------------------------------------------ weak protocol suite
    if tls.negotiated_protocol and tls.negotiated_protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(
            Finding(
                code="TLS.WEAK_PROTOCOL",
                title=f"Deprecated TLS version negotiated ({tls.negotiated_protocol})",
                detail="Older TLS versions are deprecated and vulnerable to downgrade attacks.",
                severity=Severity.MEDIUM,
                source=SignalSource.URL_TLS,
                category="certificate",
                weight=10.0,
            )
        )


def _clock_skew() -> datetime.timedelta:
    from datetime import timedelta

    return timedelta(days=1)


def probe_tls(parsed: ParsedUrl, *, timeout: float = 5.0, allow_private: bool = False) -> TlsAnalysis:
    """Open a TLS connection to the host and record certificate facts.

    This performs no HTTP request and never follows redirects.  It is safe
    against SSRF because it validates the resolved address first.
    """
    import ipaddress

    from ..security.ssrf import SsrfPolicy

    analysis = TlsAnalysis()
    host = parsed.host
    if not host or parsed.scheme != "https":
        return analysis

    policy = SsrfPolicy(allow_private=allow_private)
    addresses: list[str] = []
    try:
        for info in socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP):
            addresses.append(info[4][0])
    except OSError as exc:
        analysis.errors.append(f"DNS resolution failed: {exc}")
        return analysis

    for address in addresses:
        try:
            ipaddress.ip_address(address)
        except ValueError:
            continue
        try:
            policy.check_host_literal(address)
        except Exception as exc:
            analysis.errors.append(f"Blocked private address {address}: {exc}")
            continue
        break
    else:
        if addresses:
            analysis.errors.append("All resolved addresses are in blocked ranges")
            return analysis

    context = _ssl_context()
    try:
        with socket.create_connection((host, parsed.port or 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                analysis.available = True
                analysis.negotiated_protocol = tls_sock.version()
                cipher = tls_sock.cipher()
                analysis.cipher = cipher[0] if cipher else None
                der = tls_sock.getpeercert(binary_form=True)
                if der:
                    _populate_from_der(analysis, der)
    except (OSError, ValueError) as exc:
        analysis.errors.append(f"TLS handshake failed: {exc}")
        return analysis

    if analysis.subject and analysis.issuer:
        analysis.self_signed = analysis.subject.strip().lower() == analysis.issuer.strip().lower()
    analysis.hostname_match = _hostname_matches(host, analysis.san)
    return analysis


def _ssl_context() -> "ssl.SSLContext":  # type: ignore[name-defined]
    import ssl

    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    # A scan must record handshake problems, not abort on them.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_ciphers("DEFAULT:@SECLEVEL=1")
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError):  # pragma: no cover
        pass
    return context


def _populate_from_der(analysis: TlsAnalysis, der: bytes) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:  # pragma: no cover - malformed cert
        analysis.errors.append(f"Certificate parse failed: {exc}")
        return
    analysis.subject = cert.subject.rfc4514_string()
    analysis.issuer = cert.issuer.rfc4514_string()
    analysis.not_before = cert.not_valid_before_utc.isoformat()
    analysis.not_after = cert.not_valid_after_utc.isoformat()
    analysis.serial = f"{cert.serial_number:x}"
    analysis.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
    analysis.version = getattr(cert.version, "name", None)
    analysis.san = _extract_san(cert)
    try:
        algorithm = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
        if algorithm.lower() in _WEAK_ALGORITHMS:
            analysis.errors.append(f"Weak signature algorithm: {algorithm}")
    except Exception:  # pragma: no cover
        pass


def _extract_san(cert: object) -> list[str]:
    """Return the DNS and IP subject alternative names from a certificate.

    ``GeneralName`` objects must be unwrapped to their ``.value``; stringifying
    them directly yields ``"<DNSName(value='example.com')>"``, which then never
    matches the hostname being probed.
    """
    from cryptography import x509

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    except Exception:  # pragma: no cover - malformed extension
        return []

    names: list[str] = []
    for entry in san:
        # Keep DNS names and IP addresses: both can legitimately cover a host,
        # and an IP SAN is the only way to match a certificate issued to an
        # address literal.
        if isinstance(entry, (x509.DNSName, x509.IPAddress)):
            names.append(str(entry.value))
    return names


def _hostname_matches(host: str, san: list[str]) -> bool | None:
    """Check *host* against the certificate's SAN list.

    Returns ``True``/``False``, or ``None`` when the certificate has no SANs and
    therefore no statement to check against.
    """
    if not san:
        return None
    host = host.lower().strip("[]")
    # A wildcard matches exactly one label, so '*.co.uk' covers 'a.co.uk' but
    # neither 'co.uk' nor 'x.y.co.uk'.
    for name in san:
        candidate = name.lower()
        if candidate == host:
            return True
        if candidate.startswith("*."):
            suffix = candidate[1:]
            if host.endswith(suffix) and host.count(".") == candidate.count("."):
                return True
    return False


def analyze_tls(parsed: ParsedUrl, tls: TlsAnalysis) -> list[Finding]:
    """Derive findings from an already-collected :class:`TlsAnalysis`."""
    findings: list[Finding] = []
    if not parsed.is_https:
        return findings
    if not tls.available:
        return findings
    _analyze_certificate_fields(tls, parsed, findings)
    if not findings and tls.hostname_match:
        findings.append(
            Finding(
                code="TLS.VALID",
                title="Valid TLS certificate",
                detail=(
                    f"Certificate issued by {tls.issuer} is valid for this host. "
                    "Encryption is correctly configured - note that this says "
                    "nothing about the trustworthiness of the content."
                ),
                severity=Severity.INFO,
                source=SignalSource.URL_TLS,
                category="certificate",
                weight=0.0,
                evidence={"expires": tls.not_after},
            )
        )
    return findings


async def analyze_tls_async(parsed: ParsedUrl, *, allow_private: bool = False) -> tuple[TlsAnalysis, list[Finding]]:
    """Async wrapper around :func:`probe_tls` executed off the event loop."""
    import asyncio

    loop = asyncio.get_running_loop()
    tls = await loop.run_in_executor(None, lambda: probe_tls(parsed, allow_private=allow_private))
    return tls, analyze_tls(parsed, tls)


async def probe_tls_from_fetch(parsed: ParsedUrl, collected: dict[str, object] | None) -> TlsAnalysis:
    """Build a :class:`TlsAnalysis` from data already captured by the fetcher."""
    analysis = TlsAnalysis()
    if not collected:
        return analysis
    analysis.available = True
    analysis.subject = str(collected.get("subject") or "") or None
    analysis.issuer = str(collected.get("issuer") or "") or None
    analysis.not_before = str(collected.get("not_before") or "") or None
    analysis.not_after = str(collected.get("not_after") or "") or None
    analysis.fingerprint_sha256 = str(collected.get("fingerprint_sha256") or "") or None
    analysis.serial = str(collected.get("serial") or "") or None
    analysis.version = str(collected.get("version") or "") or None
    san = collected.get("san")
    analysis.san = [str(item) for item in san] if isinstance(san, list) else []
    if analysis.subject and analysis.issuer:
        analysis.self_signed = analysis.subject.strip().lower() == analysis.issuer.strip().lower()
    analysis.hostname_match = _hostname_matches(parsed.host, analysis.san)
    return analysis