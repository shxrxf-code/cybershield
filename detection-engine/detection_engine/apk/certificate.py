"""APK signing certificate analysis.

Why this matters
----------------
Android's trust model is that an app's signing key *is* its identity.  The
platform will not let a second app claim the same signature, and upgrade checks
fail if the key changes.  So the certificate answers the one question a user
cannot otherwise answer: *who actually built this file?*

The attacks this catches
------------------------
**Repackaging.**  Take a legitimate app, decompile it, add a payload, re-sign with
the developer's own key and redistribute it.  It installs, runs and looks
correct - but the signature is wrong.

**Debug signing.**  ``debug.keystore`` uses a well-known key that ships with the
Android SDK.  Every debug-signed app shares it, so it identifies nothing.

**Weak key.**  A 512-bit RSA key is factorable.  An expired or not-yet-valid
certificate suggests a certificate kept alive past its intended life, which
happens when an attacker wants to keep a key usable.

What is deliberately *not* claimed
----------------------------------
A certificate cannot tell you whether an app is safe, whether it is on the
official store, or whether it has been tampered with after signing - that is what
APK Signature Scheme verification is for.  A valid signature on a malicious app
is a valid signature.  Every finding here is about the certificate's own
properties, and none of them is described as proof of authenticity.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..models import Finding, Severity, SignalSource

__all__ = ["CertificateInfo", "SigningReport", "analyze_certificates", "certificate_findings"]

#: Serial/issuer fragments that identify a known debugging key.
_DEBUG_MARKERS = frozenset(
    {
        "androiddebugkey",
        "debug.keystore",
        "debugkey",
        "android platform debug key",
        "cn=android debug",
    }
)

#: Organisation fragments that belong to the platform or a major vendor.  An app
#: signed by one of these keys claiming to be an unrelated publisher is a
#: repackaged system app.
_PLATFORM_SIGNERS = frozenset(
    {
        "android",
        "aosp",
        "google",
        "samsung",
        "sony",
        "lg electronics",
        "huawei",
        "xiaomi",
        "oneplus",
        "qualcomm",
        "mediatek",
        "motorola",
        "microsoft",
    }
)

#: CN/SAN fragments suggesting a self-issued certificate created for one app.
#: This is normal for cheap or internal tooling and for test builds, so it is
#: reported as information rather than as a finding on its own.
_SELF_ISSUED_HINT = re.compile(r"(?i)^(cn|o|ou)=")


def _der_to_pem(der: bytes) -> str:
    import base64

    body = base64.b64encode(der).decode("ascii")
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


@dataclass(slots=True)
class CertificateInfo:
    """One signing certificate."""

    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    key_algorithm: str = ""
    key_size: int | None = None
    signature_algorithm: str = ""
    serial_number: int | None = None
    is_ca: bool = False
    self_signed: bool = False
    san: list[str] = field(default_factory=list)
    #: The original DER, kept so PEM output is byte-identical to what was signed.
    der: bytes = b""

    @property
    def expired(self) -> bool:
        return bool(self.not_after and self.not_after < datetime.now(tz=timezone.utc))

    @property
    def not_yet_valid(self) -> bool:
        return bool(self.not_before and self.not_before > datetime.now(tz=timezone.utc))

    @property
    def subject_common_name(self) -> str:
        match = re.search(r"CN=([^,]+)", self.subject)
        return match.group(1).strip() if match else ""

    @property
    def organization(self) -> str:
        match = re.search(r"(?:^|,)O=([^,]+)", self.subject)
        return match.group(1).strip() if match else ""

    def to_dict(self) -> dict[str, object]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "not_before": self.not_before.isoformat() if self.not_before else "",
            "not_after": self.not_after.isoformat() if self.not_after else "",
            "sha256": self.sha256,
            "sha1": self.sha1,
            "md5": self.md5,
            "key_algorithm": self.key_algorithm,
            "key_size": self.key_size,
            "signature_algorithm": self.signature_algorithm,
            "serial_number": self.serial_number,
            "is_ca": self.is_ca,
            "self_signed": self.self_signed,
            "san": self.san[:20],
            "expired": self.expired,
            "not_yet_valid": self.not_yet_valid,
        }


@dataclass(slots=True)
class SigningReport:
    """What could be determined about how the APK was signed."""

    schemes: list[str] = field(default_factory=list)
    certificates: list[CertificateInfo] = field(default_factory=list)
    verification_ok: bool | None = None
    verification_detail: str = ""
    parse_errors: list[str] = field(default_factory=list)
    available: bool = True

    @property
    def primary(self) -> CertificateInfo | None:
        return self.certificates[0] if self.certificates else None

    @property
    def signed(self) -> bool:
        return bool(self.schemes or self.certificates)

    def to_dict(self) -> dict[str, object]:
        return {
            "schemes": self.schemes,
            "certificates": [c.to_dict() for c in self.certificates],
            "verification_ok": self.verification_ok,
            "verification_detail": self.verification_detail,
            "parse_errors": self.parse_errors,
            "available": self.available,
            "signed": self.signed,
        }


def _load_certificate(der: bytes) -> CertificateInfo:
    """Parse one DER certificate.  Raises on anything unusable."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    cert = x509.load_der_x509_certificate(der)
    info = CertificateInfo(der=bytes(der))

    def rfc4514(name: Any) -> str:
        try:
            return name.rfc4514_string()
        except Exception:  # pragma: no cover - exotic names
            return str(name)

    info.subject = rfc4514(cert.subject)
    info.issuer = rfc4514(cert.issuer)
    info.serial = format(cert.serial_number, "x").upper()
    info.serial_number = cert.serial_number
    info.sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
    info.sha1 = cert.fingerprint(hashes.SHA1()).hex().upper()  # noqa: S324 - identifier, not security
    info.md5 = cert.fingerprint(hashes.MD5()).hex().upper()  # noqa: S324 - vendor display only

    try:
        info.not_before = cert.not_valid_before_utc
    except AttributeError:  # pragma: no cover - cryptography < 42
        info.not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    try:
        info.not_after = cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover - cryptography < 42
        info.not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    public_key = cert.public_key()
    info.key_algorithm = type(public_key).__name__
    info.key_size = getattr(public_key, "key_size", None)
    info.signature_algorithm = getattr(cert.signature_algorithm_oid, "_name", "") or str(
        cert.signature_algorithm_oid
    )
    info.is_ca = _is_ca(cert)
    info.self_signed = info.subject.strip().lower() == info.issuer.strip().lower()
    info.san = _san(cert)
    return info


def _is_ca(cert: Any) -> bool:
    try:
        from cryptography import x509

        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        return bool(basic.ca)
    except Exception:
        return False


def _san(cert: Any) -> list[str]:
    try:
        from cryptography import x509

        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except Exception:
        return []
    names: list[str] = []
    for entry in ext:
        if isinstance(entry, (x509.DNSName, x509.UniformResourceIdentifier)):
            names.append(str(entry.value))
    return names


def _certificate_der(apk: Any) -> list[bytes]:
    """Collect signing certificates as DER, in DER, whatever androguard returns.

    androguard is inconsistent across schemes and versions: ``get_certificates_v1``
    returns ``asn1crypto`` objects, ``get_certificates_der_v2`` returns raw DER,
    and older builds have the ``*_v1`` DER accessor that current ones dropped.
    Rather than track those differences, each accessor is tried in turn and
    anything with a ``dump()`` is treated as DER.
    """
    accessors = (
        "get_certificates_der_v3",
        "get_certificates_der_v31",
        "get_certificates_der_v2",
        "get_certificates_v3",
        "get_certificates_v31",
        "get_certificates_v2",
        "get_certificates_v1",
        "get_certificates_der_v1",
    )
    seen: set[bytes] = set()
    collected: list[bytes] = []
    for name in accessors:
        method = getattr(apk, name, None)
        if method is None:
            continue
        try:
            result = method()
        except Exception:
            continue
        if not result:
            continue
        try:
            items = list(result)
        except TypeError:
            continue
        for item in items:
            der = _as_der(item)
            if der and der not in seen:
                seen.add(der)
                collected.append(der)
        if collected:
            # v2/v3 signing blocks supersede v1 and carry the same identity, so
            # the first accessor that yields anything is authoritative.
            break
    return collected


def _as_der(item: Any) -> bytes:
    """Coerce an androguard/asn1crypto certificate object to DER bytes."""
    if item is None:
        return b""
    if isinstance(item, (bytes, bytearray)):
        return bytes(item)
    dump = getattr(item, "dump", None)
    if callable(dump):
        try:
            value = dump()
            if isinstance(value, (bytes, bytearray)):
                return bytes(value)
        except Exception:
            return b""
    return b""


def analyze_certificates(apk: Any) -> SigningReport:
    """Inspect the signing information of an androguard ``APK`` object.

    Never raises: signing data is frequently malformed in the samples that most
    need looking at, and a failure here must degrade to "could not determine"
    rather than abort the scan.
    """
    report = SigningReport()

    for scheme, getter in (
        ("v1", "is_signed_v1"),
        ("v2", "is_signed_v2"),
        ("v3", "is_signed_v3"),
        ("v3.1", "is_signed_v31"),
    ):
        try:
            if getattr(apk, getter, None) and getattr(apk, getter)():
                report.schemes.append(scheme)
        except Exception as exc:  # pragma: no cover - androguard internal failure
            report.parse_errors.append(f"Could not check signature scheme {scheme}: {exc}")

    der_certs = _certificate_der(apk)
    if not der_certs:
        report.parse_errors.append("No signing certificate could be extracted.")

    for index, der in enumerate(der_certs[:4]):
        try:
            report.certificates.append(_load_certificate(der))
        except Exception as exc:
            report.parse_errors.append(f"Certificate {index + 1} could not be parsed: {exc}")

    # Whole-file integrity verification is a distinct operation from reading the
    # certificate: it recomputes the digest of every entry and re-checks the
    # signing block, which is what proves the file was not modified after it was
    # signed.  androguard exposes the primitives (``verify_signature`` needs a
    # pre-parsed SignerInfo, signed-data blob and hash algorithm) but no
    # whole-file entry point, so CyberShield does not attempt it.
    #
    # Reporting it as unverified is the point.  A repackaged APK is by far the
    # most common form of Android malware, and this check is what would catch it,
    # so a reader must be told that it was not performed rather than left to
    # assume a signature implies integrity.  ``verification_ok`` stays ``None``,
    # which is distinct from both "verified" and "failed".
    report.verification_ok = None
    report.verification_detail = (
        "Whole-file integrity verification was not performed: this build of "
        "androguard provides no APK Signature Scheme verifier. A valid signature "
        "block shows that a certificate is present, not that the file is "
        "unmodified since it was signed, so repackaging cannot be ruled out from "
        "this report."
    )

    return report


def certificate_findings(
    report: SigningReport, *, is_android_package: bool = True
) -> list[Finding]:
    """Turn a :class:`SigningReport` into findings about the certificate itself.

    *is_android_package* says whether ``AndroidManifest.xml`` was actually read.
    It matters for the unsigned case: a file with no manifest is not an APK, so
    its missing signature is a consequence of it being something else rather
    than an independent finding, and reporting it as one would call a renamed
    document unsigned malware.
    """
    findings: list[Finding] = []

    if not report.signed:
        if not is_android_package:
            findings.append(
                Finding(
                    code="APK.SIGNATURE_NOT_APPLICABLE",
                    title="Signing could not be assessed because this is not an Android package",
                    detail=(
                        "No signature was found, but no AndroidManifest.xml was "
                        "read either, so this file is not an Android package at "
                        "all. The absence of a signature here says nothing about "
                        "the file's origin; it is only recorded so the report does "
                        "not silently omit signing from its coverage."
                    ),
                    severity=Severity.INFO,
                    source=SignalSource.APK_CERTIFICATE,
                    category="coverage",
                    weight=0.0,
                    evidence={"schemes": report.schemes},
                )
            )
            return findings

        findings.append(
            Finding(
                code="APK.UNSIGNED",
                title="The package is not signed",
                detail=(
                    "No APK Signature Scheme block or META-INF signature was "
                    "found. Android refuses to install unsigned packages, so a "
                    "file like this is either malformed, was stripped, or was "
                    "assembled by a tool that does not sign. Its origin cannot "
                    "be established at all."
                ),
                severity=Severity.HIGH,
                source=SignalSource.APK_CERTIFICATE,
                category="integrity",
                weight=30.0,
                # Not authoritative.  Authoritative means "confirmed", and it
                # carries a score floor that forces MALICIOUS.  An unsigned file
                # proves its provenance is unverifiable - it cannot be installed,
                # so it may equally be a corrupt download or a developer build -
                # and it is not evidence that anyone intends harm.  Calling that
                # MALICIOUS would be exactly the overclaim this system promises not
                # to make.
                authoritative=False,
                evidence={"schemes": report.schemes},
            )
        )
        return findings

    if report.verification_ok is False:
        findings.append(
            Finding(
                code="APK.SIGNATURE_INVALID",
                title="Signature verification failed",
                detail=(
                    f"{report.verification_detail} A signature that does not "
                    "verify means the file was modified after it was signed. That "
                    "is the defining property of a repackaged app: the original "
                    "code, resource or manifest has been changed and re-signed, "
                    "usually with a key that has nothing to do with the original "
                    "publisher."
                ),
                severity=Severity.CRITICAL,
                source=SignalSource.APK_CERTIFICATE,
                category="integrity",
                weight=40.0,
                authoritative=True,
                evidence={"schemes": report.schemes},
            )
        )

    primary = report.primary
    if primary is None:
        findings.append(
            Finding(
                code="APK.CERTIFICATE_UNREADABLE",
                title="Signing certificate could not be read",
                detail=(
                    "The package declares "
                    f"{', '.join(report.schemes) or 'a signature'} but its "
                    "certificate could not be parsed: "
                    f"{'; '.join(report.parse_errors[:2]) or 'unknown reason'}. The "
                    "signing identity is therefore unknown."
                ),
                severity=Severity.LOW,
                source=SignalSource.APK_CERTIFICATE,
                category="coverage",
                weight=8.0,
                evidence={"errors": report.parse_errors[:5]},
            )
        )
        return findings

    haystack = f"{primary.subject}\n{primary.issuer}".lower()
    debug_signed = any(marker in haystack for marker in _DEBUG_MARKERS)
    if debug_signed:
        findings.append(
            Finding(
                code="APK.DEBUG_SIGNED",
                title="Package is signed with the public Android debug key",
                detail=(
                    f"The certificate subject is '{primary.subject}'. The "
                    "debug.keystore that ships with the Android SDK uses a key "
                    "that is published in the SDK source, so every app signed with "
                    "it shares the same certificate. It identifies the developer "
                    "as 'nobody in particular', and it means the package was built "
                    "with a debug build rather than released with a real key."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.APK_CERTIFICATE,
                category="identity",
                weight=14.0,
                authoritative=True,
                evidence={"subject": primary.subject, "issuer": primary.issuer},
            )
        )

    # The public debug key is issued by ``O=Android``, which is also how genuine
    # AOSP platform keys look.  A debug-signed package is already reported as
    # debug-signed; calling it a repackaged system app on top of that would be a
    # second, contradictory claim about the same certificate, and it is wrong -
    # every SDK developer holds that key.
    organization = primary.organization.lower()
    if organization and not debug_signed and any(p in organization for p in _PLATFORM_SIGNERS):
        findings.append(
            Finding(
                code="APK.PLATFORM_CERTIFICATE",
                title="Package claims a platform vendor as its signer",
                detail=(
                    f"The certificate was issued by '{primary.issuer}'. Signing keys "
                    "belonging to Android and major vendors are not public and are "
                    "not handed to third-party developers, so a package carrying "
                    "one outside the vendor's own distribution channel has been "
                    "repackaged."
                ),
                severity=Severity.CRITICAL,
                source=SignalSource.APK_CERTIFICATE,
                category="integrity",
                weight=40.0,
                authoritative=True,
                evidence={"subject": primary.subject, "issuer": primary.issuer},
            )
        )

    if primary.expired:
        findings.append(
            Finding(
                code="APK.CERTIFICATE_EXPIRED",
                title="Signing certificate has expired",
                detail=(
                    f"The certificate expired on "
                    f"{primary.not_after.isoformat() if primary.not_after else 'unknown'}. "
                    "Android does not enforce expiry for app signing, so an expired "
                    "certificate is not on its own suspicious. It does indicate a "
                    "long-lived key, and a developer renewing certificates on a "
                    "schedule is better practice than a key kept valid indefinitely."
                ),
                severity=Severity.LOW,
                source=SignalSource.APK_CERTIFICATE,
                category="identity",
                weight=5.0,
                evidence={"not_after": primary.to_dict()["not_after"]},
            )
        )

    if primary.not_yet_valid:
        findings.append(
            Finding(
                code="APK.CERTIFICATE_NOT_YET_VALID",
                title="Signing certificate is not yet valid",
                detail=(
                    "The certificate's validity period starts in the future. A "
                    "correctly issued certificate cannot have this, so it means the "
                    "system clock was wrong when it was created, or the dates were "
                    "set deliberately to confuse analysis."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.APK_CERTIFICATE,
                category="identity",
                weight=12.0,
                authoritative=True,
                evidence={"not_before": primary.to_dict()["not_before"]},
            )
        )

    if primary.key_size is not None and primary.key_size < 2048:
        factorable = primary.key_size < 1024
        findings.append(
            Finding(
                code="APK.WEAK_SIGNING_KEY",
                title=f"Signing key is {primary.key_size} bits, below Android's 2048-bit floor",
                detail=(
                    f"The certificate uses a {primary.key_size}-bit "
                    f"{primary.key_algorithm} key. Google Play requires at least "
                    "2048-bit RSA for uploadable releases"
                    + (
                        ", and keys below 1024 bits can be factored with "
                        "commodity hardware, which means the signature can be "
                        "forged outright"
                        if factorable
                        else ", so this key was either generated outside the "
                        "normal toolchain or the app was never published through "
                        "the store at all"
                    )
                    + "."
                ),
                severity=Severity.HIGH if factorable else Severity.MEDIUM,
                source=SignalSource.APK_CERTIFICATE,
                category="integrity",
                weight=22.0 if factorable else 14.0,
                authoritative=factorable,
                evidence={"key_size": primary.key_size, "algorithm": primary.key_algorithm},
            )
        )

    if primary.is_ca:
        findings.append(
            Finding(
                code="APK.CA_CERTIFICATE",
                title="Signing certificate is marked as a certificate authority",
                detail=(
                    "The basic-constraints extension marks this certificate as a "
                    "CA. Android signing certificates are end-entity certificates, "
                    "so a CA flag means the certificate was not produced by a "
                    "normal Android toolchain."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.APK_CERTIFICATE,
                category="integrity",
                weight=14.0,
                authoritative=True,
                evidence={},
            )
        )

    if len(report.certificates) > 1:
        findings.append(
            Finding(
                code="APK.MULTIPLE_SIGNERS",
                title="Package carries more than one signing certificate",
                detail=(
                    f"{len(report.certificates)} certificates were found. This is "
                    "normal during a signing-key rotation, where the app is signed "
                    "with both the old and new key so upgrades keep working. It is "
                    "also how a publisher change is faked, so the certificate "
                    "history is worth checking against the vendor's own releases."
                ),
                severity=Severity.INFO,
                source=SignalSource.APK_CERTIFICATE,
                category="identity",
                weight=0.0,
                evidence={"certificates": [c.to_dict() for c in report.certificates]},
            )
        )

    return findings


def certificate_fingerprints(report: SigningReport) -> dict[str, str]:
    """Stable identifiers for the signing key, for allow-listing."""
    primary = report.primary
    if primary is None:
        return {}
    return {
        "sha256": primary.sha256,
        "sha1": primary.sha1,
        "md5": primary.md5,
        "subject": primary.subject,
        "fingerprint_source": "signing certificate",
    }


def pem_for(report: SigningReport) -> str:
    """PEM text of the primary certificate, for pasting into an allow-list.

    Built from the DER captured at parse time rather than re-encoded from the
    parsed fields, so the output is byte-identical to the certificate the APK
    was actually signed with.
    """
    primary = report.primary
    if primary is None or not primary.der:
        return ""
    return _der_to_pem(primary.der)