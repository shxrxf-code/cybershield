"""APK signing-scheme detection and v1 certificate extraction.

Android APKs carry their identity in up to three signature schemes:

* **v1** (JAR): ``META-INF/MANIFEST.MF`` plus a ``*.RSA``/``*.DSA``/``*.EC``
  certificate in PKCS#7 container.
* **v2 / v3**: a dedicated block between the ZIP entries and the central
  directory, located through the ZIP end-of-central-directory record.

This module decides *which* schemes are present and, for v1, extracts the
signer certificate's SHA-256 fingerprint and a minimal subject/issuer summary.
It performs no verification of the signatures themselves - verification requires
either a full X.509 implementation or re-implementing Android's apksig logic,
and an *unverifiable* APK is reported as unverifiable rather than trusted.

Nothing here executes the APK or touches the bytecode.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
from dataclasses import dataclass, field

#: Magic that identifies the APK Signature Scheme v2/v3 signing block.
APK_SIG_BLOCK_MAGIC: bytes = b"APK Sig Block 42"

#: Well-known signing block IDs.
APK_SIG_SCHEME_V2_BLOCK_ID: int = 0x7109871A
APK_SIG_SCHEME_V3_BLOCK_ID: int = 0xF05368C0
APK_SIG_SCHEME_V31_BLOCK_ID: int = 0x1B93AD61
#: v2 qualifier "stripping protection attribute".
APK_SIG_SCHEME_V2_STRIPPING_PROTECTION_ATTR_ID: int = 0x71777777
#: v3 qualifier marking the minimum supported SDK.
APK_SIG_SCHEME_V3_MIN_SDK_BLOCK_ID: int = 0x8A9B01E6

#: PKCS#7 ``contentType`` for SignedData (1.2.840.113549.1.7.2).
_PKCS7_SIGNED_DATA_OID: bytes = bytes.fromhex("2a864886f70d010702")

_V1_CERT_EXTENSIONS: frozenset[str] = frozenset({"rsa", "dsa", "ec"})

#: Object identifier name table for the name attributes we surface.
_OID_NAMES: dict[bytes, str] = {
    bytes.fromhex("550403"): "CN",    # commonName
    bytes.fromhex("55040a"): "O",     # organizationName
    bytes.fromhex("55040b"): "OU",    # organizationalUnitName
}


class _DerError(Exception):
    """Internal: a structure could not be walked."""


@dataclass(slots=True)
class CertificateInfo:
    """Best-effort summary of a v1 signer certificate."""

    sha256_fingerprint: str  # hex digest of the full certificate DER
    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def subject_label(self) -> str:
        """Short human label, e.g. ``CN=Acme, O=Acme Corp``."""
        return _name_label(self.subject)


@dataclass(slots=True)
class SignatureSchemeInfo:
    """Which signing schemes an APK declares."""

    v1_present: bool = False
    v1_files: list[str] = field(default_factory=list)
    v2_present: bool = False
    v3_present: bool = False
    v3_1_present: bool = False
    block_pair_ids: list[int] = field(default_factory=list)
    minimum_sdk: int | None = None
    certificates: list[CertificateInfo] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def any_scheme_present(self) -> bool:
        return self.v1_present or self.v2_present or self.v3_present or self.v3_1_present

    @property
    def signed(self) -> str:
        """Human summary, e.g. ``v2`` or ``v1`` or ``none``."""
        schemes: list[str] = []
        if self.v1_present:
            schemes.append("v1")
        if self.v2_present:
            schemes.append("v2")
        if self.v3_present:
            schemes.append("v3")
        if self.v3_1_present:
            schemes.append("v3.1")
        return "+".join(schemes) if schemes else "none"


def detect_signature_schemes(
    zipfile_object: zipfile.ZipFile, apk_bytes: bytes | None = None
) -> SignatureSchemeInfo:
    """Detect the signing schemes of a ZIP ``ZipFile``.

    Args:
        zipfile_object: An open ``ZipFile`` over the APK.
        apk_bytes: The raw file bytes when available (required for the
            central-directory-anchored v2/v3 block search).

    Returns:
        A :class:`SignatureSchemeInfo`. The v2/v3 block is only searched when
        ``apk_bytes`` is supplied; otherwise those values stay ``False`` and a
        note explains the limitation.
    """
    info = SignatureSchemeInfo()

    names = set(zipfile_object.namelist())
    manifest = "META-INF/MANIFEST.MF"
    info.v1_present = manifest in names
    info.v1_files = sorted(
        f"{name}"
        for name in names
        if name.startswith("META-INF/")
        and not name.endswith(".SF")
        and not name.endswith(".MF")
        and name.rsplit(".", 1)[-1].lower() in _V1_CERT_EXTENSIONS
    )

    if apk_bytes is not None:
        try:
            _read_signing_block(apk_bytes, info)
        except (struct.error, IndexError, ValueError):
            info.notes.append("signing block could not be walked; v2/v3 state unknown")
    else:
        info.notes.append("raw APK bytes unavailable; v2/v3 block not scanned")

    for cert_file in info.v1_files:
        try:
            cert_data = zipfile_object.read(cert_file)
        except (KeyError, zipfile.BadZipFile):
            continue
        info.certificates.extend(extract_certificates(cert_data))

    return info


def extract_certificates(pkcs7: bytes) -> list[CertificateInfo]:
    """Extract signer certificates from a PKCS#7 SignedData blob.

    This is a defensive, minimal DER walker, not a full PKCS#7 parser: it looks
    for the SignedData content type and, inside it, for the ``[0]`` certificates
    field, then hashes every certificate SEQUENCE it finds. Anything unexpected
    simply yields no certificates - a malformed or exotic signature is reported
    as undecodable, never guessed at.
    """
    try:
        root_tag, root_start, root_end = _read_tlv(pkcs7, 0)
        if root_tag != 0x30:
            return []
        # contentInfo: contentType OID then [0] EXPLICIT SignedData.
        oid_tag, oid_start, oid_end = _read_tlv(pkcs7, root_start)
        if oid_tag != 0x06 or pkcs7[oid_start:oid_end] != _PKCS7_SIGNED_DATA_OID:
            return []
        wrapper_tag, wrapper_start, wrapper_end = _read_tlv(pkcs7, oid_end)
        if wrapper_tag not in (0xA0, 0x30):
            return []
        signed_tag, signed_start, signed_end = _read_tlv(pkcs7, wrapper_start)
        if signed_tag != 0x30:
            return []
    except (struct.error, IndexError, _DerError):
        return []

    certificates_raw: list[bytes] = []
    inner = signed_start
    while inner < signed_end:
        try:
            tag, value_start, value_end = _read_tlv(pkcs7, inner)
        except (struct.error, IndexError, _DerError):
            break
        if tag == 0xA0:  # certificates [0] IMPLICIT SET OF Certificate
            item = value_start
            while item < value_end:
                try:
                    cert_tag, cert_start, cert_end = _read_tlv(pkcs7, item)
                except (struct.error, IndexError, _DerError):
                    break
                if cert_tag == 0x30:
                    certificates_raw.append(pkcs7[item:cert_end])
                    item = cert_end
                else:
                    break
            break
        inner = value_end

    return [_describe_certificate(der) for der in certificates_raw]


def _describe_certificate(der: bytes) -> CertificateInfo:
    """Compute fingerprint and subject/issuer from one DER certificate."""
    info = CertificateInfo(
        sha256_fingerprint=hashlib.sha256(der).hexdigest(),
    )
    try:
        _parse_cert_subjects(der, info)
    except (struct.error, IndexError, _DerError):
        info.notes.append("certificate body could not be walked")
    if not info.subject:
        info.notes.append("subject not parsed")
    if not info.issuer:
        info.notes.append("issuer not parsed")
    return info


def _parse_cert_subjects(der: bytes, info: CertificateInfo) -> None:
    """Walk ``Certificate -> tbsCertificate`` and pull issuer/subject names."""
    cert_tag, cert_start, cert_end = _read_tlv(der, 0)
    if cert_tag != 0x30:
        raise _DerError("certificate is not a SEQUENCE")
    tbs_tag, tbs_start, tbs_end = _read_tlv(der, cert_start)
    if tbs_tag != 0x30:
        raise _DerError("tbsCertificate is not a SEQUENCE")

    # Collect the flat field list of tbsCertificate. DER order is fixed:
    #   version [0] (optional), serial INTEGER, signature SEQUENCE,
    #   issuer Name SEQUENCE, validity SEQUENCE, subject Name SEQUENCE, ...
    fields: list[tuple[int, int, int]] = []
    inner = tbs_start
    while inner < tbs_end:
        tag, value_start, value_end = _read_tlv(der, inner)
        fields.append((tag, value_start, value_end))
        inner = value_end

    position = 0
    if fields and fields[0][0] == 0xA0:  # explicit version marker
        position = 1
    if len(fields) <= position + 4:
        return
    issuer_name = _parse_name(der, fields[position + 2])
    subject_name = _parse_name(der, fields[position + 4])
    info.issuer = issuer_name
    info.subject = subject_name


def _parse_name(der: bytes, field: tuple[int, int, int]) -> dict[str, str]:
    """Extract CN/O/OU from an X.509 ``Name`` SEQUENCE."""
    tag, value_start, value_end = field
    if tag != 0x30:
        return {}
    found: dict[str, str] = {}
    inner = value_start
    while inner < value_end:
        rdn_tag, rdn_start, rdn_end = _read_tlv(der, inner)
        if rdn_tag != 0x31:  # SET OF AttributeTypeAndValue
            break
        item = rdn_start
        while item < rdn_end:
            atv_tag, atv_start, atv_end = _read_tlv(der, item)
            if atv_tag == 0x30:
                oid_tag, oid_start, oid_end = _read_tlv(der, atv_start)
                name = _OID_NAMES.get(der[oid_start:oid_end]) if oid_tag == 0x06 else None
                if name and name not in found:
                    value_tag, value_start2, value_end2 = _read_tlv(der, oid_end)
                    text = _read_string_value(der, value_start2, value_end2, value_tag)
                    if text:
                        found[name] = text
            item = atv_end
        inner = rdn_end
    return found


def _read_string_value(der: bytes, start: int, end: int, tag: int) -> str:
    """Decode a common ASN.1 string type or the raw bytes as a fallback."""
    text = der[start:end]
    if tag in (0x0C, 0x13, 0x16, 0x1E):  # UTF8String, Printable, IA5, BMP
        if tag == 0x1E:  # BMPString (UTF-16BE)
            try:
                return text.decode("utf-16-be", errors="replace")
            except UnicodeDecodeError:
                return ""
        try:
            return text.decode("utf-8", errors="replace").strip()
        except UnicodeDecodeError:
            return ""
    return text.decode("utf-8", errors="replace").strip()


def _name_label(name: dict[str, str]) -> str:
    parts = [f"{key}={value}" for key, value in name.items()]
    return ", ".join(parts) if parts else "unknown"


# ---------------------------------------------------------------------------
# APK Signature Scheme v2/v3 block
# ---------------------------------------------------------------------------

#: Bytes spanning ``size field (u64) + magic (16)`` between block and central dir.
_SIG_BLOCK_TRAILER: int = 24
_EOCD_MIN_SIZE: int = 22


def _read_signing_block(apk_bytes: bytes, info: SignatureSchemeInfo) -> None:
    """Locate the signing block from the EOCD and read its ID/value pairs."""
    eocd = _find_eocd(apk_bytes)
    if eocd is None:
        raise ValueError("no end-of-central-directory record")
    if len(apk_bytes) - eocd < _EOCD_MIN_SIZE:
        raise ValueError("truncated end-of-central-directory record")

    central_dir_size, central_dir_offset = struct.unpack_from("<II", apk_bytes, eocd + 12)
    if central_dir_offset + central_dir_size > len(apk_bytes):
        raise ValueError("central directory extends past end of file")
    if central_dir_offset < _SIG_BLOCK_TRAILER:
        return  # no room for a signing block

    trailer = central_dir_offset - _SIG_BLOCK_TRAILER
    size_field = struct.unpack_from("<Q", apk_bytes, trailer)[0]
    magic = apk_bytes[trailer + 8 : trailer + 24]
    if magic != APK_SIG_BLOCK_MAGIC:
        return

    block_start = trailer - size_field
    if block_start < 0 or block_start + 8 > trailer:
        raise ValueError("signing block size does not align with the file")
    leading_size = struct.unpack_from("<Q", apk_bytes, block_start)[0]
    if leading_size != size_field:
        # Sizes must match; mismatched sizes indicate tampering.
        info.notes.append("signing block size fields disagree; block state unreliable")
        return

    cursor = block_start + 8
    block_end = block_start + size_field
    if block_end > trailer:
        block_end = trailer

    while cursor + 12 <= block_end:
        pair_size = struct.unpack_from("<Q", apk_bytes, cursor)[0]
        if pair_size < 12 or cursor + pair_size > block_end:
            raise ValueError("malformed signing block pair")
        pair_id = struct.unpack_from("<I", apk_bytes, cursor + 8)[0]
        info.block_pair_ids.append(pair_id)
        if pair_id == APK_SIG_SCHEME_V2_BLOCK_ID:
            info.v2_present = True
        elif pair_id == APK_SIG_SCHEME_V3_BLOCK_ID:
            info.v3_present = True
        elif pair_id == APK_SIG_SCHEME_V31_BLOCK_ID:
            info.v3_1_present = True
        elif pair_id == APK_SIG_SCHEME_V3_MIN_SDK_BLOCK_ID:
            payload = apk_bytes[cursor + 12 : cursor + pair_size]
            if len(payload) >= 4:
                info.minimum_sdk = struct.unpack_from("<I", payload, 0)[0]
        cursor += pair_size


def _find_eocd(apk_bytes: bytes) -> int | None:
    """Return the offset of the end-of-central-directory record, or ``None``."""
    signature = b"PK\x05\x06"
    found = apk_bytes.rfind(signature)
    # The record may carry a comment; verify the 4-byte signature at a valid site.
    probe = apk_bytes.rfind(signature, 0, len(apk_bytes) - 4)
    return probe if probe >= 0 else (found if found is not None else None)


# ---------------------------------------------------------------------------
# Minimal DER reader
# ---------------------------------------------------------------------------


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    """Read one TLV at ``offset``; return ``(tag, value_start, value_end)``."""
    if offset + 2 > len(data):
        raise _DerError("truncated DER element")
    tag = data[offset]
    length_byte = data[offset + 1]
    cursor = offset + 2
    if length_byte == 0x80:
        raise _DerError("indefinite length not supported")
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count > 8 or cursor + count > len(data):
            raise _DerError("overlong DER length")
        length = int.from_bytes(data[cursor : cursor + count], "big")
        cursor += count
    else:
        length = length_byte
    value_end = cursor + length
    if value_end > len(data):
        raise _DerError("DER element extends past end of buffer")
    return tag, cursor, value_end


__all__ = [
    "APK_SIG_BLOCK_MAGIC",
    "APK_SIG_SCHEME_V2_BLOCK_ID",
    "APK_SIG_SCHEME_V3_BLOCK_ID",
    "CertificateInfo",
    "SignatureSchemeInfo",
    "detect_signature_schemes",
    "extract_certificates",
]