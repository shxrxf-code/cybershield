"""MIME / true-file-type detection.

Trust model
-----------
**A file extension is user-controlled input and is never trusted.**  Every
upload passes through three independent layers:

1. ``libmagic`` (via ``python-magic``) when the shared library is available.
2. A built-in magic-byte table (:data:`~detection_engine.constants.MAGIC_SIGNATURES`)
   that always works, including on hosts without libmagic.
3. Structural validation by the format-specific parser (does the ZIP really
   contain ``[Content_Types].xml``? is the PNG IHDR sane?).

Disagreement between layers is itself a high-value signal: a ``.pdf`` whose
bytes are ``PK\\x03\\x04`` is a polyglot or a disguised archive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..constants import DOUBLE_EXTENSION_HINTS, EXTENSION_MAP, MAGIC_SIGNATURES
from ..exceptions import UnsupportedObjectError
from ..models import Finding, ObjectType, Severity, SignalSource

__all__ = [
    "TypeInfo",
    "detect_type",
    "detect_with_libmagic",
    "double_extension_hints",
    "findings_for_type",
    "is_inert_mime",
    "require_supported",
    "sniff_extension",
]

#: Head bytes read for signature detection.
_HEADER_BYTES = 4096

#: Bytes that must be present for a file to be considered text.
_TEXT_PRINTABLE_RATIO = 0.85


@dataclass(slots=True)
class TypeInfo:
    """Everything we know about what a file actually is."""

    declared_extension: str = ""
    #: The untrusted filename as supplied, used for double-extension checks.
    declared_name: str = ""
    declared_mime: str | None = None
    magic_mime: str | None = None
    libmagic_mime: str | None = None
    detected_family: str = ""
    object_type: ObjectType = ObjectType.UNKNOWN
    is_text: bool = False
    extension_mismatch: bool = False
    mime_mismatch: bool = False
    extension_matches_nothing: bool = False
    detection_source: str = ""
    notes: list[str] = field(default_factory=list)
    #: Confidence that ``object_type`` is correct.
    confidence: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "declared_extension": self.declared_extension,
            "declared_name": self.declared_name,
            "declared_mime": self.declared_mime,
            "magic_mime": self.magic_mime,
            "libmagic_mime": self.libmagic_mime,
            "family": self.detected_family,
            "object_type": self.object_type.value,
            "is_text": self.is_text,
            "extension_mismatch": self.extension_mismatch,
            "mime_mismatch": self.mime_mismatch,
            "detection_source": self.detection_source,
            "confidence": round(self.confidence, 2),
            "notes": self.notes,
        }


def _magic_family(mime: str | None, header: bytes) -> tuple[str, str]:
    """Return ``(family, mime)`` from the built-in signature table."""
    if not header:
        return "", mime or ""
    for signature, signature_mime, family in MAGIC_SIGNATURES:
        if header.startswith(signature):
            return family, signature_mime

    # Containers need a deeper look: every ZIP-based format starts "PK\x03\x04".
    if header[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip", "application/zip"
    # OLE2 compound documents carry Office 97-2003 and Outlook messages.
    if header[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole", "application/x-ole-storage"
    # DEX and Java class files.
    if header[:4] == b"dex\n":
        return "dex", "application/x-dex"
    if header[:4] == b"\xca\xfe\xba\xbe":
        return "class", "application/java-vm"
    # TAR has no leading magic number: the 'ustar' marker sits at offset 257, so
    # it can only be recognised by looking inside the header block.
    if len(header) >= 262 and header[257:262] == b"ustar":
        return "tar", "application/x-tar"
    return "", mime or ""


def _looks_like_text(header: bytes) -> bool:
    if not header:
        return False
    if b"\x00" in header:
        return False
    printable = sum(1 for byte in header if 0x20 <= byte < 0x7F or byte in (9, 10, 13))
    return printable / len(header) >= _TEXT_PRINTABLE_RATIO


def detect_with_libmagic(header: bytes) -> str | None:
    """Best-effort libmagic detection.

    Returns ``None`` when the library is unavailable or the buffer is empty.  A
    missing libmagic is *not* an error: the built-in table covers the formats
    CyberShield cares about.
    """
    if not header:
        return None
    try:
        import magic  # type: ignore[import-not-found]
    except Exception:
        return None
    try:
        detected = magic.from_buffer(header, mime=True)
    except Exception:
        return None
    return detected if isinstance(detected, str) else None


def _family_to_object_type(family: str, mime: str, header: bytes, is_text: bool) -> ObjectType:
    if family in ("png", "jpeg", "gif", "webp", "tiff", "bmp"):
        return ObjectType.IMAGE
    if family == "pdf":
        return ObjectType.DOCUMENT
    if family in ("zip", "gzip", "bzip2", "xz", "7z", "lz4", "zstd", "tar"):
        # A ZIP may be an APK or an OOXML document; both are resolved later.
        if b"AndroidManifest.xml" in header:
            return ObjectType.APK
        if b"[Content_Types].xml" in header or b"word/" in header:
            return ObjectType.DOCUMENT
        return ObjectType.ARCHIVE
    if family == "ole":
        return ObjectType.DOCUMENT
    if family == "apk":
        return ObjectType.APK
    if family == "msg":
        return ObjectType.EMAIL
    if is_text:
        if header.lstrip()[:5].lower() in (b"from:", b"to:  "):
            return ObjectType.EMAIL
        return ObjectType.TEXT
    if family in ("elf", "pe", "dex", "class"):
        return ObjectType.BINARY
    if mime.startswith("message/"):
        return ObjectType.EMAIL
    if mime.startswith("text/"):
        return ObjectType.TEXT
    return ObjectType.UNKNOWN


def detect_type(
    header: bytes,
    *,
    filename: str = "",
    declared_mime: str | None = None,
    full_data: bytes | None = None,
) -> TypeInfo:
    """Determine the true type of a file.

    Args:
        header: first :data:`_HEADER_BYTES` of the file.
        filename: the (untrusted) original filename.
        declared_mime: the (untrusted) MIME type the client claimed.
        full_data: optional complete file for container inspection.
    """
    info = TypeInfo(
        declared_mime=declared_mime,
        declared_extension=sniff_extension(filename),
        declared_name=filename[:512],
    )

    family, magic_mime = _magic_family(None, header)
    info.magic_mime = magic_mime or None
    info.libmagic_mime = detect_with_libmagic(header)
    if info.libmagic_mime:
        info.detection_source = "libmagic+signature"
        info.confidence = 0.95
    elif family:
        info.detection_source = "signature"
        info.confidence = 0.85
    else:
        info.detection_source = "heuristic"
        info.confidence = 0.4

    effective = header
    if family == "zip" and full_data is not None:
        family = _refine_zip_family(full_data) or family

    info.is_text = _looks_like_text(header)
    effective_mime = info.libmagic_mime or magic_mime or ""
    info.detected_family = family
    info.object_type = _family_to_object_type(family, effective_mime, header, info.is_text)

    # Reject a declared extension we do not recognise at all.
    if info.declared_extension and info.declared_extension not in EXTENSION_MAP:
        info.extension_matches_nothing = True
        info.notes.append(
            f"Extension '{info.declared_extension}' is not a recognised file type."
        )

    if info.declared_extension and info.declared_extension in EXTENSION_MAP:
        expected_mime, expected_type = EXTENSION_MAP[info.declared_extension]
        if expected_type == "apk" or expected_type == "binary":
            info.extension_mismatch = family not in ("zip", "apk", "elf", "pe", "dex", "class", "")
        else:
            info.extension_mismatch = _family_conflicts(family, expected_type)
        if declared_mime and declared_mime.split(";")[0].strip().lower() != expected_mime:
            info.mime_mismatch = True

    return info


def _refine_zip_family(data: bytes) -> str | None:
    """Identify what kind of ZIP this is by reading its entry names only."""
    import io
    import zipfile

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
    except Exception:
        return None
    if "AndroidManifest.xml" in names and "classes.dex" in names:
        return "apk"
    if "[Content_Types].xml" in names:
        return "ooxml"
    return None


def _family_conflicts(family: str, expected_type: str) -> bool:
    """True when the byte-level family contradicts the declared extension."""
    if not family:
        return False
    image_families = {"png", "jpeg", "gif", "webp", "tiff", "bmp"}
    if expected_type == "image":
        return family not in image_families
    if expected_type == "document":
        return family in image_families or family in ("elf", "pe", "dex")
    if expected_type == "archive":
        return family in image_families or family in ("pdf", "ole")
    if expected_type == "text":
        return family in image_families or family in ("zip", "elf", "pe", "pdf", "ole")
    return False


def sniff_extension(filename: str) -> str:
    """Return the lowercase extension of *filename*, including the dot."""
    if not filename or "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[-1].lower()


def double_extension_hints(filename_or_extension: str) -> str:
    """Return the *first* extension when the name is a deceptive double extension.

    Returns ``""`` when the name is not a double extension, or when the leading
    extension is not one commonly used to disguise a file.  Windows itself
    refuses to run ``.pdf.exe``, but Windows Explorer, most mail clients and all
    file listings show only the leading part, which is the entire point of the
    trick.

    >>> double_extension_hints("invoice.pdf.exe")
    '.pdf'
    >>> double_extension_hints("archive.zip")
    ''
    """
    if not filename_or_extension:
        return ""
    name = filename_or_extension.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    lowered = name.lower()

    # A compression or archive suffix is a normal second extension:
    # 'archive.tar.gz', 'logs.txt.gz', 'photos.zip.tar' are all conventional.
    # Only treat the name as deceptive when the final extension is itself a
    # document type that someone could mistake for the real one.
    final = "." + lowered.rsplit(".", 1)[-1] if "." in lowered else ""
    if final in _WRAPPER_SUFFIXES:
        return ""
    parts = [p for p in name.split(".") if p]
    if len(parts) < 3:
        # Need at least 'name.ext1.ext2' to be a double extension.
        return ""
    leading = "." + parts[-2].lower()
    if leading in DOUBLE_EXTENSION_HINTS:
        return leading
    return ""


#: Suffixes that legitimately sit on top of another extension.
_WRAPPER_SUFFIXES = frozenset(
    {
        ".gz", ".bz2", ".xz", ".zst", ".lz", ".lzma", ".lz4", ".br", ".z",
        ".tar", ".tgz", ".tbz", ".tbz2", ".txz", ".tzst",
    }
)


def findings_for_type(info: TypeInfo, *, size: int) -> list[Finding]:
    """Turn type-detection observations into explainable findings."""
    findings: list[Finding] = []
    expected = EXTENSION_MAP.get(info.declared_extension)

    if info.extension_mismatch:
        actual = info.detected_family or info.libmagic_mime or "unknown"
        findings.append(
            Finding(
                code="FILE.EXTENSION_MISMATCH",
                title="File content does not match its extension",
                detail=(
                    f"The filename claims '{info.declared_extension}' but the bytes "
                    f"identify as '{actual}'. Attackers rely on this to get a file "
                    "past a filter that only checks the name - and to confuse the "
                    "user about what they are opening."
                ),
                severity=Severity.HIGH,
                source=SignalSource.FILE_INTEGRITY,
                category="integrity",
                weight=18.0,
                authoritative=True,
                evidence=info.to_dict(),
            )
        )
    if info.mime_mismatch:
        findings.append(
            Finding(
                code="FILE.MIME_MISMATCH",
                title="Declared MIME type does not match the extension",
                detail=(
                    f"The client declared '{info.declared_mime}' while the "
                    f"extension implies '{expected[0] if expected else 'unknown'}'. "
                    "Mismatched declarations are common in automated malware delivery."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.FILE_INTEGRITY,
                category="integrity",
                weight=10.0,
                evidence={"declared": info.declared_mime, "expected": expected[0] if expected else None},
            )
        )
    deceptive = double_extension_hints(info.declared_name)
    if deceptive and size > 0:
        findings.append(
            Finding(
                code="FILE.DOUBLE_EXTENSION",
                title=f"Double extension: the name ends in a document extension then '{deceptive}'",
                detail=(
                    f"The filename carries a document extension "
                    f"('.{deceptive.lstrip('.')}') before its final extension. Most "
                    "systems decide what to do with a file from the last extension "
                    "only, so the earlier part is decoration: it makes the file look "
                    "like a document in a listing or a message while the system "
                    "treats it as something else. This is the core of double-extension "
                    "attacks such as 'invoice.pdf.exe'."
                ),
                severity=Severity.HIGH,
                source=SignalSource.FILE_INTEGRITY,
                category="integrity",
                weight=16.0,
                authoritative=True,
                evidence={"claimed_extension": deceptive, "final_extension": info.declared_extension},
            )
        )
    if info.extension_matches_nothing and size > 0:
        findings.append(
            Finding(
                code="FILE.UNKNOWN_EXTENSION",
                title=f"Unrecognised extension '{info.declared_extension}'",
                detail=(
                    "CyberShield has no type definition for this extension, so the "
                    "content was classified from its bytes alone."
                ),
                severity=Severity.LOW,
                source=SignalSource.FILE_INTEGRITY,
                category="integrity",
                weight=4.0,
            )
        )
    return findings


def require_supported(info: TypeInfo, allowed: set[ObjectType]) -> None:
    """Raise when a scanned object is not of an analysable type."""
    if info.object_type not in allowed:
        raise UnsupportedObjectError(
            f"Files of type '{info.detected_family or info.object_type.value}' cannot be analysed.",
            detail=f"Supported object types: {', '.join(sorted(t.value for t in allowed))}.",
        )


#: Content types that browsers will never render as anything but inert bytes.
_NEVER_RENDERED = re.compile(r"^(image/(png|jpeg|gif|webp|tiff|bmp))$")


def is_inert_mime(mime: str | None) -> bool:
    """True for types with no script or macro execution surface."""
    if not mime:
        return False
    from ..constants import INERT_MIME_TYPES

    return mime.split(";")[0].strip().lower() in INERT_MIME_TYPES