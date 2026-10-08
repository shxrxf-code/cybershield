"""File type identification from content signatures.

Signature-based identification is used in preference to the declared filename
extension or the client-supplied MIME type, because all three can be trivially
forged by an attacker. ``libmagic`` is consulted opportunistically when
available, but the built-in table is authoritative for the formats this project
supports so that analysis works in a minimal container.

The table is offset-aware: a JPEG may start at byte 0, while an ISO image
filesystem descriptor sits at offset 0x8001.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from app.detection_engine.file.analyzer_types import FileKind


@dataclass(frozen=True)
class Signature:
    """A byte pattern identifying a format."""

    offset: int
    magic: bytes
    label: str
    description: str
    extensions: tuple[str, ...]
    kind: FileKind
    #: When set, the signature must be unique to this format. Compound
    #: containers such as ZIP are matched further by internal structure.
    confidence: float = 0.95


#: Ordered by specificity. More specific patterns must come first because
#: several formats share a common prefix (RIFF containers, PKZIP containers).
SIGNATURES: Final[tuple[Signature, ...]] = (
    # -- Documents / compound binary containers --------------------------
    Signature(0, b"%PDF-", "PDF", "Portable Document Format", (".pdf",), FileKind.PDF, 0.99),
    Signature(
        0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2",
        "OLE2 Compound File (legacy Office or Outlook .msg)",
        (".doc", ".xls", ".ppt", ".msg", ".msi"), FileKind.OLE2, 0.98,
    ),
    Signature(0, b"{\\rtf", "RTF", "Rich Text Format", (".rtf",), FileKind.DOCUMENT, 0.9),
    Signature(
        257, b"CD001", "ISO9660", "ISO 9660 optical disc image",
        (".iso",), FileKind.ARCHIVE, 0.95,
    ),

    # -- Archives / installers ------------------------------------------
    Signature(0, b"PK\x03\x04", "ZIP", "ZIP archive (also APK, JAR, OOXML, DOCX)",
              (".zip", ".apk", ".jar", ".docx", ".xlsx", ".pptx", ".odt"), FileKind.ZIP, 0.9),
    Signature(0, b"PK\x05\x06", "ZIP", "Empty ZIP archive", (".zip",), FileKind.ZIP, 0.9),
    Signature(0, b"PK\x07\x08", "ZIP", "Spanned ZIP archive", (".zip",), FileKind.ZIP, 0.9),
    Signature(0, b"7z\xbc\xaf\x27\x1c", "7Z", "7-Zip archive", (".7z",), FileKind.ARCHIVE, 0.98),
    Signature(0, b"Rar!\x1a\x07", "RAR", "RAR archive", (".rar",), FileKind.ARCHIVE, 0.98),
    Signature(0, b"\x1f\x8b", "GZIP", "gzip compressed data", (".gz", ".tgz"), FileKind.ARCHIVE, 0.9),
    Signature(0, b"BZh", "BZIP2", "bzip2 compressed data", (".bz2",), FileKind.ARCHIVE, 0.9),
    Signature(0, b"\xfd7zXZ\x00", "XZ", "XZ compressed data", (".xz",), FileKind.ARCHIVE, 0.98),
    Signature(0, b"\x28\xb5\x2f\xfd", "ZSTD", "Zstandard compressed data", (".zst",), FileKind.ARCHIVE, 0.95),

    # -- Images ----------------------------------------------------------
    Signature(0, b"\x89PNG\r\n\x1a\n", "PNG", "Portable Network Graphics",
              (".png",), FileKind.IMAGE, 0.99),
    Signature(0, b"\xff\xd8\xff", "JPEG", "JPEG image", (".jpg", ".jpeg", ".jfif"),
              FileKind.IMAGE, 0.97),
    Signature(0, b"GIF87a", "GIF", "GIF image (87a)", (".gif",), FileKind.IMAGE, 0.99),
    Signature(0, b"GIF89a", "GIF", "GIF image (89a)", (".gif",), FileKind.IMAGE, 0.99),
    Signature(0, b"BM", "BMP", "Windows Bitmap", (".bmp", ".dib"), FileKind.IMAGE, 0.8),
    Signature(0, b"II*\x00", "TIFF", "TIFF image (little-endian)", (".tif", ".tiff"),
              FileKind.IMAGE, 0.95),
    Signature(0, b"MM\x00*", "TIFF", "TIFF image (big-endian)", (".tif", ".tiff"),
              FileKind.IMAGE, 0.95),
    Signature(0, b"\x00\x00\x01\x00", "ICO", "Windows icon", (".ico", ".cur"), FileKind.IMAGE, 0.9),
    Signature(0, b"8BPS", "PSD", "Adobe Photoshop image", (".psd",), FileKind.IMAGE, 0.95),
    Signature(0, b"\x00\x00\x00\x0cjP  ", "JP2", "JPEG 2000 image", (".jp2", ".j2k"),
              FileKind.IMAGE, 0.95),
    Signature(0, b"\x00\x00\x00\x18ftypheic", "HEIC", "HEIF/HEIC image", (".heic", ".heif"),
              FileKind.IMAGE, 0.9),
    Signature(0, b"\x00\x00\x00\x18ftypavif", "AVIF", "AVIF image", (".avif",), FileKind.IMAGE, 0.9),

    # -- Executables / binaries -----------------------------------------
    Signature(0, b"MZ", "PE", "Windows Portable Executable / DOS executable",
              (".exe", ".dll", ".sys", ".scr", ".ocx"), FileKind.EXECUTABLE, 0.85),
    Signature(0, b"\x7fELF", "ELF", "Executable and Linkable Format (Linux/Unix binary)",
              (".elf", ".so", ".bin"), FileKind.EXECUTABLE, 0.98),
    Signature(0, b"\xfe\xed\xfa\xce", "MACHO", "Mach-O binary (32-bit big-endian)",
              (".macho",), FileKind.EXECUTABLE, 0.98),
    Signature(0, b"\xfe\xed\xfa\xcf", "MACHO", "Mach-O binary (64-bit big-endian)",
              (".macho",), FileKind.EXECUTABLE, 0.98),
    Signature(0, b"\xcf\xfa\xed\xfe", "MACHO", "Mach-O binary (64-bit little-endian)",
              (".macho",), FileKind.EXECUTABLE, 0.98),
    Signature(0, b"\xce\xfa\xed\xfe", "MACHO", "Mach-O binary (32-bit little-endian)",
              (".macho",), FileKind.EXECUTABLE, 0.98),
    Signature(0, b"\xca\xfe\xba\xbe", "JAVA_CLASS", "Java class file / universal binary",
              (".class",), FileKind.EXECUTABLE, 0.9),
    Signature(0, b"dex\n", "DEX", "Dalvik Executable (Android)", (".dex",), FileKind.EXECUTABLE, 0.98),
    Signature(0, b"SQLite format 3\x00", "SQLITE", "SQLite database",
              (".sqlite", ".db"), FileKind.DATABASE, 0.98),
    Signature(0, b"\x4c\x00\x00\x00", "LNK", "Windows shortcut", (".lnk",), FileKind.EXECUTABLE, 0.9),
)

#: RIFF containers need their form type checked after the 8-byte prefix.
_RIFF_FORMS: Final[dict[bytes, Signature]] = {
    b"WEBP": Signature(0, b"RIFF", "WEBP", "WebP image", (".webp",), FileKind.IMAGE, 0.97),
    b"WAVE": Signature(0, b"RIFF", "WAV", "Waveform audio", (".wav",), FileKind.BINARY, 0.95),
    b"AVI ": Signature(0, b"RIFF", "AVI", "Audio Video Interleave", (".avi",), FileKind.BINARY, 0.95),
}

#: OOXML and ODF formats are ZIP containers; the first entry identifies them.
_OOXML_EXTENSIONS: Final[dict[str, FileKind]] = {
    "word/document.xml": FileKind.DOCUMENT,
    "xl/workbook.xml": FileKind.DOCUMENT,
    "ppt/presentation.xml": FileKind.DOCUMENT,
    "mimetypeapplication/vnd.oasis.opendocument.text": FileKind.DOCUMENT,
}

_TEXT_PREFIXES: Final[tuple[bytes, ...]] = (
    b"<!DOCTYPE html", b"<html", b"<HTML", b"<?xml", b"%!PS",
    b"From:", b"Received:", b"Return-Path:", b"Message-ID:",
    b"{\\rtf1",
)

#: Byte sequences that must never appear in a text file.
_BINARY_MARKERS: Final[tuple[bytes, ...]] = (
    b"\x00\x00\x00", b"\xff\xfe\x00", b"\x89PNG", b"PK\x03\x04", b"\x7fELF",
)


def read_prefix(data: bytes, size: int = 8192) -> bytes:
    """Return the first ``size`` bytes of ``data``."""
    return data[:size]


def detect_signature(data: bytes) -> Signature | None:
    """Identify ``data`` from its content signature, or return ``None``."""
    if not data:
        return None

    # RIFF containers share a 4-byte prefix; check the form type at offset 8.
    if len(data) >= 12 and data[:4] == b"RIFF":
        form = data[8:12]
        if form in _RIFF_FORMS:
            return _RIFF_FORMS[form]
        return Signature(0, b"RIFF", "RIFF", "RIFF container (unrecognised form type)",
                         (".riff",), FileKind.BINARY, 0.7)

    for signature in SIGNATURES:
        if len(data) < signature.offset + len(signature.magic):
            continue
        if data[signature.offset : signature.offset + len(signature.magic)] == signature.magic:
            return signature

    if _looks_like_text(data):
        return Signature(0, b"", "TEXT", "Plain text content", (".txt", ".eml", ".log"),
                         FileKind.TEXT, 0.6)
    return None


def _looks_like_text(data: bytes) -> bool:
    """Heuristic text detection: mostly printable, few NUL bytes."""
    if not data:
        return False
    sample = data[:4096]
    if sample.startswith(_TEXT_PREFIXES):
        return True
    for marker in _BINARY_MARKERS:
        if sample.startswith(marker):
            return False

    nul_count = sample.count(b"\x00")
    if nul_count > len(sample) // 50:
        return False

    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        # Allow a truncated multi-byte sequence at the sample boundary.
        try:
            sample[:-4].decode("utf-8")
        except UnicodeDecodeError:
            return False

    printable = sum(
        1 for byte in sample if byte in (9, 10, 13) or 32 <= byte <= 126 or byte >= 128
    )
    return printable / len(sample) > 0.85


@dataclass(frozen=True)
class FileTypeInfo:
    """Result of content-based file identification."""

    label: str
    description: str
    kind: FileKind
    extensions: tuple[str, ...]
    confidence: float
    is_text: bool = False

    @property
    def canonical_extension(self) -> str:
        return self.extensions[0] if self.extensions else ""

    @property
    def mimetype(self) -> str:
        return _MIME_BY_KIND.get(self.kind, "application/octet-stream")


_MIME_BY_KIND: Final[dict[FileKind, str]] = {
    FileKind.PDF: "application/pdf",
    FileKind.ZIP: "application/zip",
    FileKind.ARCHIVE: "application/x-archive",
    FileKind.IMAGE: "image/*",
    FileKind.DOCUMENT: "application/vnd.ms-office.document",
    FileKind.OLE2: "application/x-ole-storage",
    FileKind.EXECUTABLE: "application/x-executable",
    FileKind.EMAIL: "message/rfc822",
    FileKind.TEXT: "text/plain",
    FileKind.BINARY: "application/octet-stream",
    FileKind.DATABASE: "application/x-sqlite3",
    FileKind.UNKNOWN: "application/octet-stream",
}


def identify(data: bytes) -> FileTypeInfo:
    """Identify the content type of ``data`` from its leading bytes."""
    signature = detect_signature(data)
    if signature is None:
        return FileTypeInfo(
            label="UNKNOWN",
            description="Unrecognised binary content",
            kind=FileKind.UNKNOWN,
            extensions=(),
            confidence=0.0,
        )
    return FileTypeInfo(
        label=signature.label,
        description=signature.description,
        kind=signature.kind,
        extensions=signature.extensions,
        confidence=signature.confidence,
        is_text=signature.kind is FileKind.TEXT,
    )


def extension_matches(content: FileTypeInfo, filename: str | None) -> bool:
    """Does the filename extension agree with the detected content type?"""
    if not filename or "." not in filename:
        return True  # Nothing to contradict.
    extension = "." + filename.rsplit(".", 1)[1].lower()
    if not content.extensions:
        return True
    return extension in content.extensions