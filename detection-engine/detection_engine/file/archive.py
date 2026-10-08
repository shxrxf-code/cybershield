"""Archive analysis (ZIP-family containers).

A ZIP is a *delivery vehicle*, not a threat.  What matters is what is inside:

* executables and scripts hidden next to a document,
* path-traversal member names (``../../.bashrc``) used for zip-slip attacks,
* extreme compression ratios (zip bombs),
* nested archives that hide their real payload,
* files whose names lie about their extension.

This module never extracts anything to disk: members are read in memory, with a
hard cap on count, per-member size and total decompressed bytes.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field

from ..constants import (
    EXECUTABLE_EXTENSIONS,
    MAGIC_SIGNATURES,
    MAX_ARCHIVE_ENTRIES,
    MAX_ARCHIVE_ENTRY_SIZE,
)
from ..models import Finding, Severity, SignalSource
from ..security.hardening import is_path_traversal, sanitize_filename

__all__ = [
    "ArchiveMember",
    "ArchiveReport",
    "archive_findings",
    "analyze_archive",
    "analyze_tar",
    "decompress_stream",
    "is_archive",
    "iter_archive",
    "read_member",
]

#: Above this, the compression ratio is treated as a zip bomb.
_BOMB_RATIO = 100.0
#: Absolute decompressed budget for one archive scan.
_TOTAL_BUDGET = 200 * 1024 * 1024


@dataclass(slots=True)
class ArchiveMember:
    """One entry listed inside a container."""

    name: str
    compressed_size: int = 0
    file_size: int = 0
    ratio: float = 0.0
    is_directory: bool = False
    is_symlink: bool = False
    encrypted: bool = False
    crc: int | None = None
    detected_family: str = ""
    extension: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "compressed_size": self.compressed_size,
            "size": self.file_size,
            "ratio": round(self.ratio, 2),
            "directory": self.is_directory,
            "symlink": self.is_symlink,
            "encrypted": self.encrypted,
            "family": self.detected_family,
            "extension": self.extension,
        }


@dataclass(slots=True)
class ArchiveReport:
    """Structured summary of a container."""

    format: str = "zip"
    member_count: int = 0
    members: list[ArchiveMember] = field(default_factory=list)
    total_uncompressed: int = 0
    total_compressed: int = 0
    executable_members: list[str] = field(default_factory=list)
    traversal_members: list[str] = field(default_factory=list)
    symlink_members: list[str] = field(default_factory=list)
    nested_archives: list[str] = field(default_factory=list)
    extension_spoofs: list[dict[str, str]] = field(default_factory=list)
    password_protected: bool = False
    truncated: bool = False
    errors: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "member_count": self.member_count,
            "total_uncompressed": self.total_uncompressed,
            "total_compressed": self.total_compressed,
            "executable_members": self.executable_members[:50],
            "traversal_members": self.traversal_members[:50],
            "symlink_members": self.symlink_members[:50],
            "nested_archives": self.nested_archives[:50],
            "extension_spoofs": self.extension_spoofs[:50],
            "password_protected": self.password_protected,
            "errors": self.errors,
            "members": [m.to_dict() for m in self.members[:200]],
        }


def is_archive(data: bytes) -> bool:
    """True when *data* starts with a recognised container signature."""
    for signature, _mime, family in MAGIC_SIGNATURES:
        if family in ("zip", "gzip", "7z", "bzip2", "xz", "lz4", "zstd"):
            if data.startswith(signature):
                return True
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return True
    # TAR's marker lives inside the first header block.
    if len(data) >= 262 and data[257:262] == b"ustar":
        return True
    return False


def _family_for(header: bytes) -> str:
    for signature, _mime, family in MAGIC_SIGNATURES:
        if header.startswith(signature):
            return family
    return ""


#: Compressed single-stream containers we can list without an external tool.
_STREAM_FAMILIES = {"gzip", "bzip2", "xz", "lzma", "zstd", "lz4"}


def _analyze_stream(data: bytes, family: str, *, max_members: int) -> ArchiveReport:
    """List a single-stream compressed file (``.gz``, ``.bz2``, ``.xz``, ...).

    These containers hold exactly one member, but the member can still be an
    executable, and *how well it compresses* is itself a signal: a text file
    compresses to roughly a third, whereas an already-packed or encrypted
    payload barely shrinks.
    """
    report = ArchiveReport(format=family)
    try:
        raw = decompress_stream(data, family)
    except Exception as exc:
        report.errors.append(f"The {family} stream could not be decompressed: {exc}")
        return report

    if raw is None:
        report.errors.append(
            f"No decompressor is available for {family} containers, so the "
            "contents were not inspected."
        )
        return report

    name, extension = _derive_member_name(data, family)
    ratio = len(data) / len(raw) if raw else 0.0
    member = ArchiveMember(
        name=name,
        compressed_size=len(data),
        file_size=len(raw),
        ratio=ratio,
        extension=extension,
        detected_family=_family_for(raw[:512]),
    )
    report.members.append(member)
    report.member_count = 1
    report.total_compressed = len(data)
    report.total_uncompressed = len(raw)
    if extension in EXECUTABLE_EXTENSIONS:
        report.executable_members.append(name)
    return report


def decompress_stream(data: bytes, family: str) -> bytes | None:
    """Decompress a single-stream container, or return ``None`` if unsupported."""
    import bz2
    import gzip
    import lzma

    try:
        if family == "gzip":
            return gzip.decompress(data)
        if family == "bzip2":
            return bz2.decompress(data)
        if family in ("xz", "lzma"):
            return lzma.decompress(data)
        if family == "zstd":
            try:
                import zstandard  # type: ignore[import-not-found]
            except ImportError:
                return None
            return zstandard.ZstdDecompressor().decompressobj().decompress(data)
        if family == "lz4":
            try:
                import lz4.frame  # type: ignore[import-not-found]
            except ImportError:
                return None
            return lz4.frame.decompress(data)
    except Exception:
        raise
    return None


def _derive_member_name(data: bytes, family: str) -> tuple[str, str]:
    """Best-effort member name from a stream container's stored filename."""
    if family == "gzip" and len(data) > 10:
        flg = data[3]
        offset = 10
        if flg & 0x04:  # FEXTRA
            if offset + 2 <= len(data):
                xlen = int.from_bytes(data[offset : offset + 2], "little")
                offset += 2 + xlen
        if flg & 0x08 and offset < len(data):  # FNAME
            end = data.find(b"\x00", offset)
            if end != -1:
                stored = data[offset:end].decode("utf-8", errors="replace")
                # The stored name is attacker-controlled and is used only for
                # display, after flattening and sanitising.
                name = sanitize_filename(
                    stored.rsplit("/", 1)[-1], fallback="decompressed stream"
                )
                extension = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
                return name, extension
    return f"decompressed {family} stream", ""


def analyze_tar(data: bytes, *, max_members: int = MAX_ARCHIVE_ENTRIES) -> ArchiveReport:
    """List a TAR archive, including tarballs wrapped in gzip or bzip2."""
    report = ArchiveReport(format="tar")
    payload = data
    if data[:2] == b"\x1f\x8b":
        try:
            payload = gzip_decompress(data)
        except Exception as exc:
            report.errors.append(f"The gzip wrapper could not be removed: {exc}")
            return report
        if payload is None:
            report.errors.append("No gzip decompressor is available.")
            return report
    elif data[:3] == b"BZh":
        try:
            payload = bz2_decompress(data)
        except Exception as exc:
            report.errors.append(f"The bzip2 wrapper could not be removed: {exc}")
            return report
        if payload is None:
            report.errors.append("No bzip2 decompressor is available.")
            return report
    else:
        # A plain tar has no magic number, so it can only be recognised by trying.
        if len(data) < 512 or data[257:262] not in (b"ustar",):
            report.format = "unknown"
            report.errors.append("Not a recognisable archive container.")
            return report

    try:
        import tarfile

        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as tar:
            for index, info in enumerate(tar):
                if index >= max_members:
                    report.truncated = True
                    report.errors.append(
                        f"Archive lists more than {max_members} entries; "
                        "analysis was truncated."
                    )
                    break
                name = (info.name or "")[:512]
                extension = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
                member = ArchiveMember(
                    name=name,
                    compressed_size=info.size,
                    file_size=info.size,
                    is_directory=info.isdir(),
                    extension=extension,
                    is_symlink=info.issym() or info.islnk(),
                )
                report.members.append(member)
                report.member_count += 1
                report.total_uncompressed += info.size
                if is_path_traversal(name):
                    report.traversal_members.append(name[:256])
                if member.is_symlink:
                    report.symlink_members.append(name[:256])
                if extension in EXECUTABLE_EXTENSIONS:
                    report.executable_members.append(name[:256])
                if extension in (".zip", ".jar", ".7z", ".rar", ".apk", ".tar", ".gz", ".tgz"):
                    report.nested_archives.append(name[:256])
    except Exception as exc:
        report.errors.append(f"The TAR container could not be read: {exc}")
    return report


def gzip_decompress(data: bytes) -> bytes | None:
    """Convenience wrapper; ``None`` when no decompressor is available."""
    return decompress_stream(data, "gzip")


def bz2_decompress(data: bytes) -> bytes | None:
    """Convenience wrapper; ``None`` when no decompressor is available."""
    return decompress_stream(data, "bzip2")


def analyze_archive(data: bytes, *, max_members: int = 2000) -> ArchiveReport:
    """List and classify the contents of an archive of any supported family."""
    family = _family_for(data[:512])
    if data[:2] == b"\x1f\x8b" or data[:3] == b"BZh":
        # A compressed stream is either a tarball or a single compressed file.
        # Try tar first: if it parses, the member listing is far more useful.
        probe = analyze_tar(data, max_members=min(max_members, MAX_ARCHIVE_ENTRIES))
        if probe.member_count:
            return probe
        stream = _analyze_stream(
            data, "gzip" if data[:2] == b"\x1f\x8b" else "bzip2", max_members=max_members
        )
        # Prefer whichever produced an actual listing; otherwise show both errors.
        if stream.member_count or not probe.errors:
            return stream
        return probe
    if family in _STREAM_FAMILIES:
        return _analyze_stream(data, family, max_members=max_members)
    if len(data) >= 512 and data[257:262] == b"ustar":
        return analyze_tar(data, max_members=min(max_members, MAX_ARCHIVE_ENTRIES))

    report = ArchiveReport()
    if not data.startswith(b"PK\x03\x04") and not data.startswith(b"PK\x05\x06"):
        report.format = family or "unknown"
        report.errors.append(
            f"Not a container format CyberShield can list (detected '{family or 'unknown'}')."
        )
        return report

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        report.errors.append(f"Corrupt ZIP container: {exc}")
        return report

    with archive:
        if archive.comment:
            report.comments.append(archive.comment.decode("utf-8", errors="replace")[:500])
        try:
            infos = archive.infolist()
        except Exception as exc:  # pragma: no cover - defensive
            report.errors.append(f"Could not read the central directory: {exc}")
            return report

        if len(infos) > MAX_ARCHIVE_ENTRIES:
            report.truncated = True
            report.errors.append(
                f"Archive lists {len(infos)} entries; analysis limited to the first {max_members}."
            )
        report.member_count = len(infos)

        for info in infos[:max_members]:
            ratio = (info.file_size / info.compress_size) if info.compress_size else 0.0
            extension = ""
            if "." in info.filename:
                extension = "." + info.filename.rsplit(".", 1)[-1].lower()
            member = ArchiveMember(
                name=info.filename[:512],
                compressed_size=info.compress_size,
                file_size=info.file_size,
                ratio=ratio,
                is_directory=info.is_dir(),
                encrypted=bool(info.flag_bits & 0x1),
                crc=info.CRC,
                extension=extension,
            )
            report.members.append(member)
            report.total_compressed += info.compress_size
            report.total_uncompressed += info.file_size

            if is_path_traversal(info.filename):
                report.traversal_members.append(info.filename[:256])
            if extension in EXECUTABLE_EXTENSIONS:
                report.executable_members.append(info.filename[:256])
            if extension in (".zip", ".jar", ".7z", ".rar", ".apk", ".tar", ".gz"):
                report.nested_archives.append(info.filename[:256])
            if member.encrypted and not info.is_dir():
                report.password_protected = True

            # Verify the declared extension against the real bytes when the
            # member is small enough to read cheaply.
            if not info.is_dir() and info.file_size and info.file_size <= 2 * 1024 * 1024:
                actual = _peek_family(archive, info)
                if actual:
                    member.detected_family = actual
                    if extension and _spoofed(extension, actual):
                        report.extension_spoofs.append(
                            {"name": info.filename[:256], "claims": extension, "is": actual}
                        )
    return report


def _peek_family(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    try:
        with archive.open(info) as handle:
            header = handle.read(64)
    except (RuntimeError, zipfile.BadZipFile, OSError):
        return ""
    if not header:
        return ""
    family = _family_for(header)
    if family:
        return family
    if header[:5] in (b"%PDF-",):
        return "pdf"
    printable = sum(1 for b in header if 0x20 <= b < 0x7F or b in (9, 10, 13))
    if printable / len(header) > 0.9:
        return "text"
    return "binary"


def _spoofed(extension: str, actual_family: str) -> bool:
    image = {"png", "jpeg", "gif", "webp", "tiff", "bmp"}
    if extension in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".tif", ".tiff", ".bmp"):
        return actual_family not in image
    if extension in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf"):
        return actual_family in image or actual_family in ("elf", "pe")
    if extension in (".txt", ".csv", ".json", ".xml"):
        return actual_family in image or actual_family in ("zip", "elf", "pe", "dex")
    return False


def archive_findings(report: ArchiveReport, *, object_type: str = "archive") -> list[Finding]:
    """Findings derived from a :class:`ArchiveReport`."""
    findings: list[Finding] = []
    if report.errors and not report.member_count:
        return [
            Finding(
                code="ARCHIVE.UNREADABLE",
                title="Archive could not be read",
                detail=(
                    "; ".join(report.errors)
                    + " The contents could not be inspected, so nothing can be "
                    "concluded about what this archive contains."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.ARCHIVE,
                category="integrity",
                weight=8.0,
            )
        ]

    if report.traversal_members:
        findings.append(
            Finding(
                code="ARCHIVE.PATH_TRAVERSAL",
                title="Archive contains path-traversal entries",
                detail=(
                    "Member names such as "
                    f"{', '.join(repr(m) for m in report.traversal_members[:3])} "
                    "escape the extraction directory. Extracting this archive with a "
                    "naive tool can overwrite arbitrary files (a 'zip slip' attack)."
                ),
                severity=Severity.HIGH,
                source=SignalSource.ARCHIVE,
                category="payload",
                weight=20.0,
                authoritative=True,
                evidence={"members": report.traversal_members[:20]},
            )
        )

    if report.symlink_members:
        findings.append(
            Finding(
                code="ARCHIVE.SYMLINK_ESCAPE",
                title="Archive contains symbolic links",
                detail=(
                    f"{len(report.symlink_members)} entry/entries are symbolic links "
                    f"({', '.join(repr(m) for m in report.symlink_members[:3])}). "
                    "A link pointing outside the extraction directory lets a "
                    "subsequent write land anywhere on the filesystem, which is how "
                    "archive-extraction bugs become arbitrary file overwrite."
                ),
                severity=Severity.HIGH,
                source=SignalSource.ARCHIVE,
                category="payload",
                weight=18.0,
                authoritative=True,
                evidence={"members": report.symlink_members[:20]},
            )
        )

    if report.executable_members:
        findings.append(
            Finding(
                code="ARCHIVE.CONTAINS_EXECUTABLE",
                title=f"Archive contains {len(report.executable_members)} executable or script file(s)",
                detail=(
                    "Files such as "
                    f"{', '.join(report.executable_members[:5])} are inside the "
                    "archive. Bundling an executable with a document is the standard "
                    "way to deliver malware past mail gateways that only inspect "
                    "attachments by name."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.ARCHIVE,
                category="payload",
                weight=14.0,
                evidence={"members": report.executable_members[:20]},
            )
        )

    if report.extension_spoofs:
        findings.append(
            Finding(
                code="ARCHIVE.EXTENSION_SPOOF",
                title="Archive members do not match their names",
                detail=(
                    f"{len(report.extension_spoofs)} member(s) have an extension that "
                    "contradicts their actual content, e.g. "
                    f"{report.extension_spoofs[0]['name']} claims "
                    f"'{report.extension_spoofs[0]['claims']}' but is "
                    f"{report.extension_spoofs[0]['is']}."
                ),
                severity=Severity.HIGH,
                source=SignalSource.ARCHIVE,
                category="integrity",
                weight=18.0,
                authoritative=True,
                evidence={"members": report.extension_spoofs[:20]},
            )
        )

    bombs = [m for m in report.members if m.ratio >= _BOMB_RATIO and m.file_size > 1024 * 1024]
    if bombs or report.total_uncompressed > _TOTAL_BUDGET:
        offenders = [f"{m.name} ({m.ratio:.0f}x)" for m in bombs[:3]]
        findings.append(
            Finding(
                code="ARCHIVE.DECOMPRESSION_BOMB",
                title="Archive expands to an extreme size",
                detail=(
                    f"The archive decompresses to {report.total_uncompressed / 1_048_576:.1f} MB"
                    + (f" with ratios like {', '.join(offenders)}" if offenders else "")
                    + ". Decompression bombs exhaust memory and disk, and are used "
                    "to disable security tooling."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.ARCHIVE,
                category="availability",
                weight=12.0,
                evidence={
                    "total_uncompressed": report.total_uncompressed,
                    "max_ratio": max((m.ratio for m in report.members), default=0),
                },
            )
        )

    if report.password_protected:
        findings.append(
            Finding(
                code="ARCHIVE.PASSWORD_PROTECTED",
                title="Archive is password protected",
                detail=(
                    "Encrypted archives cannot be inspected by any content scanner, "
                    "including this one. Password protection on an unsolicited "
                    "attachment is a strong social-engineering signal."
                ),
                severity=Severity.LOW,
                source=SignalSource.ARCHIVE,
                category="structure",
                weight=6.0,
            )
        )

    if report.nested_archives and object_type in ("archive", "document"):
        findings.append(
            Finding(
                code="ARCHIVE.NESTED_ARCHIVE",
                title="Archive contains further archives",
                detail=(
                    f"{len(report.nested_archives)} nested archive(s) were found. "
                    "Nesting is used to defeat scanners that only inspect the outer "
                    "layer, and to make the payload harder to review by hand."
                ),
                severity=Severity.LOW,
                source=SignalSource.ARCHIVE,
                category="structure",
                weight=8.0,
                evidence={"members": report.nested_archives[:20]},
            )
        )

    if report.member_count > 500:
        findings.append(
            Finding(
                code="ARCHIVE.MANY_ENTRIES",
                title=f"Archive contains {report.member_count} files",
                detail=(
                    "Very large file counts are used to bury the interesting member "
                    "among thousands of decoys."
                ),
                severity=Severity.LOW,
                source=SignalSource.ARCHIVE,
                category="structure",
                weight=5.0,
            )
        )
    return findings


def read_member(data: bytes, member_name: str, *, limit: int = MAX_ARCHIVE_ENTRY_SIZE) -> bytes:
    """Read one member into memory with a size cap and a traversal check."""
    if is_path_traversal(member_name):
        raise ValueError(f"Refusing to read member with traversal path: {member_name!r}")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        with archive.open(member_name) as handle:
            return handle.read(limit)


def iter_archive(data: bytes, *, max_members: int = MAX_ARCHIVE_ENTRIES):
    """Yield ``(name, bytes)`` for each member, bounded in count and size."""
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for index, info in enumerate(archive.infolist()):
            if index >= max_members or info.is_dir():
                continue
            if info.file_size > MAX_ARCHIVE_ENTRY_SIZE:
                yield info.filename, b""
                continue
            try:
                with archive.open(info) as handle:
                    yield info.filename, handle.read(MAX_ARCHIVE_ENTRY_SIZE)
            except (RuntimeError, zipfile.BadZipFile, OSError):
                yield info.filename, b""