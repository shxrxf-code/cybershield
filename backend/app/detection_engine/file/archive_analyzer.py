"""Archive analysis (ZIP, and best-effort for other containers).

Threats addressed
-----------------
* **Zip-slip / path traversal** - archive members with absolute paths, drive
  letters or ``..`` traversal. CyberShield never extracts archives, but it
  reports the condition because it indicates either a malicious archive or an
  attempt to exploit an extracting application.
* **Entry flooding** - tens of thousands of members used to exhaust analysis
  tools and extraction quotas.
* **Zip bombs** - extreme compression ratios or nested archives.
* **Concealed executables** - archive entries whose extension is an executable,
  or whose content contradicts its name.
* **Nested archives** - archives within archives, which delay inspection and
  defeat shallow scanning.
* **Encrypted archives** - prevent content inspection entirely.
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import TYPE_CHECKING

from app.detection_engine.file.analyzer import EXECUTABLE_EXTENSIONS
from app.detection_engine.file.magic import identify
from app.schemas.common import IndicatorType, Severity, SignalSource
from app.schemas.signal import DetectionSignal, Indicator

if TYPE_CHECKING:  # pragma: no cover
    from app.detection_engine.file.analyzer import FileAnalysisResult

_MAX_ENTRIES = 5000
_MAX_TOTAL_UNCOMPRESSED = 2 * 1024 * 1024 * 1024  # 2 GiB aggregate ceiling
_MAX_INSPECT_BYTES = 4 * 1024 * 1024
_MAX_CONTENT_SNIFF = 40  # how many members are content-inspected
_COMPRESSION_RATIO_LIMIT = 120.0

#: Members whose names indicate a nested container.
_NESTED_ARCHIVE_NAMES: re.Pattern[str] = re.compile(
    r"\.(?:zip|7z|rar|tar|gz|tgz|bz2|xz|iso|img|cab|jar|apk)$", re.I
)

#: Names that reveal an embedded executable even with a benign extension.
_SUSPICIOUS_MEMBER_NAMES: re.Pattern[str] = re.compile(
    r"(?:^|[/\\])?(?:autorun|setup|install|update|patch|install_[a-z]+|crack|keygen|"
    r"svchost|lsass|csrss|rundll32|powershell|cmd)\.(?:exe|bat|cmd|scr|com|pif|vbs|js)$",
    re.I,
)

#: Macro/loader payloads that arrive with an innocuous extension.
_DISGUISED_PAYLOAD_NAMES: re.Pattern[str] = re.compile(
    r"(?:^|[/\\])?(?:invoice|payload|stage[0-9]?|loader|dropper|stub|data|document|"
    r"readme|instructions|notice)[\w\-]{0,24}\.(?:doc|docx|xls|xlsx|ppt|pptx|pdf|txt|"
    r"jpg|png|gif|csv|rtf)$",
    re.I,
)


def analyse_archive(data: bytes, result: "FileAnalysisResult") -> list[DetectionSignal]:
    """Inspect a ZIP container without extracting it."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError):
        return [
            DetectionSignal(
                code="archive.unreadable",
                title="Archive could not be opened",
                description=(
                    "The file carries an archive signature but its directory is unreadable. It "
                    "may be corrupted, truncated, or crafted to frustrate automated inspection."
                ),
                severity=Severity.MEDIUM,
                category="structural",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.6,
                evidence={"zip_error": True},
            )
        ]

    with archive:
        return _analyse_entries(archive, result)


def _analyse_entries(archive: zipfile.ZipFile, result: "FileAnalysisResult") -> list[DetectionSignal]:
    signals: list[DetectionSignal] = []
    try:
        infos = archive.infolist()
    except (RuntimeError, OSError):
        return signals

    entry_names = [info.filename for info in infos]
    result.metadata["archive_entry_count"] = len(infos)

    # -- Entry flooding ------------------------------------------------
    if len(infos) > _MAX_ENTRIES:
        signals.append(
            DetectionSignal(
                code="archive.entry_flood",
                title="Archive contains an excessive number of entries",
                description=(
                    f"The archive declares {len(infos)} members, above the analysis limit of "
                    f"{_MAX_ENTRIES}. This entry-flood pattern is used to exhaust extraction "
                    "quotas and to bury malicious files."
                ),
                severity=Severity.MEDIUM,
                category="obfuscation",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.75,
                evidence={"entry_count": len(infos), "limit": _MAX_ENTRIES},
            )
        )

    # -- Path traversal -------------------------------------------------
    traversal = [name for name in entry_names if _is_traversal_path(name)]
    if traversal:
        signals.append(
            DetectionSignal(
                code="archive.path_traversal",
                title="Archive contains path-traversal member names",
                description=(
                    "Some archive members use absolute paths, drive letters or parent-directory "
                    "traversal ('..'). Extracting such an archive can overwrite files outside the "
                    "intended directory. CyberShield never extracts archives, but other "
                    "applications on the system may."
                ),
                severity=Severity.HIGH,
                category="deception",
                source=SignalSource.STRUCTURAL,
                confidence=0.85,
                evidence={"count": len(traversal), "examples": traversal[:8]},
            )
        )

    # -- Executables inside the archive ---------------------------------
    executables = [
        info.filename
        for info in infos
        if _extension_of(info.filename) in EXECUTABLE_EXTENSIONS
    ]
    if executables:
        signals.append(
            DetectionSignal(
                code="archive.contains_executable",
                title="Archive contains executable files",
                description=(
                    f"The archive contains {len(executables)} executable or script files "
                    f"({', '.join(sorted({_extension_of(n) for n in executables})[:5])}). "
                    "Archives are frequently used to package and distribute malware because the "
                    "individual members bypass file-scanning filters."
                ),
                severity=Severity.HIGH,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.8,
                weight=0.55,
                evidence={"count": len(executables), "examples": executables[:10]},
            )
        )

    disguised = [
        info.filename for info in infos if _SUSPICIOUS_MEMBER_NAMES.search(info.filename)
    ]
    if disguised:
        signals.append(
            DetectionSignal(
                code="archive.suspicious_member_names",
                title="Archive contains members with malware-associated names",
                description=(
                    "Some member names match well-known malware or social-engineering file names "
                    "("
                    + ", ".join(disguised[:5])
                    + "). These names are used to persuade the user to open a file."
                ),
                severity=Severity.MEDIUM,
                category="deception",
                source=SignalSource.HEURISTIC,
                confidence=0.6,
                evidence={"members": disguised[:10]},
            )
        )

    payload_names = [
        info.filename
        for info in infos
        if _DISGUISED_PAYLOAD_NAMES.search(info.filename) and _content_disagrees(archive, info)
    ]
    if payload_names:
        signals.append(
            DetectionSignal(
                code="archive.content_disagrees_with_name",
                title="Archive members claim to be documents but are not",
                description=(
                    "Members with document or image extensions actually contain different file "
                    "types ("
                    + ", ".join(payload_names[:5])
                    + "). This is a direct technique for bypassing type-based filtering."
                ),
                severity=Severity.HIGH,
                category="deception",
                source=SignalSource.STRUCTURAL,
                confidence=0.8,
                evidence={"members": payload_names[:10]},
            )
        )

    # -- Nested archives -------------------------------------------------
    nested = [name for name in entry_names if _NESTED_ARCHIVE_NAMES.search(name)]
    if nested:
        depth_note = (
            "Archives nested inside archives delay inspection and defeat shallow scanning, and "
            "are a common way to hide payloads from email gateways."
        )
        signals.append(
            DetectionSignal(
                code="archive.nested_archive",
                title="Archive contains further archives",
                description=f"{depth_note} {len(nested)} nested container(s) were found.",
                severity=Severity.LOW if len(nested) < 3 else Severity.MEDIUM,
                category="obfuscation",
                source=SignalSource.STRUCTURAL,
                confidence=0.6,
                evidence={"count": len(nested), "examples": nested[:10]},
            )
        )

    # -- Compression ratio / zip bomb ------------------------------------
    ratio_findings = _analyse_compression(infos)
    if ratio_findings:
        signals.append(ratio_findings)

    # -- Encryption -------------------------------------------------------
    encrypted = [info.filename for info in infos if info.flag_bits & 0x1]
    if encrypted:
        signals.append(
            DetectionSignal(
                code="archive.encrypted_entries",
                title="Archive contains encrypted members",
                description=(
                    f"{len(encrypted)} member(s) are encrypted. Encrypted content cannot be "
                    "inspected without the password, so the safety of the archive contents "
                    "cannot be established by automated analysis."
                ),
                severity=Severity.MEDIUM,
                category="obfuscation",
                source=SignalSource.STRUCTURAL,
                confidence=0.8,
                evidence={"count": len(encrypted), "examples": encrypted[:10]},
            )
        )

    # -- Anonymous / malformed entries -------------------------------------
    anonymous = [info.filename for info in infos if not info.filename.strip()]
    if anonymous:
        signals.append(
            DetectionSignal(
                code="archive.anonymous_entries",
                title="Archive contains unnamed entries",
                description=(
                    "The archive declares members with empty names. This prevents meaningful "
                    "user warnings and interferes with security tooling."
                ),
                severity=Severity.MEDIUM,
                category="obfuscation",
                source=SignalSource.STRUCTURAL,
                confidence=0.7,
                evidence={"anonymous_entry_count": len(anonymous)},
            )
        )

    # -- Content inspection of a sample of members -------------------------
    signals.extend(_inspect_member_content(archive, infos, result))

    return signals


def _is_traversal_path(name: str) -> bool:
    """Detect absolute paths, drive letters and ``..`` traversal in member names."""
    if not name:
        return False
    normalised = name.replace("\\", "/")
    if normalised.startswith("/"):
        return True
    if re.match(r"^[A-Za-z]:", normalised):
        return True
    if normalised.startswith("~"):
        return True
    segments = normalised.split("/")
    if ".." in segments:
        return True
    # Encoded traversal that a naive extractor would decode and follow.
    lowered = normalised.lower().replace("%2e", ".")
    return ".." in lowered.split("/")


def _extension_of(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in base:
        return ""
    return "." + base.rsplit(".", 1)[1].lower()


def _content_disagrees(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bool:
    """Read a member's leading bytes and compare them with its extension."""
    extension = _extension_of(info.filename)
    if extension not in (".pdf", ".docx", ".xlsx", ".pptx", ".jpg", ".jpeg", ".png", ".txt", ".rtf"):
        return False
    try:
        with archive.open(info) as handle:
            head = handle.read(512)
    except (RuntimeError, zipfile.BadZipFile, OSError, EOFError):
        return False
    if not head:
        return False

    detected = identify(head)
    if detected.kind.value == "unknown":
        return False
    allowed = detected.extensions
    return bool(allowed) and extension not in allowed


def _analyse_compression(infos: list[zipfile.ZipInfo]) -> DetectionSignal | None:
    """Flag zip bombs and suspicious compression ratios."""
    total_compressed = sum(info.compress_size for info in infos)
    total_uncompressed = sum(info.file_size for info in infos)
    if total_compressed <= 0 or total_uncompressed <= 0:
        return None
    ratio = total_uncompressed / total_compressed

    if ratio > _COMPRESSION_RATIO_LIMIT or total_uncompressed > _MAX_TOTAL_UNCOMPRESSED:
        return DetectionSignal(
            code="archive.compression_bomb",
            title="Archive has an extreme compression ratio",
            description=(
                f"The archive expands from {total_compressed} bytes to roughly "
                f"{total_uncompressed} bytes, a ratio of {ratio:.0f}:1. Such archives exhaust "
                "disk space and memory during extraction, which is a denial-of-service technique."
            ),
            severity=Severity.HIGH,
            category="obfuscation",
            source=SignalSource.HEURISTIC,
            confidence=0.8,
            evidence={
                "compressed_bytes": total_compressed,
                "uncompressed_bytes": total_uncompressed,
                "ratio": round(ratio, 2),
                "limit": _COMPRESSION_RATIO_LIMIT,
            },
        )
    return None


def _inspect_member_content(
    archive: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
    result: "FileAnalysisResult",
) -> list[DetectionSignal]:
    """Sniff the leading bytes of a bounded sample of members."""
    indicators: list[Indicator] = []
    mismatches: list[str] = []
    checked = 0

    for info in infos:
        if checked >= _MAX_CONTENT_SNIFF:
            break
        if info.file_size == 0 or info.file_size > _MAX_INSPECT_BYTES:
            continue
        if info.is_dir() or info.flag_bits & 0x1:
            continue
        # Only inspect files whose names suggest an executable or unknown type.
        extension = _extension_of(info.filename)
        if extension in (".png", ".jpg", ".jpeg", ".gif", ".xml", ".json", ".txt", ".md"):
            continue
        try:
            with archive.open(info) as handle:
                head = handle.read(1024)
        except (RuntimeError, zipfile.BadZipFile, OSError, EOFError, NotImplementedError):
            continue

        checked += 1
        if not head:
            continue
        detected = identify(head)
        if detected.kind.value == "executable":
            base = info.filename.replace("\\", "/").rsplit("/", 1)[-1]
            mismatches.append(base)
            indicators.append(
                Indicator(
                    type=IndicatorType.FILE_PATH,
                    value=base[:255],
                    context="archive member detected as executable by content signature",
                )
            )

    if mismatches:
        return [
            DetectionSignal(
                code="archive.hidden_executable",
                title="Archive member is an executable despite its name",
                description=(
                    "Content inspection found "
                    f"{len(mismatches)} member(s) whose bytes identify as executable code even "
                    "though the filename does not indicate that ("
                    + ", ".join(mismatches[:5])
                    + "). This is the core mechanism of archive-based malware distribution."
                ),
                severity=Severity.CRITICAL,
                category="static_analysis",
                source=SignalSource.STRUCTURAL,
                confidence=0.85,
                weight=0.7,
                evidence={"members": mismatches[:10], "inspected": checked},
                indicators=tuple(indicators[:10]),
            )
        ]
    return []