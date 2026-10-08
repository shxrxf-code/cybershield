"""File analysis orchestration.

Pipeline position::

    bytes -> signature identification -> extension/magic cross-check
          -> entropy profile -> specialised analyser (document/image/archive)
          -> indicator extraction -> ClamAV -> YARA -> threat intelligence
          -> risk engine

Nothing in this module executes, extracts to disk, or renders uploaded content.
Every input is treated as hostile.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from app.detection_engine.entropy import normalised_entropy, shannon_entropy
from app.detection_engine.file.analyzer_types import FileKind
from app.detection_engine.file.hashing import FileHashes, hash_bytes
from app.detection_engine.file.magic import FileTypeInfo, extension_matches, identify
from app.detection_engine.text import extract_urls, truncate_for_display
from app.schemas.common import IndicatorType, Severity, SignalSource
from app.schemas.signal import DetectionSignal, Indicator

#: Extensions that execute code. Their presence inside an archive or document is
#: always reported, because archives exist precisely to smuggle them past filters.
EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".hta", ".msi", ".msp", ".jar", ".ps1",
        ".psm1", ".psd1", ".lnk", ".reg", ".chm", ".apk", ".deb", ".rpm",
        ".dmg", ".pkg", ".app", ".elf", ".so", ".sys", ".cpl", ".gadget",
        ".iso", ".img", ".vhd", ".vhdx", ".cab", ".msu", ".wsb", ".xll",
    }
)

#: Double-extension lures: a benign extension followed by an executable one.
_DOUBLE_EXTENSION_RE = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|csv|jpg|jpeg|png|gif|zip|rar|mp3|mp4)\."
    r"(exe|scr|js|jar|hta|cmd|bat|vbs|ps1|com|pif|msi|apk|iso|img)$",
    re.I,
)

#: Suffixes commonly appended to an executable to defeat extension filters.
_DANGEROUS_SUFFIX_RE = re.compile(r"\.{2,}[a-z]{1,4}$", re.I)

_SCRIPTING_EXTENSIONS: frozenset[str] = frozenset(
    {".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1", ".psm1", ".sh"}
)


@dataclass
class FileAnalysisResult:
    """Structural findings plus the signals derived from them."""

    hashes: FileHashes
    content_type: FileTypeInfo
    declared_extension: str
    declared_mime: str | None
    entropy: float
    entropy_by_region: dict[str, float] = field(default_factory=dict)
    embedded_urls: list[str] = field(default_factory=list)
    embedded_domains: list[str] = field(default_factory=list)
    strings_of_interest: list[str] = field(default_factory=list)
    signals: list[DetectionSignal] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)

    @property
    def extension_mismatch(self) -> bool:
        return not extension_matches(self.content_type, self.declared_extension or None)

    def all_signals(self) -> list[DetectionSignal]:
        return list(self.signals)


def analyse_file(
    data: bytes,
    *,
    filename: str | None = None,
    declared_mime: str | None = None,
    source_path: Path | None = None,
    deep: bool = True,
) -> FileAnalysisResult:
    """Run the full structural analysis pass over a file's bytes."""
    hashes = hash_bytes(data)
    content_type = identify(data)
    declared_extension = _extract_extension(filename)
    entropy = normalised_entropy(data)

    result = FileAnalysisResult(
        hashes=hashes,
        content_type=content_type,
        declared_extension=declared_extension,
        declared_mime=declared_mime,
        entropy=entropy,
    )

    result.signals.extend(_analyse_extension_mismatch(result, filename))
    result.signals.extend(_analyse_double_extension(result, filename))
    result.signals.extend(_analyse_entropy(result))
    result.signals.extend(_analyse_declared_mime(result))
    result.signals.extend(_analyse_size(result))

    if deep:
        _extract_indicators(result, data)
        result.signals.extend(_analyse_embedded_urls(result))

        result.signals.extend(_dispatch_specialised_analyser(data, result, source_path))

    return result


#: Members that identify a ZIP package as a specific container format.
_CONTAINER_MARKERS: dict[str, FileKind] = {
    "androidmanifest.xml": FileKind.APK,
    "classes.dex": FileKind.APK,
    "word/document.xml": FileKind.DOCUMENT,
    "xl/workbook.xml": FileKind.DOCUMENT,
    "ppt/presentation.xml": FileKind.DOCUMENT,
    "mimetypeapplication/vnd.oasis.opendocument.text": FileKind.DOCUMENT,
}


def classify_container(data: bytes) -> FileKind | None:
    """Identify the specific format of a ZIP container by its member list.

    ZIP, APK, OOXML and ODF share one signature, so the container must be opened
    to be classified. Never extracts; only reads the central directory.
    """
    import io
    import zipfile

    if not data.startswith(b"PK"):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = {info.filename.lower() for info in archive.infolist()}
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
        return None

    # Order matters: the most specific format wins.
    for marker in ("androidmanifest.xml", "classes.dex"):
        if marker in names:
            return FileKind.APK
    for marker in ("word/document.xml", "xl/workbook.xml", "ppt/presentation.xml"):
        if marker in names:
            return FileKind.DOCUMENT
    for name in names:
        if name.startswith("mimetypeapplication/vnd.oasis.opendocument"):
            return FileKind.DOCUMENT
    return FileKind.ZIP


def _dispatch_specialised_analyser(
    data: bytes, result: "FileAnalysisResult", source_path: Path | None
) -> list[DetectionSignal]:
    """Route the file to the analyser that understands its format."""
    from app.detection_engine.file.archive_analyzer import analyse_archive
    from app.detection_engine.file.document_analyzer import analyse_document
    from app.detection_engine.file.image_analyzer import analyse_image

    kind = result.content_type.kind

    if kind in (FileKind.PDF, FileKind.DOCUMENT, FileKind.OLE2):
        return analyse_document(data, result, source_path)

    if kind is FileKind.IMAGE:
        return analyse_image(data, result)

    if kind in (FileKind.ZIP, FileKind.ARCHIVE):
        # A ZIP may actually be an APK or an OOXML package.
        container = classify_container(data)
        if container is FileKind.DOCUMENT:
            result.metadata["container_subtype"] = "ooxml"
            return analyse_document(data, result, source_path)
        if container is FileKind.APK:
            # APK gets a dedicated static analyser in the scan pipeline; here we
            # only report that the container is a package, never analyse code.
            result.metadata["container_subtype"] = "apk"
            return []
        return analyse_archive(data, result)

    if kind is FileKind.TEXT:
        # SVG is XML text and needs the image analyser's active-content checks.
        if _looks_like_svg(data):
            return analyse_image(data, result)
        return analyse_document(data, result, source_path)

    if kind is FileKind.BINARY:
        if _looks_like_svg(data):
            return analyse_image(data, result)

    return []


def _looks_like_svg(data: bytes) -> bool:
    """Cheap SVG sniffing: XML prologue or an <svg> root element."""
    head = data[:4096].lstrip().lower()
    return head.startswith(b"<?xml") or b"<svg" in head


# ---------------------------------------------------------------------------
# Filename and type checks
# ---------------------------------------------------------------------------
def _extract_extension(filename: str | None) -> str:
    if not filename or "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[1].lower()


def _analyse_extension_mismatch(result: FileAnalysisResult, filename: str | None) -> list[DetectionSignal]:
    """Cross-check the declared extension against the actual content."""
    if not filename or not result.declared_extension:
        return []
    if not result.extension_mismatch:
        return []

    content = result.content_type
    return [
        DetectionSignal(
            code="file.extension_mismatch",
            title="File extension does not match the file content",
            description=(
                f"The file is named '{truncate_for_display(filename, 120)}' but its content is "
                f"{content.label} ({content.description}). Content type is determined from the "
                "file's own signature, never from its name, so this mismatch indicates either a "
                "deliberate attempt to disguise the file or a corrupt download."
            ),
            severity=Severity.HIGH,
            category="structural",
            source=SignalSource.STRUCTURAL,
            confidence=0.8,
            evidence={
                "declared_extension": result.declared_extension,
                "detected_type": content.label,
                "detected_kind": content.kind.value,
                "detected_extensions": list(content.extensions[:5]),
            },
        )
    ]


def _analyse_double_extension(result: FileAnalysisResult, filename: str | None) -> list[DetectionSignal]:
    """Detect ``invoice.pdf.exe`` style lures."""
    if not filename:
        return []
    if _DOUBLE_EXTENSION_RE.search(filename):
        return [
            DetectionSignal(
                code="file.double_extension",
                title="Double file extension used to disguise the file type",
                description=(
                    f"The filename '{truncate_for_display(filename, 120)}' ends in a second "
                    "extension. This technique appends a trusted extension in front of a real "
                    "executable extension so the file appears to be a document or image."
                ),
                severity=Severity.HIGH,
                category="deception",
                source=SignalSource.STRUCTURAL,
                confidence=0.75,
                evidence={"filename": truncate_for_display(filename, 160)},
            )
        ]
    if _DANGEROUS_SUFFIX_RE.search(filename):
        return [
            DetectionSignal(
                code="file.trailing_dots",
                title="Filename ends in dots or a fake extension",
                description=(
                    "The filename contains a trailing sequence of dots followed by a short string. "
                    "Windows silently strips trailing dots, so the displayed name differs from the "
                    "stored name - a classic file-type disguise."
                ),
                severity=Severity.MEDIUM,
                category="deception",
                source=SignalSource.STRUCTURAL,
                confidence=0.7,
                evidence={"filename": truncate_for_display(filename, 160)},
            )
        ]
    return []


def _analyse_declared_mime(result: FileAnalysisResult) -> list[DetectionSignal]:
    """Compare the client-declared MIME type with the detected content."""
    declared = (result.declared_mime or "").split(";")[0].strip().lower()
    if not declared or declared == "application/octet-stream":
        return []

    detected_mime = result.content_type.mimetype
    if detected_mime == "image/*":
        if declared.startswith("image/"):
            return []
    elif declared == detected_mime:
        return []

    return [
        DetectionSignal(
            code="file.mime_mismatch",
            title="Declared content type does not match the file content",
            description=(
                f"The client declared '{declared}' but the file content is {result.content_type.label}. "
                "The declared type was supplied by the sender and is not trusted."
            ),
            severity=Severity.MEDIUM,
            category="structural",
            source=SignalSource.STRUCTURAL,
            confidence=0.6,
            evidence={"declared_mime": declared, "detected_mime": detected_mime},
        )
    ]


def _analyse_size(result: FileAnalysisResult) -> list[DetectionSignal]:
    """Flag sizes that are inconsistent with the detected type."""
    size = result.hashes.size_bytes
    content = result.content_type
    if size == 0:
        return [
            DetectionSignal(
                code="file.empty",
                title="File is empty",
                description="The uploaded file contains no data, so no content could be analysed.",
                severity=Severity.LOW,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.9,
                evidence={"size_bytes": 0},
            )
        ]

    # A tiny file claiming to be an image is usually a redirector or a stub.
    if content.kind is FileKind.IMAGE and size < 128:
        return [
            DetectionSignal(
                code="file.undersized_image",
                title="Image file is too small to contain a valid image",
                description=(
                    f"The file is only {size} bytes but carries an image signature. Truncated or "
                    "stub image files are used to slip past content filters."
                ),
                severity=Severity.MEDIUM,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.7,
                evidence={"size_bytes": size},
            )
        ]
    return []


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------
def _analyse_entropy(result: FileAnalysisResult) -> list[DetectionSignal]:
    """Flag uniformly high-entropy files that look packed or encrypted."""
    data_entropy = result.entropy
    content = result.content_type

    # High entropy is expected for compressed and media formats, so those kinds
    # are exempt from the packing heuristic.
    if content.kind in (FileKind.ARCHIVE, FileKind.IMAGE, FileKind.ZIP, FileKind.BINARY):
        return []

    if data_entropy >= 0.94 and result.hashes.size_bytes >= 2048:
        return [
            DetectionSignal(
                code="file.high_entropy",
                title="File content has near-maximum entropy",
                description=(
                    f"The file scores {data_entropy:.2f} on a 0-1 entropy scale, which is close to "
                    "the theoretical maximum for compressed or encrypted data. For this file type "
                    "that may indicate packing, encryption or an embedded archive. It is a weak "
                    "indicator on its own."
                ),
                severity=Severity.MEDIUM,
                category="obfuscation",
                source=SignalSource.HEURISTIC,
                confidence=0.45,
                evidence={
                    "normalised_entropy": round(data_entropy, 4),
                    "bits_per_byte": round(data_entropy * 8, 3),
                    "size_bytes": result.hashes.size_bytes,
                    "detected_type": content.label,
                },
            )
        ]
    return []


def _entropy_profile(data: bytes) -> dict[str, float]:
    """Entropy of fixed-size windows, to localise packed regions."""
    window = 4096
    profile: dict[str, float] = {}
    if len(data) < window * 2:
        return profile
    regions = min(8, len(data) // window)
    step = max(1, (len(data) // regions) // window)
    for index in range(regions):
        start = index * step * window
        chunk = data[start : start + window]
        if len(chunk) < window:
            break
        profile[f"0x{start:08x}"] = round(normalised_entropy(chunk), 4)
    return profile


# ---------------------------------------------------------------------------
# Indicator extraction
# ---------------------------------------------------------------------------
#: Strings worth reporting when found inside a document or binary.
_INTERESTING_STRING_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("powershell_command", re.compile(r"powershell(?:\.exe)?\s+-[a-z]{1,3}\b", re.I)),
    ("wscript_shell", re.compile(r"wscript\.shell", re.I)),
    ("cmd_osc", re.compile(r"cmd(?:\.exe)?\s*/c\b", re.I)),
    ("mshta", re.compile(r"mshta(?:\.exe)?\b", re.I)),
    ("scripting_filesystemobject", re.compile(r"Scripting\.FileSystemObject", re.I)),
    ("adodb_stream", re.compile(r"ADODB\.Stream", re.I)),
    ("shell_application", re.compile(r"Shell\.Application", re.I)),
    ("environment_getenv", re.compile(r"Environ\([\"']?COMSPEC", re.I)),
    ("rundll32", re.compile(r"rundll32(?:\.exe)?\b", re.I)),
    ("regsvr32", re.compile(r"regsvr32(?:\.exe)?\s+/[sc]", re.I)),
    ("certutil_decode", re.compile(r"certutil(?:\.exe)?\s+-decode", re.I)),
    ("bitsadmin", re.compile(r"bitsadmin(?:\.exe)?\b", re.I)),
    ("curl_download", re.compile(r"\bcurl\s+[^\n]{0,80}https?://", re.I)),
    ("wget_download", re.compile(r"\bwget\s+[^\n]{0,80}https?://", re.I)),
    ("base64_blob", re.compile(r"\b[A-Za-z0-9+/]{300,}={0,2}\b")),
)

#: Substrings searched in printable runs (binary files only).
_BINARY_INTEREST_SUBSTRINGS: tuple[tuple[str, bytes], ...] = (
    ("cmd.exe", b"cmd.exe"),
    ("powershell", b"powershell"),
    ("http_url", b"http://"),
    ("https_url", b"https://"),
    ("javascript_scheme", b"javascript:"),
    ("vbscript_scheme", b"vbscript:"),
    ("auto_open", b"AutoOpen"),
    ("auto_exec", b"AutoExec"),
    ("shell_execute", b"ShellExecute"),
    ("create_object", b"CreateObject"),
    ("WScript.Shell", b"WScript.Shell"),
    ("kernel32", b"kernel32"),
    ("LoadLibrary", b"LoadLibrary"),
    ("VirtualAlloc", b"VirtualAlloc"),
    ("WriteProcessMemory", b"WriteProcessMemory"),
    ("CreateRemoteThread", b"CreateRemoteThread"),
)

_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{6,}")


def _extract_indicators(result: FileAnalysisResult, data: bytes) -> None:
    """Pull URLs, domains and notable strings out of the raw bytes."""
    sample = data[:4 * 1024 * 1024]

    result.entropy_by_region = _entropy_profile(data)

    urls = extract_urls(sample.decode("latin-1", errors="ignore"), limit=200)
    # The regexes above operate on decoded text; filter out obvious false
    # positives from binary noise by requiring a plausible host.
    urls = [url for url in urls if _plausible_url(url)]
    result.embedded_urls = urls

    from app.detection_engine.text import extract_domains

    text = sample.decode("latin-1", errors="ignore")
    result.embedded_domains = extract_domains(" ".join(urls), limit=100)

    findings: list[str] = []
    for name, pattern in _INTERESTING_STRING_PATTERNS:
        if pattern.search(text):
            findings.append(name)

    for name, needle in _BINARY_INTEREST_SUBSTRINGS:
        if needle.lower() in sample.lower():
            findings.append(name)

    result.strings_of_interest = sorted(set(findings))


def _plausible_url(url: str) -> bool:
    from app.detection_engine.url.parser import parse_url

    try:
        parsed = parse_url(url)
    except Exception:  # pragma: no cover - parser is defensive already
        return False
    return bool(parsed.hostname and "." in parsed.hostname)


def _analyse_embedded_urls(result: FileAnalysisResult) -> list[DetectionSignal]:
    """Flag embedded URLs that point at scripting schemes or credential endpoints."""
    if not result.embedded_urls:
        return []

    dangerous = [
        url
        for url in result.embedded_urls
        if url.lower().startswith(("javascript:", "vbscript:", "data:text/html"))
    ]
    if dangerous:
        return [
            DetectionSignal(
                code="file.active_url_scheme",
                title="File contains active-content URLs",
                description=(
                    "The file embeds URLs using javascript: or vbscript: schemes, which execute "
                    "code when the link is followed rather than loading a remote resource. These "
                    "are used to bypass URL filters."
                ),
                severity=Severity.HIGH,
                category="deception",
                source=SignalSource.HEURISTIC,
                confidence=0.75,
                evidence={"count": len(dangerous), "examples": [truncate_for_display(u, 120) for u in dangerous[:5]]},
                indicators=tuple(
                    Indicator(type=IndicatorType.SUSPICIOUS_TOKEN, value=truncate_for_display(u, 200))
                    for u in dangerous[:10]
                ),
            )
        ]
    return []