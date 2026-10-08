"""Static analysis of documents (PDF, OOXML, OLE2, RTF).

All analysis is static and read-only:

* PDF structure is inspected with regex and byte scanning only. The document is
  never rendered, so no JavaScript, font parser or image codec is ever invoked.
* OOXML files are opened as ZIP containers and individual members are read into
  memory under a strict size cap. Nothing is extracted to disk, so archive-path
  traversal is structurally impossible.
* OLE2 files are scanned for macro streams and auto-execute triggers without
  being parsed by an OLE library.

Automation abuse (macros, auto-actions, DDE, embedded executables) is treated as
*high* risk rather than *proof* of maliciousness, because legitimate enterprise
documents legitimately use macros and external links.
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import TYPE_CHECKING

from app.detection_engine.file.analyzer_types import FileKind
from app.detection_engine.text import extract_urls, truncate_for_display
from app.schemas.common import IndicatorType, Severity, SignalSource
from app.schemas.signal import DetectionSignal, Indicator

if TYPE_CHECKING:  # pragma: no cover
    from app.detection_engine.file.analyzer import FileAnalysisResult

#: Never read more than this from a single compressed member (zip-bomb guard).
_MAX_MEMBER_BYTES = 8 * 1024 * 1024
#: Never inspect more than this many entries (entry-flood guard).
_MAX_ENTRIES = 5000

# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
#: PDF constructs that execute or exfiltrate when a document is opened.
_PDF_DANGEROUS_KEYS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("javascript_action", re.compile(rb"/JavaScript\b")),
    ("javascript_script", re.compile(rb"/JS\b")),
    ("open_action", re.compile(rb"/OpenAction\b")),
    ("additional_actions", re.compile(rb"/AA\b")),
    ("launch_action", re.compile(rb"/Launch\b")),
    ("embedded_file", re.compile(rb"/EmbeddedFile\b")),
    ("rich_media", re.compile(rb"/RichMedia\b")),
    ("xfa_form", re.compile(rb"/XFA\b")),
    ("submit_form", re.compile(rb"/SubmitForm\b")),
    ("import_data", re.compile(rb"/ImportData\b")),
    ("go_to_remote", re.compile(rb"/GoToR\b")),
    ("uri_action", re.compile(rb"/URI\b")),
    ("javascript_name", re.compile(rb"/JavaScript\b")),
    ("acro_form", re.compile(rb"/AcroForm\b")),
    ("encrypt", re.compile(rb"/Encrypt\b")),
    ("uri", re.compile(rb"/URI\s*\(([^)]{0,512})\)")),
)

_PDF_OBJECT_KEY_RE = re.compile(rb"/([A-Za-z#][A-Za-z0-9#]{0,40})\b")

_PDF_URL_RE = re.compile(rb"/URI\s*\(([^)\s]{4,2048})\)")

#: Names of embedded file streams, which reveal what the PDF carries.
_PDF_EMBEDDED_NAME_RE = re.compile(rb"/F(?:ilespec)?\s*\(([^)]{1,255})\)")

# ---------------------------------------------------------------------------
# OOXML
# ---------------------------------------------------------------------------
_VBA_MARKERS: tuple[bytes, ...] = (
    b"vbaProject.bin",
    b"word/vbaProject.bin",
    b"xl/vbaProject.bin",
    b"word/_rels/vbaProject.bin.rels",
)

_XLM_MACRO_RE = re.compile(rb"macrosheets?/.*\.bin", re.I)
_EXTERNAL_LINK_RE = re.compile(rb"externalLinks?/.*\.xml", re.I)
_EMBEDDING_RE = re.compile(rb"word/embeddings/|^embeddings/", re.I)
_ACTIVE_X_RE = re.compile(rb"(activeX|ctrlProps)/", re.I)
_OOXML_REL_RE = re.compile(rb'Target="([^"]{1,512})"', re.I)

#: Relationship types that cause external data to be resolved or executed.
_DANGEROUS_REL_TYPES: tuple[bytes, ...] = (
    b"oleObject",
    b"package",
    b"externalLink",
    b"attachedTemplate",
    b"frame",
    b"subDocument",
    b"vbaProject",
)

#: DDE field codes and command switches abused for code execution.
_DDE_PATTERN_RE = re.compile(
    rb"(?:DDE|DDEAUTO)\b[^\n]{0,200}?(?:cmd\s*\|'?/?c|powershell|mshta|wscript|cscript|excel\.exe|word\.exe)",
    re.I,
)

# ---------------------------------------------------------------------------
# RTF
# ---------------------------------------------------------------------------
_RTF_CONTROL_RE = re.compile(
    rb"\\object|\\objemb|\\objautlink|\\objlink|\\pict|\\datastore|\\jscript|\\vbscript|\\msdatauri",
    re.I,
)

_RTF_URL_RE = re.compile(rb"https?://[^\s\\'\"<>]{4,512}", re.I)


def analyse_document(
    data: bytes,
    result: "FileAnalysisResult",
    source_path=None,
) -> list[DetectionSignal]:
    """Dispatch to the format-specific document analyser."""
    kind = result.content_type.kind
    if kind is FileKind.PDF:
        return analyse_pdf(data, result)
    if kind is FileKind.OLE2:
        return analyse_ole2(data, result)
    if kind is FileKind.ZIP:
        return analyse_ooxml(data, result)
    if kind is FileKind.TEXT:
        return analyse_text_document(data, result)
    if kind is FileKind.DOCUMENT:
        return _analyse_rtf(data, result)
    return []


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
def analyse_pdf(data: bytes, result: "FileAnalysisResult") -> list[DetectionSignal]:
    """Detect active content and exfiltration primitives in a PDF."""
    signals: list[DetectionSignal] = []
    # PDF structure lives throughout the file; scan widely but bound the cost.
    sample = data[:16 * 1024 * 1024]
    keys = {name for name, pattern in _PDF_DANGEROUS_KEYS if pattern.search(sample)}

    js_present = {"javascript_action", "javascript_script"} & keys
    auto_execute = bool(js_present and ("open_action" in keys or "additional_actions" in keys))

    if js_present:
        severity = Severity.CRITICAL if auto_execute else Severity.HIGH
        description = (
            "The PDF contains JavaScript actions"
            + (" that execute automatically when the document is opened, without any user action."
               if auto_execute
               else ". These actions can perform actions such as opening network connections.")
            + " Malicious PDFs use this to run code or redirect the reader."
        )
        signals.append(
            DetectionSignal(
                code="pdf.javascript",
                title="PDF contains embedded JavaScript",
                description=description,
                severity=severity,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.85 if auto_execute else 0.7,
                weight=0.75 if auto_execute else 0.45,
                evidence={
                    "constructs": sorted(js_present),
                    "auto_execute": auto_execute,
                    "open_action": "open_action" in keys,
                    "additional_actions": "additional_actions" in keys,
                },
            )
        )

    if "launch_action" in keys:
        signals.append(
            DetectionSignal(
                code="pdf.launch_action",
                title="PDF can launch an external application",
                description=(
                    "The document contains a Launch action that can start another program. This is "
                    "used to open executables or scripts directly from a PDF."
                ),
                severity=Severity.HIGH,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.8,
                evidence={"construct": "Launch"},
            )
        )

    if "embedded_file" in keys or "rich_media" in keys:
        embedded_names = [
            name.decode("latin-1", errors="ignore")
            for name in _PDF_EMBEDDED_NAME_RE.findall(sample)[:10]
        ]
        signals.append(
            DetectionSignal(
                code="pdf.embedded_payload",
                title="PDF carries an embedded file or media object",
                description=(
                    "The document contains an attached file or a Rich Media object. Embedded "
                    "payloads are used to hide executables inside an apparently normal document "
                    "and can also contain macros."
                ),
                severity=Severity.HIGH,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.75,
                evidence={"constructs": sorted(keys & {"embedded_file", "rich_media"}),
                          "embedded_names": embedded_names},
            )
        )

    if "xfa_form" in keys:
        signals.append(
            DetectionSignal(
                code="pdf.xfa_form",
                title="PDF uses an XFA form",
                description=(
                    "The document contains an XFA (XML Forms Architecture) form. XFA forms can "
                    "execute script, submit data to a remote server and are widely used in "
                    "credential-harvesting PDFs because they bypass standard form validation."
                ),
                severity=Severity.HIGH,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.8,
                evidence={"construct": "XFA", "acro_form": "acro_form" in keys},
            )
        )

    if "submit_form" in keys and "acro_form" in keys:
        signals.append(
            DetectionSignal(
                code="pdf.form_submission",
                title="PDF form submits data to an external destination",
                description=(
                    "The interactive form is configured to submit its contents to an external "
                    "URL. Combined with a request for personal or banking details this is the "
                    "standard structure of a phishing PDF."
                ),
                severity=Severity.HIGH,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.75,
                evidence={"constructs": ["SubmitForm", "AcroForm"]},
            )
        )

    if "encrypt" in keys:
        signals.append(
            DetectionSignal(
                code="pdf.encrypted",
                title="PDF is password protected",
                description=(
                    "The document declares an encryption dictionary. Encrypted PDFs prevent "
                    "content inspection by gateways and are sometimes used to conceal payloads."
                ),
                severity=Severity.LOW,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.5,
                evidence={"construct": "Encrypt"},
            )
        )

    pdf_urls = _extract_pdf_urls(sample)
    if pdf_urls:
        result.embedded_urls.extend(pdf_urls)
        signals.extend(_pdf_url_signals(pdf_urls))

    return signals


def _extract_pdf_urls(data: bytes) -> list[str]:
    urls: list[str] = []
    for match in _PDF_URL_RE.findall(data[:8 * 1024 * 1024]):
        candidate = match.decode("latin-1", errors="ignore").strip()
        if candidate and candidate not in urls:
            urls.append(candidate)
        if len(urls) >= 50:
            break
    return urls


def _pdf_url_signals(urls: list[str]) -> list[DetectionSignal]:
    """Evaluate URLs referenced by PDF actions."""
    from app.detection_engine.url.parser import parse_url

    active = [url for url in urls if url.lower().startswith(("javascript:", "data:", "file:"))]
    if active:
        return [
            DetectionSignal(
                code="pdf.active_url",
                title="PDF links to active content",
                description=(
                    "The PDF contains links using javascript:, data: or file: schemes, which can "
                    "execute code or load local resources when clicked."
                ),
                severity=Severity.HIGH,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.8,
                evidence={"schemes": sorted({url.split(":", 1)[0] for url in active}),
                          "count": len(active)},
            )
        ]

    ip_hosts = [url for url in urls if parse_url(url).is_ip_literal]
    if ip_hosts:
        return [
            DetectionSignal(
                code="pdf.uri_to_ip_address",
                title="PDF action targets a raw IP address",
                description=(
                    "The document's embedded links point at a bare IP address rather than a "
                    "domain name. Attackers use direct IP links because the address cannot be "
                    "taken down and is not subject to domain reputation."
                ),
                severity=Severity.MEDIUM,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.65,
                evidence={"count": len(ip_hosts),
                          "examples": [truncate_for_display(url, 120) for url in ip_hosts[:5]]},
                indicators=tuple(
                    Indicator(type=IndicatorType.IP_ADDRESS, value=parse_url(url).effective_host)
                    for url in ip_hosts[:10]
                ),
            )
        ]
    return []


# ---------------------------------------------------------------------------
# OOXML (DOCX / XLSX / PPTX) and ODF
# ---------------------------------------------------------------------------
def analyse_ooxml(data: bytes, result: "FileAnalysisResult") -> list[DetectionSignal]:
    """Inspect an OOXML/ODF package without extracting it to disk."""
    signals: list[DetectionSignal] = []

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError):
        return [
            DetectionSignal(
                code="document.corrupt_container",
                title="Document container could not be opened",
                description=(
                    "The file carries a ZIP signature but its central directory is unreadable. "
                    "A truncated or deliberately corrupted container may be an attempt to evade "
                    "inspection by automated tools."
                ),
                severity=Severity.MEDIUM,
                category="structural",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.6,
                evidence={"zip_error": True},
            )
        ]

    if len(infos) > _MAX_ENTRIES:
        return [
            DetectionSignal(
                code="document.entry_flood",
                title="Document contains an abnormal number of entries",
                description=(
                    f"The container declares {len(infos)} entries, exceeding the inspection limit "
                    "of "
                    f"{_MAX_ENTRIES}. This entry-flood technique is used to exhaust analysis tools."
                ),
                severity=Severity.MEDIUM,
                category="obfuscation",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.7,
                evidence={"entry_count": len(infos), "limit": _MAX_ENTRIES},
            )
        ]

    names = [info.filename for info in infos]
    result.metadata["entry_count"] = len(infos)
    result.metadata["total_uncompressed_bytes"] = sum(info.file_size for info in infos)

    # -- Macros ------------------------------------------------------
    vba_entries = [
        name
        for name in names
        if any(marker.decode("latin-1") in name for marker in _VBA_MARKERS)
    ]
    xlm_entries = [name for name in names if _XLM_MACRO_RE.search(name.encode("latin-1", "ignore"))]

    if vba_entries or xlm_entries:
        signals.append(
            DetectionSignal(
                code="document.vba_macro",
                title="Document contains executable macros",
                description=(
                    "This Office document contains a VBA project"
                    + (" (XLM macro sheets)" if xlm_entries else "")
                    + ". Macros can run arbitrary code with the user's privileges when the "
                    "document is opened, and are the most common initial-execution vector in "
                    "document-based malware. Not all macro use is malicious, but it requires "
                    "review."
                ),
                severity=Severity.HIGH,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.85,
                weight=0.6,
                evidence={
                    "vba_entries": vba_entries[:5],
                    "xlm_macro_entries": xlm_entries[:5],
                    "macro_type": "vba" if vba_entries else "xlm",
                },
            )
        )

    # -- External links ----------------------------------------------
    external_link_entries = [
        name for name in names if _EXTERNAL_LINK_RE.search(name.encode("latin-1", "ignore"))
    ]
    external_targets = _collect_external_targets(data, names)
    if external_link_entries or external_targets:
        signals.append(
            DetectionSignal(
                code="document.external_links",
                title="Document references external data sources",
                description=(
                    "The document links to external workbooks or web resources. External links "
                    "are a data-exfiltration channel and a common way to pull attacker-supplied "
                    "formulas or content into a trusted document."
                ),
                severity=Severity.MEDIUM,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.65,
                evidence={
                    "external_link_parts": external_link_entries[:5],
                    "external_targets": external_targets[:10],
                },
            )
        )

    # -- Embedded objects --------------------------------------------
    embedded = [name for name in names if _EMBEDDING_RE.search(name.encode("latin-1", "ignore"))]
    if embedded:
        signals.append(
            DetectionSignal(
                code="document.embedded_objects",
                title="Document embeds external objects",
                description=(
                    "The document contains embedded OLE objects or packages. Embedded objects "
                    "can carry executables or macro-enabled documents that are invisible in the "
                    "normal view of the file."
                ),
                severity=Severity.MEDIUM,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.7,
                evidence={"count": len(embedded), "examples": embedded[:5]},
            )
        )

    # -- ActiveX ------------------------------------------------------
    activex = [name for name in names if _ACTIVE_X_RE.search(name.encode("latin-1", "ignore"))]
    if activex:
        signals.append(
            DetectionSignal(
                code="document.activex_control",
                title="Document contains ActiveX controls",
                description=(
                    "ActiveX controls execute native code and are a direct code-execution path "
                    "from a document. Their presence in an unsolicited document is a strong "
                    "indicator of a weaponised attachment."
                ),
                severity=Severity.HIGH,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.75,
                evidence={"parts": activex[:5]},
            )
        )

    # -- DDE ----------------------------------------------------------
    dde_hits = _scan_dde(data, names)
    if dde_hits:
        signals.append(
            DetectionSignal(
                code="document.dde_execution",
                title="Document contains Dynamic Data Exchange commands",
                description=(
                    "The document contains DDE or DDEAUTO field codes that execute a command on "
                    "the host. DDE is one of the oldest and most reliable code-execution chains "
                    "in Office documents and requires no macros."
                ),
                severity=Severity.CRITICAL,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.8,
                weight=0.7,
                evidence={"matches": dde_hits[:5]},
            )
        )

    # -- Relationship review ----------------------------------------
    signals.extend(_analyse_relationships(data, names))

    return signals


def _collect_external_targets(data: bytes, names: list[str]) -> list[str]:
    """Read relationship parts and return external targets."""
    targets: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in names:
                if not name.endswith(".rels") and "externalLink" not in name:
                    continue
                if not name.endswith((".xml", ".rels")):
                    continue
                try:
                    content = _read_member(archive, name)
                except (KeyError, RuntimeError, zipfile.BadZipFile, OSError):
                    continue
                for match in _OOXML_REL_RE.findall(content or b""):
                    value = match.decode("utf-8", errors="ignore").strip()
                    if value.startswith(("http://", "https://", "file://", "\\\\")) and value not in targets:
                        targets.append(value)
                    if len(targets) >= 40:
                        return targets
    except (zipfile.BadZipFile, OSError):
        return targets
    return targets


def _scan_dde(data: bytes, names: list[str]) -> list[str]:
    """Search document parts for DDE field codes."""
    hits: list[str] = []
    candidates = [name for name in names if name.endswith((".xml", ".bin", ".txt"))]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in candidates[:60]:
                try:
                    content = _read_member(archive, name)
                except (KeyError, RuntimeError, zipfile.BadZipFile, OSError):
                    continue
                for match in _DDE_PATTERN_RE.finditer(content or b""):
                    hits.append(f"{name}: {match.group(0)[:120].decode('latin-1', errors='ignore')}")
                    if len(hits) >= 5:
                        return hits
    except (zipfile.BadZipFile, OSError):
        pass

    for match in _DDE_PATTERN_RE.finditer(data[:4 * 1024 * 1024]):
        hits.append(match.group(0)[:120].decode("latin-1", errors="ignore"))
        if len(hits) >= 5:
            break
    return hits


def _analyse_relationships(data: bytes, names: list[str]) -> list[DetectionSignal]:
    """Flag dangerous relationship types in the OOXML package."""
    dangerous: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in names:
                if not name.endswith(".rels"):
                    continue
                try:
                    content = _read_member(archive, name)
                except (KeyError, RuntimeError, zipfile.BadZipFile, OSError):
                    continue
                lowered = (content or b"").lower()
                for marker in _DANGEROUS_REL_TYPES:
                    if marker.lower() in lowered:
                        dangerous.append(f"{name}:{marker.decode()}")
                if len(dangerous) >= 20:
                    break
    except (zipfile.BadZipFile, OSError):
        return []

    if not dangerous:
        return []
    return [
        DetectionSignal(
            code="document.dangerous_relationship",
            title="Document declares high-risk relationships",
            description=(
                "The package contains relationships of types that load or execute external "
                "content (OLE objects, attached templates, packages, macros). These are the "
                "document-level equivalents of execution primitives."
            ),
            severity=Severity.MEDIUM,
            category="static_analysis",
            source=SignalSource.STATIC_ANALYSIS,
            confidence=0.6,
            evidence={"relationships": dangerous[:15]},
        )
    ]


def _read_member(archive: zipfile.ZipFile, name: str) -> bytes | None:
    """Read a single member under strict limits.

    Raises ``RuntimeError`` when the member declares a size beyond the cap, which
    is how zip bombs are refused without decompressing them.
    """
    info = archive.getinfo(name)
    if info.file_size > _MAX_MEMBER_BYTES:
        raise RuntimeError(f"member {name} exceeds the { _MAX_MEMBER_BYTES } byte inspection limit")
    with archive.open(info) as handle:
        return handle.read(_MAX_MEMBER_BYTES)


# ---------------------------------------------------------------------------
# OLE2 (legacy Office, Outlook .msg)
# ---------------------------------------------------------------------------
_OLE_MACRO_MARKERS: tuple[bytes, ...] = (
    b"VBA\x00",
    b"_VBA_PROJECT",
    b"\x01CompObj",
    b"Macros",
    b"AutoOpen",
    b"AutoClose",
    b"Document_Open",
    b"Workbook_Open",
    b"ThisWorkbook",
    b"Shell(",
)

_OLE_AUTOEXEC_RE = re.compile(
    rb"(?:Auto(?:Open|Close|Exec)|Document_Open|Workbook_Open|Auto_Open)\b", re.I
)


def analyse_ole2(data: bytes, result: "FileAnalysisResult") -> list[DetectionSignal]:
    """Detect macro presence and auto-execution in OLE2 compound files."""
    signals: list[DetectionSignal] = []
    sample = data[:16 * 1024 * 1024]

    markers = sorted({marker.decode("latin-1", "ignore") for marker in _OLE_MACRO_MARKERS if marker in sample})
    autoexec = sorted(
        {m.group(0).decode("latin-1", errors="ignore") for m in _OLE_AUTOEXEC_RE.finditer(sample)}
    )

    has_vba = b"_VBA_PROJECT" in sample or b"VBA\x00" in sample
    if has_vba or "Macros" in markers:
        signals.append(
            DetectionSignal(
                code="document.ole_macro",
                title="Office document contains a VBA project",
                description=(
                    "This legacy Office document contains a Visual Basic for Applications project. "
                    "VBA macros execute with the user's privileges when the document is opened, "
                    "which makes them a primary malware delivery mechanism."
                ),
                severity=Severity.HIGH,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.8,
                weight=0.6,
                evidence={"markers": markers[:10], "auto_execute_triggers": autoexec[:5]},
            )
        )

    if autoexec:
        signals.append(
            DetectionSignal(
                code="document.auto_execute_macro",
                title="Document defines an automatic macro trigger",
                description=(
                    "The document defines macros that run automatically when the file is opened or "
                    "closed ("
                    + ", ".join(autoexec[:4])
                    + "). Legitimate documents rarely need automatic execution; this pattern is "
                    "characteristic of malicious attachments."
                ),
                severity=Severity.CRITICAL,
                category="static_analysis",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.8,
                weight=0.7,
                evidence={"triggers": autoexec[:8]},
            )
        )

    urls = _extract_rtf_or_binary_urls(sample)
    if urls:
        result.embedded_urls.extend(urls)
        signals.extend(_pdf_url_signals(urls))

    return signals


# ---------------------------------------------------------------------------
# RTF
# ---------------------------------------------------------------------------
def _analyse_rtf(data: bytes, result: "FileAnalysisResult") -> list[DetectionSignal]:
    sample = data[:4 * 1024 * 1024]
    controls = sorted(
        {m.group(0).decode("latin-1", "ignore") for m in _RTF_CONTROL_RE.finditer(sample)}
    )
    urls = [
        m.decode("latin-1", errors="ignore")
        for m in _RTF_URL_RE.findall(sample)[:50]
    ]
    if urls:
        result.embedded_urls.extend(urls)

    if not controls:
        return []

    executable_controls = [c for c in controls if c in ("\\object", "\\objemb", "\\objautlink", "\\objlink", "\\jscript", "\\vbscript")]
    return [
        DetectionSignal(
            code="document.rtf_objects",
            title="RTF document contains embedded objects or scripts",
            description=(
                "The RTF file uses object and scripting control words ("
                + ", ".join((executable_controls or controls)[:5])
                + "). RTF objects can embed executables and documents, and RTF is commonly used "
                "to disguise a payload as plain text."
            ),
            severity=Severity.HIGH if executable_controls else Severity.MEDIUM,
            category="static_analysis",
            source=SignalSource.STATIC_ANALYSIS,
            confidence=0.7,
            evidence={"control_words": controls[:10]},
        )
    ]


def _extract_rtf_or_binary_urls(data: bytes) -> list[str]:
    urls: list[str] = []
    for match in _RTF_URL_RE.findall(data[:4 * 1024 * 1024]):
        candidate = match.decode("latin-1", errors="ignore").strip()
        if candidate and candidate not in urls:
            urls.append(candidate)
        if len(urls) >= 50:
            break
    return urls


# ---------------------------------------------------------------------------
# Plain text documents
# ---------------------------------------------------------------------------
def analyse_text_document(data: bytes, result: "FileAnalysisResult") -> list[DetectionSignal]:
    """Run text files through the phishing content analyser."""
    from app.detection_engine.phishing.heuristics import analyse_text_content

    try:
        text = data[:1 * 1024 * 1024].decode("utf-8", errors="ignore")
    except Exception:  # pragma: no cover - decode with errors never raises
        return []

    signals = analyse_text_content(text)
    if signals:
        result.metadata["text_analysed"] = True
    return signals