"""Microsoft Office document analysis (OOXML and legacy OLE2 formats).

Two generations of format are handled:

* **OOXML** (``.docx``/``.xlsx``/``.pptx``) - a ZIP of XML parts.  Analysed by
  reading the XML with ``defusedxml`` (never a bare parser: XXE and billion-laughs
  are real risks in attacker-supplied documents) and walking the relationships.
* **Legacy OLE2** (``.doc``/``.xls``/``.ppt``/``.msg``) - a compound binary file.
  We look for the ``Macros``/``VBA`` streams and the ``WordDocument`` markers
  without using a full parser.

Nothing is ever executed or opened in a viewer.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field

from ..constants import SUSPICIOUS_OFFICE_RELATIONSHIPS, SUSPICIOUS_EMBED_TOKENS
from ..models import Finding, Severity, SignalSource

__all__ = ["OfficeReport", "analyze_office", "analyze_ooxml", "analyze_ole2", "extract_urls"]

#: Strings that appear in VBA macro streams and in malicious macro templates.
MACRO_MARKERS = (
    b"AutoOpen",
    b"Document_Open",
    b"AutoClose",
    b"Workbook_Open",
    b"Auto_Open",
    b"Shell(",
    b"CreateObject",
    b"GetObject",
    b"WScript.Shell",
    b"powershell",
    b"cmd.exe",
    b"URLDownloadToFile",
    b"XMLHTTP",
    b"ADODB.Stream",
    b"Chr(",
    b"Environ(",
    b"Declare PtrSafe",
    b"VBProject",
    b"Application.OnTime",
    b"Sleep",
)

#: DDE-style field codes used to launch other applications on open.
DDE_MARKERS = (b"DDEAUTO", b"DDE ", b"ddeauto", b"\\dde")

_URL_RE = re.compile(
    rb"(?:https?://|ftp://|\\\\)[^\s<>\"'\)\]\x00]{4,300}", re.IGNORECASE
)
_META_RE = re.compile(rb"<meta[^>]+>", re.IGNORECASE)
_HREF_RE = re.compile(rb'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

#: Parts that must exist for a well-formed OOXML package.
_REQUIRED_PARTS = ("[Content_Types].xml",)


@dataclass(slots=True)
class OfficeReport:
    """Findings and metadata extracted from an Office document."""

    format: str = ""
    parts: list[str] = field(default_factory=list)
    external_relationships: list[dict[str, str]] = field(default_factory=list)
    external_objects: list[str] = field(default_factory=list)
    embedded_objects: list[str] = field(default_factory=list)
    macro_present: bool = False
    macro_markers: list[str] = field(default_factory=list)
    dde_fields: list[str] = field(default_factory=list)
    active_content: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ole_streams: list[str] = field(default_factory=list)
    encrypted: bool = False
    core_properties: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    #: Human-visible text pulled out of the document body, for phishing analysis.
    text_parts: list[str] = field(default_factory=list)
    #: Total characters of extracted text.
    text_chars: int = 0

    @property
    def text(self) -> str:
        """Extracted document text, truncated to a sane analysis budget."""
        return "\n".join(self.text_parts)[:200_000]

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "parts": self.parts[:100],
            "external_relationships": self.external_relationships[:50],
            "embedded_objects": self.embedded_objects[:50],
            "macro_present": self.macro_present,
            "macro_markers": self.macro_markers[:30],
            "dde_fields": self.dde_fields[:20],
            "active_content": self.active_content[:30],
            "urls": self.urls[:100],
            "ole_streams": self.ole_streams[:50],
            "encrypted": self.encrypted,
            "core_properties": self.core_properties,
            "text_chars": self.text_chars,
            "errors": self.errors,
        }


def extract_urls(data: bytes, *, limit: int = 500) -> list[str]:
    """Pull URLs out of arbitrary bytes (also used for images and plain text)."""
    urls: list[str] = []
    seen: set[str] = set()
    for match in _URL_RE.findall(data):
        try:
            value = match.decode("utf-8", errors="replace").strip().rstrip(".,;:)\"'")
        except Exception:  # pragma: no cover - decode with replace never raises
            continue
        if len(value) < 8 or value in seen:
            continue
        seen.add(value)
        urls.append(value)
        if len(urls) >= limit:
            break
    return urls


def _safe_xml(data: bytes) -> str:
    """Parse XML with external entities and entity expansion disabled."""
    try:
        from defusedxml.ElementTree import fromstring
    except ImportError:  # pragma: no cover - defusedxml is a hard dependency
        return ""
    try:
        root = fromstring(data)
    except Exception:
        return ""
    try:
        return "".join(root.itertext())
    except Exception:  # pragma: no cover
        return ""


def analyze_office(data: bytes, *, filename: str = "") -> OfficeReport:
    """Analyse an Office document of either generation."""
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return analyze_ooxml(data, filename=filename)
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return analyze_ole2(data, filename=filename)
    report = OfficeReport()
    report.errors.append("Not a recognised Office container.")
    return report


def analyze_ooxml(data: bytes, *, filename: str = "") -> OfficeReport:
    """Analyse an OOXML (``.docx``/``.xlsx``/``.pptx``) package."""
    report = OfficeReport(format="ooxml")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        report.errors.append(f"Invalid OOXML package: {exc}")
        return report

    with archive:
        try:
            names = archive.namelist()
        except Exception as exc:  # pragma: no cover
            report.errors.append(str(exc))
            return report
        report.parts = names[:500]

        for required in _REQUIRED_PARTS:
            if required not in names:
                report.errors.append(f"Missing required OOXML part '{required}'.")
                break
        for name in names:
            if name.endswith(".bin") and ("vbaProject" in name or "activeX" in name):
                report.embedded_objects.append(name)
            if "vbaProject" in name:
                report.macro_present = True
            if "oleObject" in name or "embeddings/" in name:
                report.embedded_objects.append(name)
            if "externalLink" in name:
                report.external_objects.append(name)
            if "activeX" in name:
                report.active_content.append(name)
            if "customUI" in name:
                report.active_content.append(name)

        report.urls.extend(extract_urls(data))

        # Relationship parts point at external templates and OLE servers.
        for name in names:
            if not name.endswith(".rels"):
                continue
            try:
                xml = archive.read(name)
            except (RuntimeError, zipfile.BadZipFile, OSError):
                continue
            text = xml.decode("utf-8", errors="replace")
            for tag in re.finditer(
                r'<Relationship\b[^>]*>', text, re.IGNORECASE
            ):
                element = tag.group(0)
                mode = _attr(element, "TargetMode")
                target = _attr(element, "Target")
                rel_type = _attr(element, "Type", ).rsplit("/", 1)[-1]
                if not target:
                    continue
                if mode == "External" or target.lower().startswith(("http:", "https:", "file:", "\\\\")):
                    report.external_relationships.append(
                        {
                            "part": name,
                            "type": rel_type,
                            "target": target[:300],
                            "mode": mode or "External",
                        }
                    )
                if rel_type in SUSPICIOUS_OFFICE_RELATIONSHIPS:
                    report.embedded_objects.append(f"{rel_type}:{target[:120]}")

        # Document text, for phishing/social-engineering analysis.
        for name in names:
            if not name.startswith(("word/", "xl/", "ppt/")):
                continue
            if not name.endswith(".xml"):
                continue
            try:
                xml = archive.read(name)
            except (RuntimeError, zipfile.BadZipFile, OSError):
                continue
            lowered = xml
            if any(marker in lowered for marker in MACRO_MARKERS):
                report.macro_markers.append(f"macro pattern in {name}")
                report.macro_present = True
            if any(marker in lowered for marker in DDE_MARKERS):
                report.dde_fields.append(name)
            for token in SUSPICIOUS_EMBED_TOKENS:
                if token.encode() in lowered:
                    report.active_content.append(f"{token} in {name}")
                    break
            if name.endswith("document.xml") or name.endswith("sharedStrings.xml") or name.endswith(
                ("slide1.xml", "notesSlide1.xml")
            ):
                report.text_parts.append(_xml_text(xml))
                report.text_chars += len(report.text_parts[-1])

        report.core_properties = _read_core_properties(archive)

    # Deduplicate while preserving order.
    report.embedded_objects = list(dict.fromkeys(report.embedded_objects))
    report.active_content = list(dict.fromkeys(report.active_content))
    report.urls = list(dict.fromkeys(report.urls))
    report.external_objects = list(dict.fromkeys(report.external_objects))
    report.macro_markers = list(dict.fromkeys(report.macro_markers))
    return report


def analyze_ole2(data: bytes, *, filename: str = "") -> OfficeReport:
    """Analyse a legacy OLE2 compound document (``.doc``, ``.xls``, ``.msg``)."""
    report = OfficeReport(format="ole2")
    lowered = data.lower()

    for marker in MACRO_MARKERS:
        if marker.lower() in lowered:
            report.macro_markers.append(marker.decode("ascii", errors="replace"))
    report.macro_present = bool(report.macro_markers)

    # OLE directory entries store stream names as UTF-16LE.
    for stream_name in (
        "WordDocument", "Workbook", "PowerPoint Document", "VBA", "_VBA_PROJECT",
        "Macros", "Ctls", "ObjInfo", "SummaryInformation", "__substg1.0_0037001F",
    ):
        if stream_name.encode("utf-16-le") in data:
            report.ole_streams.append(stream_name)
    if b"VBA" in data or b"_VBA_PROJECT" in data:
        report.ole_streams.append("VBA")
    if report.macro_present or "VBA" in report.ole_streams:
        report.macro_present = True

    for marker in DDE_MARKERS:
        if marker in data:
            report.dde_fields.append(marker.decode("ascii", errors="replace"))

    if b"EncryptedPackage" in data or b"EncryptionInfo" in data:
        report.encrypted = True

    report.urls.extend(extract_urls(data))
    report.urls = list(dict.fromkeys(report.urls))

    summary = _read_ole_summary(data)
    report.core_properties.update(summary)
    return report


#: OOXML text runs live inside these elements.
_TEXT_TAGS = frozenset(
    {"w:t", "a:t", "t", "instrText", "v:textbox"}
)


def _xml_text(xml: bytes, *, limit: int = 400_000) -> str:
    """Extract human-visible text from an OOXML part.

    Only the run-text elements are collected.  Walking every node with
    ``itertext()`` would also pull in attribute names, style identifiers and
    relationship targets, which add noise to the social-engineering analysis.
    """
    if len(xml) > limit:
        xml = xml[:limit]
    try:
        from defusedxml.ElementTree import fromstring as _fromstring
    except ImportError:  # pragma: no cover - defusedxml is a hard dependency
        import xml.etree.ElementTree as _std  # noqa: S405 - fall back to stdlib

        try:
            root = _std.fromstring(xml)
        except Exception:
            return ""
    else:
        try:
            root = _fromstring(xml)
        except Exception:
            return ""

    pieces: list[str] = []
    for element in root.iter():
        tag = element.tag
        if not isinstance(tag, str):
            continue
        # Strip the namespace: OOXML uses '{ns}t' for 't'.
        local = tag.rsplit("}", 1)[-1].lower()
        if local not in _TEXT_TAGS:
            continue
        if element.text:
            pieces.append(element.text)
    return " ".join(pieces)


def _attr(element: str, name: str) -> str:
    match = re.search(rf'{name}\s*=\s*["\']([^"\']*)["\']', element, re.IGNORECASE)
    return match.group(1) if match else ""


def _read_core_properties(archive: zipfile.ZipFile) -> dict[str, str]:
    try:
        xml = archive.read("docProps/core.xml")
    except (KeyError, RuntimeError, zipfile.BadZipFile, OSError):
        return {}
    from defusedxml.ElementTree import fromstring

    try:
        root = fromstring(xml)
    except Exception:
        return {}
    properties: dict[str, str] = {}
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if element.text and tag in (
            "title", "subject", "creator", "keywords", "description",
            "lastModifiedBy", "category", "contentStatus", "revision",
        ):
            properties[tag] = element.text.strip()[:200]
    return properties


#: SummaryInformation property IDs worth surfacing.
_OLE_SUMMARY_FIELDS = {
    2: "title",
    3: "subject",
    4: "author",
    5: "keywords",
    6: "comments",
    7: "template",
    8: "last_saved_by",
    9: "revision_number",
    15: "create_time",
    16: "last_saved_time",
}


def _read_ole_summary(data: bytes) -> dict[str, str]:
    """Extract readable strings from an OLE SummaryInformation stream."""
    properties: dict[str, str] = {}
    # CP1252 and UTF-16 printable runs are good enough for author metadata.
    for match in re.finditer(rb"[\x20-\x7e]{6,120}", data):
        text = match.group(0).decode("ascii", errors="replace")
        if text.startswith(("SummaryInformation", "DocumentSummaryInformation")):
            continue
        if any(token in text for token in ("Microsoft Office", "Word.Document", "Excel.Sheet")):
            continue
        properties.setdefault("visible_strings", "")
        properties["visible_strings"] += ("," + text[:60])
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){4,60}", data):
        try:
            text = match.group(0).decode("utf-16-le", errors="replace")
        except Exception:  # pragma: no cover
            continue
        text = text.strip()
        if len(text) >= 4 and not text.isdigit():
            properties.setdefault("utf16_strings", "")
            properties["utf16_strings"] += ("," + text[:60])
    for key in ("visible_strings", "utf16_strings"):
        if key in properties:
            properties[key] = properties[key].strip(",")[:600]
    return properties


def office_findings(report: OfficeReport, *, filename: str = "") -> list[Finding]:
    """Findings derived from an :class:`OfficeReport`."""
    findings: list[Finding] = []

    if report.macro_present:
        findings.append(
            Finding(
                code="OFFICE.MACRO_PRESENT",
                title="Document contains macros",
                detail=(
                    "This document embeds a VBA project. Macros are the single most "
                    "common way malicious Office files execute code on a victim's "
                    "machine, and they are invisible without enabling content. "
                    + (
                        f"Patterns found: {', '.join(sorted(set(report.macro_markers))[:6])}."
                        if report.macro_markers
                        else ""
                    )
                ),
                severity=Severity.HIGH,
                source=SignalSource.OFFICE_DOCUMENT,
                category="payload",
                weight=24.0,
                authoritative=True,
                evidence={"markers": sorted(set(report.macro_markers))[:30]},
            )
        )

    dangerous_rels = [
        rel for rel in report.external_relationships
        if rel["type"] in ("attachedTemplate", "oleObject", "package", "externalLink", "frame")
        or rel["target"].lower().startswith(("http:", "https:", "file:", "\\\\"))
    ]
    if dangerous_rels:
        targets = [rel["target"] for rel in dangerous_rels[:5]]
        findings.append(
            Finding(
                code="OFFICE.EXTERNAL_REFERENCE",
                title="Document references external content",
                detail=(
                    "The document links to external resources: "
                    f"{', '.join(targets)}. External templates and links are a "
                    "long-standing technique for turning a harmless-looking document "
                    "into remote code execution - the payload arrives from the "
                    "referenced location rather than from the file you were sent."
                ),
                severity=Severity.HIGH,
                source=SignalSource.OFFICE_DOCUMENT,
                category="payload",
                weight=20.0,
                evidence={"relationships": dangerous_rels[:20]},
            )
        )

    if report.embedded_objects:
        findings.append(
            Finding(
                code="OFFICE.EMBEDDED_OBJECT",
                title="Document embeds other objects",
                detail=(
                    f"{len(report.embedded_objects)} embedded object(s) were found "
                    f"({', '.join(report.embedded_objects[:4])}). Embedded OLE "
                    "objects and packages execute under their own application and "
                    "can hide any file type inside a document."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.OFFICE_DOCUMENT,
                category="payload",
                weight=14.0,
                evidence={"objects": report.embedded_objects[:20]},
            )
        )

    if report.dde_fields:
        findings.append(
            Finding(
                code="OFFICE.DDE_FIELD",
                title="Document contains DDE field codes",
                detail=(
                    "DDE fields instruct another installed application to run a "
                    "command when the document is opened. This was the basis of the "
                    "Follina vulnerability and remains a live exploitation path."
                ),
                severity=Severity.HIGH,
                source=SignalSource.OFFICE_DOCUMENT,
                category="payload",
                weight=20.0,
                evidence={"fields": report.dde_fields[:10]},
            )
        )

    if report.active_content:
        findings.append(
            Finding(
                code="OFFICE.ACTIVE_CONTENT",
                title="Document contains active or scripted content",
                detail=(
                    "ActiveX controls, custom UI XML or script-like content were "
                    "found in the document parts. These run without a macro warning."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.OFFICE_DOCUMENT,
                category="payload",
                weight=12.0,
                evidence={"items": report.active_content[:20]},
            )
        )

    if report.encrypted:
        findings.append(
            Finding(
                code="OFFICE.ENCRYPTED",
                title="Document is password protected",
                detail=(
                    "An encrypted document cannot be inspected by any scanner. "
                    "Password protection on an unexpected attachment prevents "
                    "verification by both the user and their security tooling."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.OFFICE_DOCUMENT,
                category="integrity",
                weight=10.0,
            )
        )

    suspicious_urls = _suspicious_urls(report.urls)
    if suspicious_urls:
        findings.append(
            Finding(
                code="OFFICE.SUSPICIOUS_EMBEDDED_URL",
                title="Document contains links to unencrypted or raw-IP destinations",
                detail=(
                    "The document references "
                    f"{', '.join(suspicious_urls[:4])}. Raw-IP and plaintext-HTTP links "
                    "inside documents are used for click-through tracking to "
                    "infrastructure that cannot be blocklisted by domain."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.OFFICE_DOCUMENT,
                category="links",
                weight=10.0,
                evidence={"urls": suspicious_urls[:20]},
            )
        )
    return findings


def _suspicious_urls(urls: list[str]) -> list[str]:
    from ..url.normalizer import parse_url

    flagged: list[str] = []
    for url in urls:
        try:
            parsed = parse_url(url)
        except Exception:
            continue
        if parsed.is_ip_literal or parsed.scheme == "http":
            flagged.append(url)
    return flagged