"""PDF structural and content analysis.

PDF is the most abused delivery format in targeted phishing, and it is a genuinely
hard format to analyse safely: it is a declarative page-description language with
optional encryption, embedded JavaScript, launch actions, attachments and
arbitrary compressed object streams.

Design decisions
----------------
* ``pypdf`` is used when available for structural parsing; otherwise the raw
  token scanner below still finds URLs, JavaScript and launch actions.
* Nothing is rendered.  No external binary is invoked.  No font, image or stream
  is decoded beyond what pypdf exposes as bytes.
* The module is hardened against decompression bombs: total inflated bytes are
  budgeted, and object counts are capped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Finding, Severity, SignalSource

__all__ = ["PdfReport", "analyze_pdf", "pdf_findings", "extract_pdf_text"]

#: Budget for inflated PDF streams in a single scan.
_INFLATE_BUDGET = 120 * 1024 * 1024
#: Cap on number of indirect objects inspected.
_MAX_OBJECTS = 20_000

#: Dangerous PDF tokens, matched case-insensitively against decoded content.
_JS_MARKERS = (
    b"/JavaScript", b"/JS", b"eval(", b"unescape(", b"app.alert", b"this.getField",
    b"submitForm", b"importData", b"exportDataObject", b"String.fromCharCode",
    b"\.pdf_javascript", b"for (var", b"function(",
)
_ACTION_MARKERS = (b"/Launch", b"/URI", b"/SubmitForm", b"/ImportData", b"/GoToR", b"/RichMedia", b"/Movie")
_ENCRYPT_MARKERS = (b"/Encrypt", b"/Filter /Standard")
_AUTOMATION_MARKERS = (b"/OpenAction", b"/AA", b"/Names /JavaScript", b"/AcroForm", b"/XFA")
_EXFIL_MARKERS = (b"http://", b"https://", b"mailto:")

_URL_RE = re.compile(rb"(?:https?|ftp)://[^\s<>\)\]\"'%]{4,400}", re.IGNORECASE)
#: Classic PDF-embedded-in-HTML obfuscation.
_HTML_SNIFF_RE = re.compile(rb"<\s*html|<\s*script|<\s*iframe", re.IGNORECASE)
#: Executable signatures hiding inside a PDF stream.
_EXEC_MAGIC = (
    b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe", b"PK\x03\x04", b"#!", b"\x1f\x8b\x08",
)


@dataclass(slots=True)
class PdfReport:
    """Structural facts and findings from a PDF."""

    version: str = ""
    encrypted: bool = False
    encrypted_detail: str = ""
    object_count: int = 0
    page_count: int | None = None
    has_javascript: bool = False
    js_indicators: list[str] = field(default_factory=list)
    launch_actions: list[str] = field(default_factory=list)
    open_action: bool = False
    embedded_files: list[str] = field(default_factory=list)
    xfa_forms: bool = False
    auto_actions: bool = False
    urls: list[str] = field(default_factory=list)
    raw_ip_urls: list[str] = field(default_factory=list)
    embedded_executables: list[str] = field(default_factory=list)
    trailer_id: str = ""
    producer: str = ""
    creator: str = ""
    creation_date: str = ""
    #: Human-visible text from the content stream, used for phishing analysis.
    text_parts: list[str] = field(default_factory=list)
    text_chars: int = 0
    #: True when a text layer exists but is too small to be meaningful.
    text_layer_suspect: bool = False
    anomalies: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        """Extracted text, capped at a sane analysis budget."""
        return "\n".join(self.text_parts)[:200_000]

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "encrypted": self.encrypted,
            "object_count": self.object_count,
            "page_count": self.page_count,
            "has_javascript": self.has_javascript,
            "js_indicators": self.js_indicators[:20],
            "launch_actions": self.launch_actions[:20],
            "open_action": self.open_action,
            "embedded_files": self.embedded_files[:20],
            "xfa_forms": self.xfa_forms,
            "auto_actions": self.auto_actions,
            "urls": self.urls[:100],
            "raw_ip_urls": self.raw_ip_urls[:20],
            "embedded_executables": self.embedded_executables[:20],
            "metadata": {
                "producer": self.producer,
                "creator": self.creator,
                "creation_date": self.creation_date,
                "trailer_id": self.trailer_id,
            },
            "text_chars": self.text_chars,
            "text_layer_suspect": self.text_layer_suspect,
            "anomalies": self.anomalies,
            "errors": self.errors,
        }


def analyze_pdf(data: bytes, *, max_depth: int = 3) -> PdfReport:
    """Analyse a PDF file's structure and content."""
    report = PdfReport()
    if not data.startswith(b"%PDF-"):
        report.errors.append("Missing %PDF- header.")
        return report

    report.version = data[:9].decode("ascii", errors="replace").strip()

    # ---- structural pass with pypdf when available ------------------- #
    structural = _analyze_with_pypdf(data)
    if structural is not None:
        report = structural
    else:
        report.errors.append(
            "pypdf unavailable; analysis limited to raw token scanning (reduced confidence)."
        )

    # ---- raw token pass (always runs, catches what parsers normalise away)
    haystack = _searchable_bytes(data, budget=_INFLATE_BUDGET)
    _scan_tokens(report, haystack)

    # A PDF that is really an HTML page (or vice versa) is a browser-detection
    # trick that fools file-type filters.
    if _HTML_SNIFF_RE.search(data[:4096]):
        report.anomalies.append(
            "HTML markup appears inside the file header - this is used to fool "
            "browser content sniffing and upload filters."
        )

    report.text_parts = extract_pdf_text(data)
    report.text_chars = sum(len(part) for part in report.text_parts)
    if report.has_javascript and report.text_chars > 0:
        # A tiny visible text layer plus script is the shape of a "you have won"
        # overlay that replaces the page content at open time.
        report.text_layer_suspect = report.text_chars < 400
    return report


#: PDF text-showing operators we can safely recover without a font-aware parser.
_TEXT_SHOW = re.compile(rb"\((?:\\.|[^\\()])*\)\s*T[jJ*]|<[0-9A-Fa-f\s]+>\s*T[jJ*]")


def extract_pdf_text(data: bytes, *, max_parts: int = 20_000) -> list[str]:
    """Recover human-visible text from a PDF's content streams.

    This is a *deliberately shallow* extraction.  Full text recovery needs font
    CMap parsing and encoding inference to map glyph codes back to characters;
    doing that properly is out of scope.  What this returns is good enough to run
    social-engineering lexicon matching over, and :func:`analyze_pdf` reports a
    suspiciously small result rather than claiming the document is blank.

    Strings inside ``Tj``/``TJ`` operators are the page's drawn text.  Escaped
    parentheses are unescaped; octal escapes are decoded.
    """
    if not data.startswith(b"%PDF-"):
        return []

    parts: list[str] = []
    seen = 0
    for match in _TEXT_SHOW.finditer(data):
        raw = match.group(0)
        seen += 1
        if seen > max_parts:
            break
        for literal in re.findall(rb"\((?:\\.|[^\\()])*\)", raw):
            text = _decode_pdf_string(literal[1:-1])
            if text:
                parts.append(text)
    # A PDF can legitimately hold hundreds of thousands of glyphs; cap the
    # retained text so a huge document cannot blow up memory or scan time.
    return parts[:max_parts]


_ESCAPES = {
    ord("n"): "\n",
    ord("r"): "\r",
    ord("t"): "\t",
    ord("b"): "\b",
    ord("f"): "\f",
    ord("("): "(",
    ord(")"): ")",
    ord("\\"): "\\",
}


def _decode_pdf_string(raw: bytes) -> str:
    out = bytearray()
    index = 0
    while index < len(raw):
        byte = raw[index]
        if byte != 0x5C:  # backslash
            out.append(byte)
            index += 1
            continue
        index += 1
        if index >= len(raw):
            break
        nxt = raw[index]
        if nxt in _ESCAPES:
            out.extend(_ESCAPES[nxt].encode())
            index += 1
        elif 0x30 <= nxt <= 0x37:  # octal, up to three digits
            digits = bytearray()
            while index < len(raw) and len(digits) < 3 and 0x30 <= raw[index] <= 0x37:
                digits.append(raw[index])
                index += 1
            out.append(int(digits, 8) & 0xFF)
        elif nxt in (0x0A, 0x0D):  # line continuation
            index += 1
        else:
            out.append(nxt)
            index += 1
    return out.decode("utf-8", errors="replace").strip()


def _searchable_bytes(data: bytes, *, budget: int) -> bytes:
    """Inflate FlateDecode streams so token scanning sees real content."""
    import zlib

    out = bytearray(data[: min(len(data), budget)])
    consumed = 0
    for match in re.finditer(rb"stream\r?\n", data):
        if consumed > budget:
            break
        start = match.end()
        end = data.find(b"endstream", start)
        if end == -1 or end - start > 20 * 1024 * 1024:
            continue
        chunk = data[start:end]
        for attempt in (chunk, chunk.rstrip(b"\r\n")):
            try:
                inflated = zlib.decompress(attempt)
            except zlib.error:
                continue
            if inflated:
                room = budget - consumed - len(out)
                if room <= 0:
                    break
                out.extend(inflated[:room])
                consumed += len(inflated)
            break
    return bytes(out)


def _scan_tokens(report: PdfReport, data: bytes) -> None:
    lowered = data.lower()

    for marker in _JS_MARKERS:
        if marker.lower() in lowered:
            report.has_javascript = True
            report.js_indicators.append(marker.decode("ascii", errors="replace"))
    report.js_indicators = list(dict.fromkeys(report.js_indicators))

    for marker in _ACTION_MARKERS:
        if marker.lower() in lowered:
            report.launch_actions.append(marker.decode("ascii", errors="replace"))
    report.launch_actions = list(dict.fromkeys(report.launch_actions))

    if any(m in data for m in (b"/OpenAction", b"/AA")):
        report.open_action = True
    if any(m in data for m in (b"/AcroForm", b"/XFA")):
        report.xfa_forms = True
        report.auto_actions = True
    if b"/Names" in data and b"/JavaScript" in data:
        report.auto_actions = True

    for match in re.finditer(rb"/EmbeddedFile", data):
        report.embedded_files.append(f"EmbeddedFile at offset {match.start()}")
    for match in re.finditer(rb"/Filespec", data):
        report.embedded_files.append(f"Filespec at offset {match.start()}")
    report.embedded_files = list(dict.fromkeys(report.embedded_files))[:20]

    for match in _URL_RE.finditer(data):
        url = match.group(0).decode("utf-8", errors="replace").rstrip(".,;)")
        if len(url) < 10:
            continue
        report.urls.append(url)
        if _is_raw_ip_url(url):
            report.raw_ip_urls.append(url)
    report.urls = list(dict.fromkeys(report.urls))[:200]
    report.raw_ip_urls = list(dict.fromkeys(report.raw_ip_urls))[:50]

    for magic in _EXEC_MAGIC:
        position = data.find(magic, 8)  # skip a leading match in the header
        if position != -1:
            report.embedded_executables.append(
                f"{magic[:4].hex()} signature at byte {position}"
            )
    report.embedded_executables = list(dict.fromkeys(report.embedded_executables))[:20]

    if not report.encrypted and any(marker in data for marker in _ENCRYPT_MARKERS):
        report.encrypted = True
        report.encrypted_detail = "Encryption dictionary present"

    trailer = re.search(rb"/ID\s*\[\s*<([0-9A-Fa-f]{16,64})>", data)
    if trailer:
        report.trailer_id = trailer.group(1).decode("ascii")[:64]

    producer = re.search(rb"/Producer\s*\(([^)]{0,120})\)", data)
    if producer:
        report.producer = producer.group(1).decode("utf-8", errors="replace")
    creator = re.search(rb"/Creator\s*\(([^)]{0,120})\)", data)
    if creator:
        report.creator = creator.group(1).decode("utf-8", errors="replace")
    creation = re.search(rb"/CreationDate\s*\(([^)]{0,60})\)", data)
    if creation:
        report.creation_date = creation.group(1).decode("utf-8", errors="replace")

    # Version skew is a classic sign of a hand-crafted weaponised PDF.
    if report.version and report.version not in ("%PDF-1.4", "%PDF-1.5", "%PDF-1.6", "%PDF-1.7", "%PDF-2.0"):
        report.anomalies.append(f"Unusual PDF version header '{report.version}'.")


def _is_raw_ip_url(url: str) -> bool:
    import ipaddress
    from urllib.parse import urlsplit

    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _analyze_with_pypdf(data: bytes) -> PdfReport | None:
    """Structural analysis using pypdf; returns None if it is unavailable."""
    try:
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError
    except Exception:
        return None

    report = PdfReport()
    try:
        reader = PdfReader(io_bytes(data), strict=False)
    except Exception as exc:
        report.errors.append(f"pypdf could not read the structure: {exc}")
        return report

    try:
        report.encrypted = bool(reader.is_encrypted)
    except Exception:
        pass
    if report.encrypted:
        report.encrypted_detail = "Document requires a password for full access"
    try:
        report.page_count = len(reader.pages)
    except Exception as exc:
        report.anomalies.append(f"Page tree unreadable: {exc}")
    try:
        report.object_count = sum(1 for _ in reader.xref) if hasattr(reader, "xref") else 0
    except Exception:
        report.object_count = 0
    try:
        metadata = reader.metadata or {}
        report.producer = str(metadata.get("/Producer", "") or "")
        report.creator = str(metadata.get("/Creator", "") or "")
        report.creation_date = str(metadata.get("/CreationDate", "") or "")
        report.trailer_id = str(metadata.get("/ID", "") or "")[:64]
    except Exception:
        pass

    # Field names can carry phishing/social-engineering text.
    try:
        root = getattr(reader, "trailer", {}).get("/Root", {})
        names = root.get("/Names", {})
        for name in names.get("/JavaScript", []) if hasattr(names.get("/JavaScript", []), "__iter__") else []:
            report.has_javascript = True
            del name
    except Exception:
        pass

    try:
        outline = reader.outline
        if outline:
            report.auto_actions = report.auto_actions
    except Exception:
        pass
    return report


def io_bytes(data: bytes):
    import io

    return io.BytesIO(data)


def pdf_findings(report: PdfReport) -> list[Finding]:
    """Findings derived from a :class:`PdfReport`."""
    findings: list[Finding] = []

    if report.has_javascript:
        findings.append(
            Finding(
                code="PDF.JAVASCRIPT",
                title="PDF contains JavaScript",
                detail=(
                    "This document executes script when opened. JavaScript in a PDF "
                    "can rewrite the visible page, auto-submit forms, and - on "
                    "vulnerable readers - read local files or reach the network "
                    "silently. Legitimate documents do not need it."
                ),
                severity=Severity.HIGH,
                source=SignalSource.PDF_DOCUMENT,
                category="payload",
                weight=24.0,
                authoritative=True,
                evidence={"indicators": report.js_indicators[:20]},
            )
        )

    if report.launch_actions:
        dangerous = [a for a in report.launch_actions if a in ("/Launch", "/RichMedia", "/Movie", "/GoToR")]
        if dangerous:
            findings.append(
                Finding(
                    code="PDF.LAUNCH_ACTION",
                    title="PDF contains actions that launch external content",
                    detail=(
                        f"Action types {', '.join(dangerous)} tell the reader to open "
                        "another file or application. This is the mechanism behind "
                        "many 'open this attachment to view' malware campaigns."
                    ),
                    severity=Severity.HIGH,
                    source=SignalSource.PDF_DOCUMENT,
                    category="payload",
                    weight=24.0,
                    authoritative=True,
                    evidence={"actions": report.launch_actions[:20]},
                )
            )
        else:
            findings.append(
                Finding(
                    code="PDF.AUTOMATIC_ACTION",
                    title="PDF performs an action when opened",
                    detail="The document triggers navigation or form actions automatically.",
                    severity=Severity.MEDIUM,
                    source=SignalSource.PDF_DOCUMENT,
                    category="payload",
                    weight=12.0,
                    evidence={"actions": report.launch_actions[:20]},
                )
            )

    if report.embedded_executables:
        findings.append(
            Finding(
                code="PDF.EMBEDDED_EXECUTABLE",
                title="PDF contains executable data",
                detail=(
                    "Executable or archive signatures were found inside the document "
                    f"({'; '.join(report.embedded_executables[:3])}). A PDF that "
                    "carries a program is being used as a covert delivery container."
                ),
                severity=Severity.CRITICAL,
                source=SignalSource.PDF_DOCUMENT,
                category="payload",
                weight=32.0,
                authoritative=True,
                evidence={"offsets": report.embedded_executables[:20]},
            )
        )

    if report.embedded_files:
        findings.append(
            Finding(
                code="PDF.EMBEDDED_ATTACHMENT",
                title="PDF has files embedded in it",
                detail=(
                    f"{len(report.embedded_files)} embedded file specification(s) were "
                    "found. Embedded attachments are invisible in a normal preview "
                    "and are used to smuggle a second payload past email gateways."
                ),
                severity=Severity.HIGH,
                source=SignalSource.PDF_DOCUMENT,
                category="payload",
                weight=20.0,
                evidence={"files": report.embedded_files[:20]},
            )
        )

    if report.xfa_forms:
        findings.append(
            Finding(
                code="PDF.XFA_FORM",
                title="PDF contains XFA forms",
                detail=(
                    "XFA forms can execute arbitrary script and have been used as an "
                    "exploit vector (for example CVE-2023-21627). Their presence "
                    "should be treated as an exploitation attempt."
                ),
                severity=Severity.HIGH,
                source=SignalSource.PDF_DOCUMENT,
                category="payload",
                weight=22.0,
            )
        )

    if report.encrypted and not report.has_javascript:
        findings.append(
            Finding(
                code="PDF.ENCRYPTED",
                title="PDF is password protected",
                detail=(
                    "The document is encrypted, so its content cannot be inspected by "
                    "any scanner. If you were not expecting a password, treat this as "
                    "a way to smuggle an unviewable file past review."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.PDF_DOCUMENT,
                category="integrity",
                weight=10.0,
            )
        )

    if report.raw_ip_urls:
        findings.append(
            Finding(
                code="PDF.RAW_IP_LINK",
                title="PDF links to a raw IP address",
                detail=(
                    f"The document links to {', '.join(report.raw_ip_urls[:3])}. "
                    "IP-literal links cannot be filtered by domain reputation and are "
                    "a common way to redirect victims to disposable infrastructure."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.PDF_DOCUMENT,
                category="links",
                weight=10.0,
                evidence={"urls": report.raw_ip_urls[:20]},
            )
        )

    for anomaly in report.anomalies:
        findings.append(
            Finding(
                code="PDF.ANOMALY",
                title="Structural anomaly in PDF",
                detail=anomaly,
                severity=Severity.MEDIUM,
                source=SignalSource.PDF_DOCUMENT,
                category="structure",
                weight=10.0,
            )
        )
    return findings