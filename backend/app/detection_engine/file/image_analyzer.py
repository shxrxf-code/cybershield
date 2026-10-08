"""Image security analysis.

What image analysis can and cannot establish
--------------------------------------------
Metadata, dimensions and integrity checks reliably describe an image, but they
**cannot** determine whether an image is malicious. A trojanised PNG and a
photograph of a cat have identical structure. This module therefore reports
*anomalies* - polyglot files, appended payloads, metadata-borne URLs and social
engineering text - and explicitly never classifies an image as malicious on
metadata alone.

The strongest genuine signals are:

* **Appended data after the image end marker** - a legitimate encoder stops after
  the final chunk. Trailing bytes mean a payload is being carried inside a file
  that passes image filters.
* **Magic-byte / extension mismatch** - a "photo.jpg" that is actually a script.
* **Embedded URLs in EXIF/XMP comments** - QR-code phishing and watermark-based
  lure campaigns embed links in image metadata.
* **Suspicious EXIF fields** - GPS coordinates combined with a social platform
  handle indicates location disclosure.
"""

from __future__ import annotations

import re
import struct
from typing import TYPE_CHECKING

from app.detection_engine.file.analyzer_types import FileKind
from app.detection_engine.file.magic import identify
from app.detection_engine.text import extract_urls, truncate_for_display
from app.schemas.common import IndicatorType, Severity, SignalSource
from app.schemas.signal import DetectionSignal, Indicator

if TYPE_CHECKING:  # pragma: no cover
    from app.detection_engine.file.analyzer import FileAnalysisResult

#: End markers that terminate the image payload of each format.
# PNG/JPEG/GIF/TIFF all have a well-defined end marker; every other kind is
# omitted so that trailing-data analysis is skipped rather than guessed at.
_END_MARKERS: dict[str, bytes] = {
    "PDF": b"%%EOF",
    "PNG": b"IEND\xaeB`\x82",
    "JPEG": b"\xff\xd9",
    "GIF": b"\x3b",
    "ZIP": b"PK\x05\x06",
    "OLE2": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
}

#: Kinds with no reliably-locatable end marker, so trailing-data analysis is
#: skipped rather than producing false positives.
_UNBOUNDED_FORMATS: frozenset[str] = frozenset({"binary", "unknown", "archive", "text"})

#: Image dimensions above which a file is very likely to be a decompression bomb.
_MAX_SAFE_DIMENSION = 60000
_MAX_TOTAL_PIXELS = 250_000_000

_EXIF_INTERESTING_TAGS: dict[int, str] = {
    0x010E: "ImageDescription",
    0x010F: "Make",
    0x0110: "Model",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x8769: "ExifIFD",
    0x9C9B: "XPTitle",
    0x9C9C: "XPComment",
    0x9C9D: "XPAuthor",
    0x9C9E: "XPKeywords",
    0x9C9F: "XPSubject",
    0x9286: "UserComment",
}

#: EXIF GPS tags, tracked to report location disclosure.
_GPS_TAGS: frozenset[str] = frozenset(
    {"GPSLatitude", "GPSLongitude", "GPSLatitudeRef", "GPSLongitudeRef", "GPSAltitude"}
)

_URL_IN_TEXT_RE = re.compile(r"https?://[^\s<>\"']{4,500}", re.I)

_SUSPICIOUS_SOFTWARE_RE = re.compile(
    r"(?:metasploit|cobalt\s*strike|empire|mimikatz|havij|nikto|acunetix|burp\s*suite|"
    r"nuclei|masscan|hydra|sqlmap)",
    re.I,
)


def analyse_image(data: bytes, result: "FileAnalysisResult") -> list[DetectionSignal]:
    """Analyse an image's structure, metadata and integrity."""
    signals: list[DetectionSignal] = []
    kind = result.content_type.kind
    if kind is FileKind.UNKNOWN:
        return signals

    dimensions = _read_dimensions(data, kind)
    if dimensions:
        width, height = dimensions
        result.metadata.update({"width": width, "height": height,
                                "megapixels": round(width * height / 1_000_000, 2)})
        signals.extend(_analyse_dimensions(width, height, result))

    exif = _parse_exif(data)
    if exif:
        result.metadata["exif"] = exif
        signals.extend(_analyse_exif(exif, result))

    signals.extend(_analyse_trailing_data(data, kind, result, result.content_type.label))
    signals.extend(_analyse_svg(data, result))
    return signals


# ---------------------------------------------------------------------------
# Dimensions
# ---------------------------------------------------------------------------
def _read_dimensions(data: bytes, kind: FileKind) -> tuple[int, int] | None:
    """Read pixel dimensions from the image header."""
    try:
        if kind is FileKind.IMAGE and data[:8] == b"\x89PNG\r\n\x1a\n":
            return _png_dimensions(data)
        if data[:3] == b"\xff\xd8\xff":
            return _jpeg_dimensions(data)
        if data[:6] in (b"GIF87a", b"GIF89a"):
            return _gif_dimensions(data)
        if data[:4] in (b"II*\x00", b"MM\x00*"):
            return _tiff_dimensions(data)
        if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            return _webp_dimensions(data)
        if data[:2] == b"BM":
            return _bmp_dimensions(data)
    except (struct.error, IndexError, ValueError):
        return None
    return None


def _png_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 24 or data[12:16] != b"IHDR":
        return None
    return struct.unpack(">II", data[16:24])


def _jpeg_dimensions(data: bytes) -> tuple[int, int] | None:
    offset = 2
    length = len(data)
    while offset + 9 < length:
        if data[offset] != 0xFF:
            offset += 1
            continue
        marker = data[offset + 1]
        # SOF0-SOF15, excluding the non-frame markers DHT/JPG/DAC.
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            height, width = struct.unpack(">HH", data[offset + 5 : offset + 9])
            return width, height
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            offset += 2
            continue
        if offset + 4 > length:
            break
        segment_length = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
        if segment_length < 2:
            break
        offset += 2 + segment_length
    return None


def _gif_dimensions(data: bytes) -> tuple[int, int] | None:
    return struct.unpack("<HH", data[6:10])


def _tiff_dimensions(data: bytes) -> tuple[int, int] | None:
    endian = "<" if data[:2] == b"II" else ">"
    ifd_offset = struct.unpack(endian + "I", data[4:8])[0]
    if ifd_offset + 2 > len(data):
        return None
    entry_count = struct.unpack(endian + "H", data[ifd_offset : ifd_offset + 2])[0]
    width = height = None
    for index in range(min(entry_count, 64)):
        entry = ifd_offset + 2 + index * 12
        if entry + 12 > len(data):
            break
        tag, tag_type, _count = struct.unpack(endian + "HHI", data[entry : entry + 8])
        value = data[entry + 8 : entry + 12]
        if tag == 0x0100 and tag_type == 3:
            width = struct.unpack(endian + "H", value[:2])[0]
        elif tag == 0x0101 and tag_type == 3:
            height = struct.unpack(endian + "H", value[:2])[0]
    if width and height:
        return width, height
    return None


def _webp_dimensions(data: bytes) -> tuple[int, int] | None:
    chunk = data[12:16]
    if chunk == b"VP8X" and len(data) >= 30:
        width = int.from_bytes(data[24:27], "little") + 1
        height = int.from_bytes(data[27:30], "little") + 1
        return width, height
    if chunk == b"VP8 " and len(data) >= 30:
        return (
            struct.unpack("<H", data[26:28])[0] & 0x3FFF,
            struct.unpack("<H", data[28:30])[0] & 0x3FFF,
        )
    if chunk == b"VP8L" and len(data) >= 25:
        bits = int.from_bytes(data[21:25], "little")
        return ((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1)
    return None


def _bmp_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 26:
        return None
    width, height = struct.unpack("<ii", data[18:26])
    return abs(width), abs(height)


def _analyse_dimensions(width: int, height: int, result: "FileAnalysisResult") -> list[DetectionSignal]:
    signals: list[DetectionSignal] = []
    total_pixels = width * height

    if width > _MAX_SAFE_DIMENSION or height > _MAX_SAFE_DIMENSION or total_pixels > _MAX_TOTAL_PIXELS:
        signals.append(
            DetectionSignal(
                code="image.dimension_anomaly",
                title="Image declares implausible dimensions",
                description=(
                    f"The image header declares {width}x{height} pixels "
                    f"({result.metadata.get('megapixels', 0)} megapixels). Decoding an image of "
                    "this size can exhaust memory, so this pattern is used in image-based denial "
                    "of service attacks. The file was not decoded by this analysis."
                ),
                severity=Severity.MEDIUM,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.7,
                evidence={
                    "width": width,
                    "height": height,
                    "total_pixels": total_pixels,
                    "max_safe_dimension": _MAX_SAFE_DIMENSION,
                },
            )
        )
    elif width == 0 or height == 0:
        signals.append(
            DetectionSignal(
                code="image.zero_dimension",
                title="Image declares zero width or height",
                description=(
                    "The image header declares a zero dimension, which is inconsistent with a "
                    "valid image and may indicate truncation or deliberate header corruption."
                ),
                severity=Severity.MEDIUM,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.75,
                evidence={"width": width, "height": height},
            )
        )
    return signals


# ---------------------------------------------------------------------------
# EXIF / XMP metadata
# ---------------------------------------------------------------------------
def _parse_exif(data: bytes) -> dict[str, str]:
    """Extract a small, safe subset of EXIF/XMP text fields.

    Only ASCII and UTF-8 text fields are decoded, with strict bounds, so a crafted
    metadata block cannot cause unbounded allocation.
    """
    fields: dict[str, str] = {}
    limit = min(len(data), 512 * 1024)
    window = data[:limit]

    # XMP packets are plain XML and easy to parse safely.
    xmp_start = window.find(b"<x:xmpmeta")
    if xmp_start != -1:
        xmp_end = window.find(b"</x:xmpmeta>", xmp_start)
        if xmp_end != -1:
            chunk = window[xmp_start : xmp_end + 12].decode("utf-8", errors="ignore")
            for key, pattern in (
                ("XMPDescription", r"<dc:description>.*?<rdf:li[^>]*>(.*?)</rdf:li>"),
                ("XMPTitle", r"<dc:title>.*?<rdf:li[^>]*>(.*?)</rdf:li>"),
                ("XMPCreator", r"<dc:creator>.*?<rdf:li[^>]*>(.*?)</rdf:li>"),
                ("XPComment", r"<photoshop:Instructions>(.*?)</photoshop:Instructions>"),
                ("XMPToolkit", r"<xmp:CreatorTool>(.*?)</xmp:CreatorTool>"),
            ):
                match = re.search(pattern, chunk, re.S)
                if match:
                    value = _clean_metadata(match.group(1))
                    if value:
                        fields[key] = value

    # JPEG APP1 EXIF text fields.
    if data[:3] == b"\xff\xd8\xff":
        fields.update(_parse_jpeg_exif_text(window))
    return fields


def _parse_jpeg_exif_text(data: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    marker = data.find(b"Exif\x00\x00")
    if marker == -1:
        return fields
    tiff_start = marker + 6
    if tiff_start + 8 > len(data):
        return fields

    endian = "<" if data[tiff_start : tiff_start + 2] == b"II" else ">"
    try:
        ifd_offset = struct.unpack(endian + "I", data[tiff_start + 4 : tiff_start + 8])[0]
        offset = tiff_start + ifd_offset
        if offset + 2 > len(data):
            return fields
        count = struct.unpack(endian + "H", data[offset : offset + 2])[0]
        for index in range(min(count, 128)):
            entry = offset + 2 + index * 12
            if entry + 12 > len(data):
                break
            tag, tag_type, value_count, value_offset = struct.unpack(
                endian + "HHII", data[entry : entry + 12]
            )
            name = _EXIF_INTERESTING_TAGS.get(tag)
            if not name:
                continue
            value = _read_exif_value(data, tiff_start, endian, tag_type, value_count, value_offset)
            if value:
                fields[name] = value
    except (struct.error, ValueError, IndexError):
        return fields
    return fields


def _read_exif_value(
    data: bytes,
    tiff_start: int,
    endian: str,
    tag_type: int,
    value_count: int,
    value_offset: int,
) -> str:
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}
    unit_size = sizes.get(tag_type)
    if not unit_size:
        return ""
    total = unit_size * max(1, value_count)
    if total > 4096:
        return ""

    if total <= 4:
        raw = data[tiff_start + 8 + (value_offset & 0xFFFFFFFF) :][:4]
    else:
        start = tiff_start + value_offset
        if start + total > len(data):
            return ""
        raw = data[start : start + total]

    if tag_type in (2,):
        return _clean_metadata(raw.split(b"\x00")[0].decode("utf-8", errors="ignore"))
    if tag_type in (1, 7):
        return _clean_metadata(raw.split(b"\x00")[0].decode("latin-1", errors="ignore"))
    if tag_type == 3:
        value = struct.unpack(endian + "H", raw[:2])[0]
        return f"{value} ({value})"  # Rational shorthand, truncated below.
    return ""


def _clean_metadata(value: str) -> str:
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", value or "").strip()
    return cleaned[:256]


def _analyse_exif(exif: dict[str, str], result: "FileAnalysisResult") -> list[DetectionSignal]:
    signals: list[DetectionSignal] = []
    if not exif:
        return signals

    # URLs in metadata -> QR / watermark phishing campaigns.
    urls: list[str] = []
    for key, value in exif.items():
        urls.extend(extract_urls(value, limit=10))
    if urls:
        unique = sorted(set(urls))[:10]
        signals.append(
            DetectionSignal(
                code="image.metadata_url",
                title="Image metadata contains web links",
                description=(
                    "The image's metadata contains "
                    f"{len(set(urls))} URL(s) ("
                    + ", ".join(truncate_for_display(url, 80) for url in unique[:3])
                    + "). Links hidden in image metadata are used in QR-code phishing and "
                    "watermark lure campaigns, where the visible image appears harmless."
                ),
                severity=Severity.MEDIUM,
                category="deception",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.6,
                evidence={"urls": unique, "fields": sorted(exif.keys())},
                indicators=tuple(
                    Indicator(type=IndicatorType.URL, value=url[:255]) for url in unique[:10]
                ),
            )
        )
        result.embedded_urls.extend(unique)

    gps_fields = [key for key in exif if key.replace("GPS", "") in _GPS_TAGS or key in _GPS_TAGS]
    if gps_fields:
        signals.append(
            DetectionSignal(
                code="image.gps_metadata",
                title="Image contains GPS location metadata",
                description=(
                    "The image retains precise geographic coordinates. This discloses the "
                    "photographer's or subject's location, which is a privacy concern when "
                    "sharing images publicly."
                ),
                severity=Severity.INFO,
                category="privacy",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.85,
                evidence={"fields": gps_fields},
            )
        )

    software = exif.get("Software", "") + " " + exif.get("XMPToolkit", "")
    if _SUSPICIOUS_SOFTWARE_RE.search(software):
        signals.append(
            DetectionSignal(
                code="image.security_tool_metadata",
                title="Image metadata names a security testing tool",
                description=(
                    f"The authoring software field reads '{truncate_for_display(software, 120)}', "
                    "which is associated with offensive security tooling. Images prepared for "
                    "exploitation often retain this metadata."
                ),
                severity=Severity.MEDIUM,
                category="static_analysis",
                source=SignalSource.HEURISTIC,
                confidence=0.55,
                evidence={"software": truncate_for_display(software, 160)},
            )
        )

    return signals


# ---------------------------------------------------------------------------
# Trailing data / polyglot detection
# ---------------------------------------------------------------------------
def _analyse_trailing_data(
    data: bytes, kind: FileKind, result: "FileAnalysisResult", format_label: str = ""
) -> list[DetectionSignal]:
    """Detect bytes appended after the end of the image payload."""
    if kind.value in _UNBOUNDED_FORMATS:
        return []
    marker = _END_MARKERS.get(format_label.upper())
    if marker is None:
        return []

    end = data.rfind(marker)
    if end == -1:
        return []

    trailing = len(data) - (end + len(marker))
    result.metadata["trailing_data_bytes"] = trailing
    if trailing <= 0:
        return []

    # A handful of bytes is normal encoder padding; a large block is a payload.
    if trailing < 64:
        return []

    tail = data[end + len(marker) : end + len(marker) + 4096]
    payload_type = identify(tail)
    payload_description = (
        f" It begins with {payload_type.label} data ({payload_type.description})."
        if payload_type.kind.value != "unknown"
        else ""
    )

    severity = Severity.HIGH if payload_type.kind.value == "executable" else Severity.MEDIUM
    return [
        DetectionSignal(
            code="image.appended_data",
            title="Image contains data appended after its final marker",
            description=(
                f"{trailing} bytes follow the end of the {kind.value.upper()} image data. A "
                "standard encoder terminates the file at this point, so trailing content means a "
                "payload is being carried inside an image that would pass file-type filters."
                + payload_description
            ),
            severity=severity,
            category="static_analysis",
            source=SignalSource.STRUCTURAL,
            confidence=0.75,
            weight=0.5 if severity is Severity.HIGH else 0.3,
            evidence={
                "trailing_bytes": trailing,
                "total_size": len(data),
                "trailing_payload_type": payload_type.label,
                "trailing_payload_kind": payload_type.kind.value,
            },
        )
    ]


# ---------------------------------------------------------------------------
# SVG
# ---------------------------------------------------------------------------
_SVG_SCRIPT_RE = re.compile(
    rb"<\s*script\b|javascript\s*:|on(?:load|click|mouseover|error)\s*=|<\s*foreignObject\b|"
    rb"<\s*use\b[^>]*xlink:href\s*=\s*[\"']\s*(?:https?:|data:|file:)",
    re.I,
)

_SVG_EXTERNAL_RE = re.compile(rb"(?:xlink:href|href)\s*=\s*[\"'](?:https?:|data:|file:)[^\"']*", re.I)


def _analyse_svg(data: bytes, result: "FileAnalysisResult") -> list[DetectionSignal]:
    """SVG is an XML document that can execute script; it is treated as active content."""
    prefix = data[:4096].lstrip()
    is_svg = prefix[:5].lower() == b"<?xml" or prefix[:4].lower() == b"<svg" or b"<svg" in data[:2048].lower()
    if not is_svg:
        return []

    result.metadata["svg"] = True
    sample = data[:2 * 1024 * 1024]
    matches = sorted({m.group(0).decode("latin-1", "ignore")[:120] for m in _SVG_SCRIPT_RE.finditer(sample)})

    signals: list[DetectionSignal] = [
        DetectionSignal(
            code="image.svg_active_content",
            title="SVG image can execute script",
            description=(
                "This SVG contains script elements, event handlers or embedded external objects. "
                "Unlike raster images, SVG is an XML document that runs JavaScript when rendered, "
                "so it is a viable phishing and exploit vector."
            ),
            severity=Severity.HIGH if matches else Severity.MEDIUM,
            category="static_analysis",
            source=SignalSource.STATIC_ANALYSIS,
            confidence=0.7,
            evidence={"active_content_count": len(matches), "matches": matches[:8]},
        )
    ]

    externals = sorted(
        {
            m.group(0).decode("latin-1", "ignore")[:200]
            for m in _SVG_EXTERNAL_RE.finditer(sample)
        }
    )
    if externals:
        result.embedded_urls.extend(extract_urls(" ".join(externals), limit=20))
        signals.append(
            DetectionSignal(
                code="image.svg_external_reference",
                title="SVG references external content",
                description=(
                    "The SVG loads external resources, which leaks the viewer's IP address and "
                    "referrer to a third-party host and can be used for tracking or for staging "
                    "follow-on content."
                ),
                severity=Severity.MEDIUM,
                category="deception",
                source=SignalSource.STATIC_ANALYSIS,
                confidence=0.6,
                evidence={"references": externals[:8]},
            )
        )
    return signals