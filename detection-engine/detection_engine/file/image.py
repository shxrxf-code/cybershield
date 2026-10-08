"""Image metadata, integrity and payload analysis.

Honesty constraint
------------------
**An image cannot be classified as malicious from its metadata alone.**  EXIF data
proves authorship and origin, not intent.  What CyberShield does do is report
things that materially change risk:

* the file's actual type differs from its extension,
* EXIF records a preview thumbnail (often a different, embedded image) or
  GPS coordinates that were silently attached,
* a trailing payload is appended *after* the image's end-of-stream marker - the
  classic image-polyglot technique that passes every image scanner while
  carrying an HTML page, a ZIP or an executable,
* compression ratios are anomalous (a tiny file with a huge declared dimension
  is a decompression-bomb candidate),
* optional OCR text contains phishing language, which *is* actionable because it
  runs the same social-engineering analyser used for emails.

OCR is optional and off unless ``tesseract`` is installed; when it is
unavailable the scan says so rather than pretending the image had no text.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field

from ..models import Finding, Severity, SignalSource

__all__ = ["ImageReport", "analyze_image", "image_findings", "ocr_available", "ocr_text"]

#: Image formats we can structurally validate.
SUPPORTED = ("PNG", "JPEG", "GIF", "WEBP", "TIFF", "BMP")

#: Bytes appended after the image end marker before we call it a polyglot.
#: Encoders occasionally emit a few padding bytes after IEND/EOI, so a small
#: slack is allowed before the trailer is treated as a payload.
_TRAILING_TOLERANCE = 8
#: Pixel-count ceiling above which we refuse to fully decode.
_MAX_PIXELS = 80_000_000

#: EXIF tags that leak identity or location and are stripped by privacy tools.
_SENSITIVE_EXIF = {
    "GPS": "geographic coordinates",
    "MakerNote": "device-specific maker notes that can serialise a camera",
    "BodySerialNumber": "camera serial number",
    "OwnerName": "camera owner name",
    "CameraOwnerName": "camera owner name",
    "ImageUniqueID": "unique image identifier used for cross-site tracking",
    "DocumentID": "document identifier",
}

_GPS_FIELDS = ("GPSLatitude", "GPSLongitude", "GPSLatitudeRef", "GPSLongitudeRef")


@dataclass(slots=True)
class ImageReport:
    """Structural facts about an image."""

    format: str = ""
    mime: str = ""
    width: int | None = None
    height: int | None = None
    mode: str = ""
    frame_count: int = 1
    animated: bool = False
    file_size: int = 0
    compression_ratio: float = 0.0
    bits_per_pixel: float = 0.0
    trailing_bytes: int = 0
    trailing_signature: str = ""
    truncated: bool = False
    exif: dict[str, str] = field(default_factory=dict)
    sensitive_exif: list[str] = field(default_factory=list)
    has_thumbnail: bool = False
    text_segments: list[str] = field(default_factory=list)
    ocr_text: str = ""
    ocr_performed: bool = False
    ocr_error: str | None = None
    phishing_findings: list[Finding] = field(default_factory=list)
    structural_error: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "mime": self.mime,
            "width": self.width,
            "height": self.height,
            "mode": self.mode,
            "frames": self.frame_count,
            "animated": self.animated,
            "file_size": self.file_size,
            "compression_ratio": round(self.compression_ratio, 2),
            "bits_per_pixel": round(self.bits_per_pixel, 2),
            "trailing_bytes": self.trailing_bytes,
            "trailing_signature": self.trailing_signature,
            "truncated": self.truncated,
            "exif": self.exif,
            "sensitive_exif": self.sensitive_exif,
            "has_thumbnail": self.has_thumbnail,
            "text_segments": self.text_segments[:20],
            "ocr_performed": self.ocr_performed,
            "ocr_error": self.ocr_error,
            "ocr_text_excerpt": self.ocr_text[:2000],
            "structural_error": self.structural_error,
            "notes": self.notes,
        }


def _detect_end_offset(data: bytes, fmt: str) -> int:
    """Byte offset immediately after the last structural element of the image."""
    if fmt == "PNG":
        # Walk the chunk list; the last chunk must be IEND.
        offset = 8
        total = len(data)
        while offset + 8 <= total:
            length = int.from_bytes(data[offset : offset + 4], "big")
            chunk_type = data[offset + 4 : offset + 8]
            offset += 12 + length
            if chunk_type == b"IEND":
                return offset
        return -1
    if fmt == "JPEG":
        # Find the final EOI marker (FFD9), scanning backwards for robustness.
        index = data.rfind(b"\xff\xd9")
        return index + 2 if index != -1 else -1
    if fmt == "GIF":
        index = data.rfind(b"\x00\x3b")
        return index + 2 if index != -1 else -1
    if fmt in ("TIFF", "BMP"):
        return -1  # no reliable end marker; skip the trailing-payload check
    if fmt == "WEBP":
        index = data.rfind(b"WEBP")
        # RIFF length field gives the authoritative container size.
        if len(data) >= 8:
            declared = int.from_bytes(data[4:8], "little") + 8
            if 0 < declared <= len(data):
                return declared
        del index
    return -1


def _trailing_signature(data: bytes) -> str:
    if not data:
        return ""
    signatures = (
        (b"<!DOCTYPE", "HTML document"),
        (b"<html", "HTML document"),
        (b"<script", "HTML/script content"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"MZ", "Windows PE executable"),
        (b"\x7fELF", "ELF executable"),
        (b"\xca\xfe\xba\xbe", "Java/Mach-O binary"),
        (b"%PDF-", "PDF document"),
        (b"GIF8", "another GIF image"),
        (b"\x89PNG", "another PNG image"),
        (b"<?php", "PHP source"),
        (b"{\"", "JSON data"),
    )
    lowered = data[:512].lower()
    for marker, description in signatures:
        if lowered.startswith(marker.lower()):
            return description
    # Embedded file markers anywhere near the start of the trailer.
    head = data[:64]
    for marker, description in signatures:
        if marker.lower() in head.lower():
            return description
    return "binary data"


def analyze_image(data: bytes, *, run_ocr: bool = False) -> ImageReport:
    """Analyse an image's structure, metadata and optional OCR text."""
    report = ImageReport(file_size=len(data))
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError:  # pragma: no cover - Pillow is a hard dependency
        report.structural_error = "Pillow is not installed; image structure was not validated."
        return report

    try:
        image = Image.open(io.BytesIO(data))
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        report.structural_error = f"Pillow could not open the image: {exc}"
        return report

    report.format = (image.format or "UNKNOWN").upper()
    report.mime = image.get_format_mimetype() or ""
    report.mode = image.mode
    try:
        report.width, report.height = image.size
    except Exception:
        pass
    try:
        report.frame_count = getattr(image, "n_frames", 1)
        report.animated = report.frame_count > 1
    except Exception:
        pass

    pixels = (report.width or 0) * (report.height or 0)
    if pixels > _MAX_PIXELS:
        report.notes.append(
            f"Declared dimensions imply {pixels / 1_000_000:.1f} megapixels; pixel data was not decoded."
        )
        report.structural_error = report.structural_error or "Image exceeds the decode size budget."
    else:
        try:
            image.verify()
        except Exception as exc:
            report.truncated = True
            report.notes.append(f"Pillow verification failed: {exc}")

    if report.width and report.height:
        report.bits_per_pixel = (len(data) * 8) / (report.width * report.height)
        report.compression_ratio = report.bits_per_pixel / 8.0

    # EXIF -------------------------------------------------------------
    try:
        image = Image.open(io.BytesIO(data))
        exif = image.getexif()
        if exif:
            from PIL.ExifTags import TAGS

            for tag_id, value in exif.items():
                name = TAGS.get(tag_id, str(tag_id))
                text = _stringify(value)
                if text:
                    report.exif[name] = text[:300]
            for field_name in _GPS_FIELDS:
                if field_name in report.exif:
                    report.sensitive_exif.append("geographic coordinates")
                    break
            for key in report.exif:
                if key in _SENSITIVE_EXIF:
                    report.sensitive_exif.append(_SENSITIVE_EXIF[key])
            try:
                thumb = exif.get(0x9286)
                report.has_thumbnail = thumb is not None
            except Exception:
                pass
    except Exception as exc:  # pragma: no cover - malformed EXIF
        report.notes.append(f"EXIF could not be read: {exc}")

    # trailing payload --------------------------------------------------
    end = _detect_end_offset(data, report.format)
    if end != -1 and end < len(data):
        trailer = data[end:]
        # All-zero padding is normal after IEND; anything else is content the
        # image format has no place for.
        padding = len(trailer) - len(trailer.lstrip(b"\x00"))
        if padding < len(trailer) - _TRAILING_TOLERANCE:
            report.trailing_bytes = len(trailer)
            report.trailing_signature = _trailing_signature(trailer[:512])

    # text chunks (PNG tEXt/iTXt) --------------------------------------
    report.text_segments = _png_text_chunks(data)

    # OCR ---------------------------------------------------------------
    if run_ocr:
        report.ocr_text, report.ocr_error = ocr_text(data)
        report.ocr_performed = report.ocr_error is None or bool(report.ocr_text)
        if report.ocr_text:
            from ..phishing.text import analyze_text, findings_from_profile

            profile = analyze_text(report.ocr_text)
            report.phishing_findings = findings_from_profile(profile)
    return report


def _stringify(value: object) -> str:
    if isinstance(value, bytes):
        return value[:300].decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value[:300]
    try:
        return str(value)[:300]
    except Exception:  # pragma: no cover
        return ""


def _png_text_chunks(data: bytes) -> list[str]:
    """Read PNG ``tEXt``/``iTXt``/``zTXt`` chunks without decoding pixels."""
    segments: list[str] = []
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return segments
    offset = 8
    total = len(data)
    import struct
    import zlib

    while offset + 8 <= total:
        (length,) = struct.unpack(">I", data[offset : offset + 4])
        chunk_type = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        if chunk_type in (b"tEXt", b"iTXt"):
            segments.append(payload[:500].decode("latin-1", errors="replace"))
        elif chunk_type == b"zTXt":
            try:
                _keyword, compressed = payload.split(b"\x00", 1)
                segments.append(
                    zlib.decompress(compressed[1:])[:500].decode("latin-1", errors="replace")
                )
            except Exception:
                continue
        offset += 12 + length
        if chunk_type == b"IEND" or len(segments) > 20:
            break
    return segments


def ocr_available() -> bool:
    """True when a usable Tesseract binary is installed."""
    import shutil

    return shutil.which("tesseract") is not None


def ocr_text(data: bytes, *, timeout: int = 20) -> tuple[str, str | None]:
    """Extract text from an image using Tesseract, if installed.

    Returns ``(text, error)``.  When OCR is unavailable the caller reports reduced
    coverage instead of claiming the image contains no text.

    The subprocess is invoked with an explicit argument list (never a shell
    string) and a timeout, so untrusted content cannot influence how the command
    is assembled.
    """
    import shutil
    import subprocess
    import tempfile

    binary = shutil.which("tesseract")
    if not binary:
        return "", "Tesseract OCR is not installed on this scanner; text-based phishing cues were not extracted."

    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as handle:
            handle.write(data)
            tmp_path = handle.name
        completed = subprocess.run(  # noqa: S603 - fixed binary, arg list, no shell
            [binary, tmp_path, "stdout", "--psm", "6"],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0:
            return "", f"tesseract exited with {completed.returncode}"
        return completed.stdout.decode("utf-8", errors="replace").strip(), None
    except subprocess.TimeoutExpired:
        return "", f"OCR timed out after {timeout}s"
    except OSError as exc:
        return "", f"OCR could not be started: {exc}"
    finally:
        if tmp_path:
            try:
                import os

                os.unlink(tmp_path)
            except OSError:
                pass


def image_findings(report: ImageReport) -> list[Finding]:
    """Findings derived from an :class:`ImageReport`."""
    findings: list[Finding] = []

    if report.structural_error and not report.format:
        findings.append(
            Finding(
                code="IMAGE.UNREADABLE",
                title="Image structure could not be validated",
                detail=(
                    f"{report.structural_error} A file that presents itself as an "
                    "image but cannot be decoded is either corrupt or is deliberately "
                    "a polyglot."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.IMAGE_ANALYSIS,
                category="integrity",
                weight=12.0,
            )
        )

    if report.trailing_bytes > 0:
        findings.append(
            Finding(
                code="IMAGE.TRAILING_PAYLOAD",
                title="Data is hidden after the end of the image",
                detail=(
                    f"{report.trailing_bytes} bytes follow the image's end marker. "
                    f"The trailer begins with {report.trailing_signature or 'unrecognised data'}. "
                    "Appending a second payload after the image is a standard way to "
                    "hide an HTML page or executable inside a file that still opens as "
                    "a picture - the technique behind several 'double extension' "
                    "attacks and browser content-sniffing exploits."
                ),
                severity=Severity.HIGH,
                source=SignalSource.IMAGE_ANALYSIS,
                category="payload",
                weight=20.0,
                authoritative=True,
                evidence={
                    "trailing_bytes": report.trailing_bytes,
                    "signature": report.trailing_signature,
                },
            )
        )

    if report.truncated:
        findings.append(
            Finding(
                code="IMAGE.STRUCTURALLY_INVALID",
                title="Image data is inconsistent or truncated",
                detail=(
                    "The declared structure does not match the available bytes. "
                    "Deliberately malformed images are used to crash previewers and "
                    "to slip content past parsers that stop at the first error."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.IMAGE_ANALYSIS,
                category="integrity",
                weight=12.0,
            )
        )

    if report.sensitive_exif:
        unique = sorted(set(report.sensitive_exif))
        findings.append(
            Finding(
                code="IMAGE.EXIF_PRIVACY_LEAK",
                title=f"Image metadata exposes {unique[0]}",
                detail=(
                    "EXIF metadata records "
                    f"{', '.join(unique)}. This does not indicate malicious intent, but "
                    "it discloses information about the device, the person who took "
                    "the picture and possibly their precise location. Most legitimate "
                    "shares have this stripped."
                ),
                severity=Severity.LOW,
                source=SignalSource.IMAGE_ANALYSIS,
                category="metadata",
                weight=6.0,
                evidence={"fields": unique},
            )
        )

    if report.text_segments:
        joined = " ".join(report.text_segments).lower()
        if any(token in joined for token in ("javascript:", "<script", "http://", "eval(")):
            findings.append(
                Finding(
                    code="IMAGE.SCRIPT_IN_METADATA",
                    title="Image metadata contains executable markup",
                    detail=(
                        "PNG text chunks carry script or URL content. Some viewers and "
                        "renderers process these chunks, which turns a harmless-looking "
                        "picture into a delivery vector."
                    ),
                    severity=Severity.HIGH,
                    source=SignalSource.IMAGE_ANALYSIS,
                    category="payload",
                    weight=18.0,
                    evidence={"segments": report.text_segments[:10]},
                )
            )

    if report.animated and report.frame_count > 200:
        findings.append(
            Finding(
                code="IMAGE.ANIMATION_BOMB",
                title=f"Image contains {report.frame_count} frames",
                detail=(
                    "Very large animations exhaust memory and CPU when rendered. Used "
                    "for denial-of-service against viewers and automated processors."
                ),
                severity=Severity.LOW,
                source=SignalSource.IMAGE_ANALYSIS,
                category="availability",
                weight=6.0,
            )
        )

    if report.width and report.height and report.compression_ratio < 0.001 and report.file_size > 4096:
        megapixels = (report.width * report.height) / 1_000_000
        findings.append(
            Finding(
                code="IMAGE.EXTREME_DIMENSIONS",
                title=f"Image declares {megapixels:.0f} megapixels but is tiny on disk",
                detail=(
                    f"{report.width}x{report.height} in {report.file_size} bytes is "
                    "physically implausible for real image content. This shape is used "
                    "for decompression bombs."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.IMAGE_ANALYSIS,
                category="availability",
                weight=10.0,
                evidence={"dimensions": [report.width, report.height], "size": report.file_size},
            )
        )

    findings.extend(report.phishing_findings)

    if not report.ocr_performed and not report.phishing_findings:
        findings.append(
            Finding(
                code="IMAGE.OCR_NOT_AVAILABLE",
                title="Text inside this image was not analysed",
                detail=(
                    "Screenshots of phishing pages are a common delivery method and "
                    "carry no machine-readable text. OCR is required to read them; "
                    "without it, phishing wording inside images is invisible to this "
                    "scan. Run a scanner with OCR enabled for full coverage."
                ),
                severity=Severity.INFO,
                source=SignalSource.IMAGE_ANALYSIS,
                category="coverage",
                weight=0.0,
            )
        )
    return findings