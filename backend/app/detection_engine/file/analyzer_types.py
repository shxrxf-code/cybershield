"""Shared file-analysis result types.

Separated from the analysers so that :mod:`app.detection_engine.file.magic` can
describe what a file *is* without importing the document, image and archive
analysers that consume that information.
"""

from __future__ import annotations

from enum import Enum


class FileKind(str, Enum):
    """Coarse classification of a file, derived from content signatures."""

    PDF = "pdf"
    ZIP = "zip"
    ARCHIVE = "archive"
    IMAGE = "image"
    DOCUMENT = "document"
    APK = "apk"
    OLE2 = "ole2"
    EXECUTABLE = "executable"
    EMAIL = "email"
    TEXT = "text"
    BINARY = "binary"
    DATABASE = "database"
    UNKNOWN = "unknown"

    @property
    def is_analysable(self) -> bool:
        return self not in (FileKind.UNKNOWN,)

    @property
    def is_container(self) -> bool:
        """Containers hold other files and can hide their real content."""
        return self in (FileKind.ZIP, FileKind.ARCHIVE)


class DocumentFormat(str, Enum):
    """Office/document formats the analyser understands specifically."""

    PDF = "pdf"
    DOCX = "docx"
    XLSX = "xlsx"
    PPTX = "pptx"
    DOC = "doc"
    XLS = "xls"
    PPT = "ppt"
    RTF = "rtf"
    ODT = "odt"
    ODS = "ods"
    ODP = "odp"
    TXT = "txt"
    HTML = "html"
    XML = "xml"
    UNKNOWN = "unknown"


class ImageFormat(str, Enum):
    """Image formats with dedicated metadata analysis."""

    PNG = "png"
    JPEG = "jpeg"
    GIF = "gif"
    WEBP = "webp"
    TIFF = "tiff"
    BMP = "bmp"
    ICO = "ico"
    SVG = "svg"
    HEIC = "heic"
    AVIF = "avif"
    UNKNOWN = "unknown"