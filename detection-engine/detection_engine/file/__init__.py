"""File analysis: identity, type detection, structure, entropy, signatures.

The orchestrator is :class:`FileAnalyzer`; everything else in this package is a
focused step it calls.  The steps are individually importable so a caller that
only needs, say, PDF structure does not have to instantiate the whole pipeline.
"""

from __future__ import annotations

from . import archive, entropy, hashing, image, magic, office, pdf
from .analyzer import (
    HEADER_BYTES,
    STRUCTURAL_LIMIT,
    Coverage,
    FileAnalysisConfig,
    FileAnalyzer,
    analyze_bytes,
    analyze_path,
)
from .entropy import EntropyReport, analyze_entropy, entropy_findings, shannon_entropy
from .hashing import FileHashes, hash_bytes, hash_file
from .image import ImageReport, analyze_image, image_findings, ocr_available
from .magic import TypeInfo, detect_type
from .office import OfficeReport, analyze_office, office_findings
from .pdf import PdfReport, analyze_pdf, extract_pdf_text, pdf_findings

__all__ = [
    "HEADER_BYTES",
    "STRUCTURAL_LIMIT",
    "Coverage",
    "EntropyReport",
    "FileAnalysisConfig",
    "FileAnalyzer",
    "FileHashes",
    "ImageReport",
    "OfficeReport",
    "PdfReport",
    "TypeInfo",
    "analyze_bytes",
    "analyze_entropy",
    "analyze_image",
    "analyze_office",
    "analyze_path",
    "analyze_pdf",
    "archive",
    "detect_type",
    "entropy",
    "entropy_findings",
    "extract_pdf_text",
    "hashing",
    "hash_bytes",
    "hash_file",
    "image",
    "image_findings",
    "magic",
    "ocr_available",
    "office",
    "office_findings",
    "pdf",
    "pdf_findings",
    "shannon_entropy",
]