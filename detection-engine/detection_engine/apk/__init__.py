"""Android package analysis.

Static analysis only.  CyberShield does not install, execute, or load a DEX
file from a package it analyses, and it does not contact any network endpoint it
finds.  Everything here is reading: the ZIP layout, ``AndroidManifest.xml``, the
signing certificates and the DEX string pool.

The package is split into four modules, each usable on its own:

``manifest``      identity, build configuration, components, permissions
``certificate``   who signed it, and what the signature proves
``code``          strings and API references found in the DEX
``analyzer``      the entry point that assembles the three

A required capability going missing is never allowed to look like a clean
result: :func:`ApkAnalyzer.analyze_bytes` marks the result incomplete and the
risk engine turns that into an UNKNOWN verdict.
"""

from __future__ import annotations

from .analyzer import (
    ApkAnalysis,
    ApkAnalysisConfig,
    ApkAnalyzer,
    analyze_apk_bytes,
    analyze_apk_path,
    androguard_available,
)
from .certificate import CertificateInfo, SigningReport, analyze_certificates
from .code import StringEvidence, redact, scan_strings
from .manifest import ManifestInfo, PermissionReview, review_permissions

__all__ = [
    "ApkAnalysis",
    "ApkAnalysisConfig",
    "ApkAnalyzer",
    "CertificateInfo",
    "ManifestInfo",
    "PermissionReview",
    "SigningReport",
    "StringEvidence",
    "analyze_apk_bytes",
    "analyze_apk_path",
    "analyze_certificates",
    "androguard_available",
    "redact",
    "review_permissions",
    "scan_strings",
]