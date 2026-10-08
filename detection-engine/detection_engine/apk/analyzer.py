"""Android package analysis.

Entry points
------------
:func:`analyze_apk_bytes` and :func:`analyze_apk_path` return a
:class:`~detection_engine.models.AnalysisResult` ready for the risk engine.

Honest coverage
---------------
APK analysis depends on ``androguard``, an optional dependency.  When it is
absent the analyser returns a result whose coverage is *incomplete* - which the
risk engine turns into an UNKNOWN verdict rather than SAFE.  Reporting a
package as clean because the parser was not installed would be the single most
dangerous failure mode this system could have, so it is explicitly prevented.

What this analyser never does
-----------------------------
It never installs, runs, or loads a DEX file.  It never contacts a network
endpoint found inside a package.  It never claims that a package is safe, only
that it found no evidence of abuse, at the confidence it reports.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..exceptions import MalformedObjectError
from ..models import AnalysisResult, Finding, ObjectType, Severity, SignalSource
from ..scoring import RiskEngine
from .certificate import SigningReport, analyze_certificates, certificate_findings
from .code import StringEvidence, scan_strings, string_findings
from .manifest import ManifestInfo, analyze_manifest, manifest_findings, review_permissions

__all__ = [
    "ApkAnalysis",
    "ApkAnalysisConfig",
    "ApkAnalyzer",
    "analyze_apk_bytes",
    "analyze_apk_path",
    "androguard_available",
]

#: Refuse to open anything that is not plausibly a ZIP, before parsing it.
_MIN_APK_SIZE = 64

#: Keys an Android app should never carry, because they are plaintext.
_WEAK_BACKUP_KEYS = frozenset({"password", "passwd", "pwd"})


def androguard_available() -> bool:
    """True when ``androguard`` can be imported."""
    try:
        import androguard.core.apk  # noqa: F401
    except Exception:
        return False
    return True


@dataclass(slots=True)
class ApkAnalysisConfig:
    """Tunables for :class:`ApkAnalyzer`."""

    #: Read the DEX string pool and resource table.  Turning this off leaves
    #: manifest and certificate analysis only.
    read_code: bool = True
    #: Cap on entries read from the archive, to bound memory on a zip bomb.
    max_archive_entries: int = 4000
    #: Cap on total decompressed bytes inspected.
    max_total_uncompressed: int = 64 * 1024 * 1024
    #: Cap on strings pulled out of the DEX pool.
    max_strings: int = 200_000


@dataclass(slots=True)
class ApkAnalysis:
    """Everything the APK pipeline produced."""

    manifest: ManifestInfo = field(default_factory=ManifestInfo)
    signing: SigningReport = field(default_factory=SigningReport)
    strings: StringEvidence = field(default_factory=StringEvidence)
    entries: list[str] = field(default_factory=list)
    dex_files: list[str] = field(default_factory=list)
    native_libraries: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    engines_ran: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    #: Capability -> assessment, for the report's permission panel.
    permissions: dict[str, object] = field(default_factory=dict)
    #: True when the entry list was truncated at the configured cap.
    entries_truncated: bool = False
    #: True when a required capability was missing, forcing UNKNOWN.
    incomplete: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "manifest": self.manifest.to_dict(),
            "signing": self.signing.to_dict(),
            "strings": self.strings.to_dict(),
            "permissions": self.permissions,
            "entries": self.entries[:200],
            "entries_truncated": self.entries_truncated,
            "dex_files": self.dex_files[:20],
            "native_libraries": self.native_libraries[:40],
            "engines_ran": self.engines_ran,
            "skipped": self.skipped,
            "incomplete": self.incomplete,
        }


class ApkAnalyzer:
    """Static analysis of an Android package."""

    def __init__(
        self,
        config: ApkAnalysisConfig | None = None,
        *,
        risk_engine: RiskEngine | None = None,
    ) -> None:
        self.config = config or ApkAnalysisConfig()
        #: Scoring is injectable so a caller can share one engine across scans,
        #: and so tests can inspect contributions without re-deriving them.
        self.risk_engine = risk_engine or RiskEngine()

    # ------------------------------------------------------------------ #
    # public API
    # ------------------------------------------------------------------ #

    def analyze_bytes(
        self, data: bytes, filename: str | None = None
    ) -> AnalysisResult:
        """Analyse APK *data* and return a scored result."""
        analysis = self._analyze(data)
        result = AnalysisResult(
            object_type=ObjectType.APK,
            object_name=filename or analysis.manifest.package or "application.apk",
        )
        result.findings.extend(analysis.findings)
        result.engines_ran.extend(analysis.engines_ran)
        # Same coverage shape the file analyser publishes, so the risk engine and
        # the API layer read one format regardless of object type.
        result.metadata["coverage"] = {
            "ran": list(analysis.engines_ran),
            "skipped": dict(analysis.skipped),
            "not_applicable": [],
            "disabled": [],
            "complete": not analysis.incomplete,
        }
        result.metadata["apk"] = analysis.to_dict()
        result.incomplete = analysis.incomplete or result.incomplete

        package = analysis.manifest.package
        if package:
            result.add_indicator("package", package, context="manifest package name")
        primary = analysis.signing.primary
        if primary:
            if primary.sha256:
                result.add_indicator(
                    "certificate_sha256", primary.sha256, context="signing certificate"
                )
            cn = primary.subject_common_name
            if cn:
                result.add_indicator("certificate_cn", cn, context="signing certificate")
        for url in analysis.strings.urls[:30]:
            result.add_indicator("url", url, context="string in package")
        for address in analysis.strings.ip_addresses[:30]:
            result.add_indicator("ip", address, context="string in package")
        for domain in analysis.strings.domains[:30]:
            result.add_indicator("domain", domain, context="string in package")
        # Scoring happens here, not in the caller.  ``incomplete`` must already
        # be set, because it is what turns insufficient coverage into UNKNOWN.
        self.risk_engine.finalise(result)
        return result

    def analyze_path(self, path: str | Path, *, filename: str | None = None) -> AnalysisResult:
        """Analyse the APK at *path*.

        The path is only read.  Nothing is written, extracted to disk, installed
        or executed.
        """
        target = Path(path)
        try:
            data = target.read_bytes()
        except OSError as exc:
            raise MalformedObjectError(f"The file could not be read: {exc}") from exc
        return self.analyze_bytes(data, filename or target.name)

    # ------------------------------------------------------------------ #
    # internals
    # ------------------------------------------------------------------ #

    def _analyze(self, data: bytes) -> ApkAnalysis:
        analysis = ApkAnalysis()

        if len(data) < _MIN_APK_SIZE:
            analysis.findings.append(
                Finding(
                    code="APK.TOO_SMALL",
                    title="File is too small to be an Android package",
                    detail=(
                        f"The file is {len(data)} bytes. The smallest possible APK "
                        "is several kilobytes. This is likely a renamed file rather "
                        "than a package, and it was not analysed as one."
                    ),
                    severity=Severity.MEDIUM,
                    source=SignalSource.APK_MANIFEST,
                    category="structure",
                    weight=12.0,
                    evidence={"size": len(data)},
                )
            )
            # Incomplete, deliberately.  Nothing about this object was analysed,
            # so the coverage report must not imply that it was.  "It is too
            # small to be a package" is a statement about size, not about safety,
            # and a verdict drawn from it would be an all-clear nobody earned.
            analysis.incomplete = True
            analysis.skipped["apk_analysis"] = (
                "the file is too small to be an Android package, so no manifest, "
                "code or certificate analysis was possible"
            )
            analysis.engines_ran.append("apk_structure")
            return analysis

        self._read_archive(data, analysis)

        if not androguard_available():
            analysis.skipped["apk_manifest"] = (
                "androguard is not installed, so AndroidManifest.xml could not be "
                "decoded and DEX code could not be read"
            )
            analysis.skipped["apk_code"] = (
                "androguard is not installed, so the DEX string pool could not be read"
            )
            analysis.skipped["apk_certificate"] = (
                "androguard is not installed, so signing certificates could not be read"
            )
            analysis.incomplete = True
            analysis.findings.append(
                Finding(
                    code="APK.ANALYSIS_UNAVAILABLE",
                    title="Android analysis could not run",
                    detail=(
                        "The file is a ZIP archive of the shape Android uses, but "
                        "androguard is not installed in this deployment. No "
                        "manifest, code or certificate analysis was performed. "
                        "CyberShield cannot say anything about this package - it "
                        "is reporting that it was unable to look, not that it "
                        "found nothing."
                    ),
                    severity=Severity.INFO,
                    source=SignalSource.APK_MANIFEST,
                    category="coverage",
                    weight=0.0,
                    evidence={"size": len(data)},
                )
            )
            return analysis

        try:
            from androguard.core.apk import APK
        except Exception as exc:  # pragma: no cover - import already checked
            analysis.skipped["apk_manifest"] = f"androguard import failed: {exc}"
            analysis.incomplete = True
            return analysis

        try:
            # ``raw=True`` makes androguard treat the argument as the archive
            # bytes rather than a path, so no temporary file is ever created for
            # an upload.
            apk = APK(data, raw=True, testzip=False)
        except Exception as exc:
            analysis.skipped["apk_manifest"] = f"APK could not be opened: {exc}"
            analysis.findings.append(
                Finding(
                    code="APK.STRUCTURE_BROKEN",
                    title="Package structure could not be parsed",
                    detail=(
                        f"andruguard could not open the archive: {exc}. A file that "
                        "claims to be an APK but cannot be opened by the platform's "
                        "own parser is either corrupt, deliberately malformed to "
                        "confuse analysis, or not an APK."
                    ),
                    severity=Severity.MEDIUM,
                    source=SignalSource.APK_MANIFEST,
                    category="structure",
                    weight=16.0,
                    evidence={"error": str(exc)[:300]},
                )
            )
            analysis.incomplete = True
            return analysis

        self._analyze_manifest(apk, analysis)
        self._analyze_signing(apk, analysis)
        if self.config.read_code:
            self._analyze_code(apk, data, analysis)
        else:
            analysis.skipped["apk_code"] = "code analysis was disabled for this scan"

        return analysis

    # ---- archive ------------------------------------------------------ #

    def _read_archive(self, data: bytes, analysis: ApkAnalysis) -> None:
        """List the archive so analysis can proceed even if androguard fails."""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = archive.infolist()
                analysis.entries = [info.filename for info in infos[: self.config.max_archive_entries]]
                analysis.dex_files = [
                    name for name in analysis.entries
                    if name.endswith(".dex") and not name.endswith("/")
                ]
                analysis.native_libraries = [
                    name for name in analysis.entries
                    if name.endswith(".so") and not name.endswith("/")
                ]
                analysis.engines_ran.append("apk_archive")
                if len(infos) > self.config.max_archive_entries:
                    analysis.entries_truncated = True
                total = sum(info.file_size for info in infos)
                if total > self.config.max_total_uncompressed:
                    analysis.findings.append(
                        Finding(
                            code="APK.LARGE_EXPANSION",
                            title="Package expands to an unusually large size",
                            detail=(
                                f"The archive declares {total / 1_048_576:.1f} MiB "
                                "uncompressed. Content compressed this heavily is "
                                "usually a packed or encrypted payload rather than "
                                "application resources, which is also what makes a "
                                "zip bomb possible."
                            ),
                            severity=Severity.MEDIUM,
                            source=SignalSource.APK_MANIFEST,
                            category="structure",
                            weight=12.0,
                            evidence={
                                "declared_uncompressed_bytes": total,
                                "entries": len(infos),
                            },
                        )
                    )
        except zipfile.BadZipFile as exc:
            analysis.entries = []
            # Not a ZIP means the file is not an Android package at all.  That is
            # a conclusion about identity, not about malice, so it must not push
            # the verdict to MALICIOUS: a renamed document would otherwise be
            # reported as malware.  Marking it incomplete instead makes the risk
            # engine answer UNKNOWN, which is the honest result.
            analysis.incomplete = True
            analysis.skipped["apk_analysis"] = (
                "the file is not a ZIP archive, so it is not an Android package"
            )
            analysis.findings.append(
                Finding(
                    code="APK.NOT_A_ZIP",
                    title="File is not an Android package",
                    detail=(
                        f"{exc}. Android packages are ZIP archives, so this file "
                        "cannot be one and was not analysed as an application. "
                        "This says nothing about whether the file is dangerous - "
                        "only that it is not what the Android package format looks "
                        "like, which points at a misidentified or truncated file "
                        "rather than at an attack."
                    ),
                    severity=Severity.MEDIUM,
                    source=SignalSource.APK_MANIFEST,
                    category="structure",
                    weight=10.0,
                    evidence={"error": str(exc)[:200]},
                )
            )

    # ---- manifest ----------------------------------------------------- #

    def _analyze_manifest(self, apk: Any, analysis: ApkAnalysis) -> None:
        try:
            xml_root = apk.get_android_manifest_xml()
        except Exception as exc:
            analysis.skipped["apk_manifest"] = f"manifest could not be decoded: {exc}"
            analysis.incomplete = True
            return

        info = analyze_manifest(xml_root)
        analysis.manifest = info
        review = review_permissions(info)
        analysis.findings.extend(manifest_findings(info, review))
        analysis.engines_ran.append("apk_manifest")
        analysis.engines_ran.append("apk_permissions")
        analysis.permissions = review.to_dict()

        if not info.parse_errors:
            analysis.engines_ran.append("apk_sdk")

    # ---- signing ------------------------------------------------------ #

    def _analyze_signing(self, apk: Any, analysis: ApkAnalysis) -> None:
        report = analyze_certificates(apk)
        analysis.signing = report
        analysis.findings.extend(
            certificate_findings(
                report, is_android_package=bool(analysis.manifest.package)
            )
        )
        analysis.engines_ran.append("apk_certificate")

        if report.signed and report.primary is None:
            # Signed but identity unreadable: a real gap in what we can conclude.
            analysis.skipped["apk_certificate_identity"] = (
                "the signing certificate could not be parsed"
            )

        # Integrity verification is the check that catches a repackaged APK, and
        # this build cannot perform it.  Recorded as skipped so the coverage
        # report shows the gap; it does not make the result incomplete, because
        # every other part of the analysis did run and the missing check can
        # only ever *raise* a score, never lower one.
        analysis.skipped["apk_integrity_verification"] = report.verification_detail

    # ---- code --------------------------------------------------------- #

    def _analyze_code(self, apk: Any, data: bytes, analysis: ApkAnalysis) -> None:
        strings: list[str] = []
        errors: list[str] = []

        for dex_name in analysis.dex_files[:20] or ["classes.dex"]:
            try:
                items = apk.get_dex()
            except Exception as exc:
                errors.append(f"{dex_name}: {exc}")
                break
            if isinstance(items, dict):
                for value in items.values():
                    if hasattr(value, "get_strings"):
                        strings.extend(value.get_strings())
            if len(strings) >= self.config.max_strings:
                break

        if not strings:
            try:
                for dex_name in analysis.dex_files[:5]:
                    with zipfile.ZipFile(io.BytesIO(data)) as archive:
                        raw = archive.read(dex_name)
                    # A DEX string pool is a length-prefixed UTF-8 blob; the
                    # printable runs are a good enough proxy when androguard
                    # cannot parse the file.
                    strings.extend(_salvage_dex_strings(raw))
            except Exception as exc:
                errors.append(str(exc))

        evidence = scan_strings(
            strings[: self.config.max_strings],
            raw_bytes=data,
            asset_names=[
                name for name in analysis.entries
                if name.startswith("assets/") and not name.endswith("/")
            ],
            dex_names=analysis.dex_files,
        )
        if not evidence.strings_available:
            analysis.skipped["apk_code"] = (
                "the DEX string pool could not be read"
                + (f" ({'; '.join(errors[:2])})" if errors else "")
            )
            analysis.incomplete = True
        analysis.strings = evidence
        analysis.findings.extend(string_findings(evidence, analysis.manifest.package))
        analysis.engines_ran.append("apk_code")


def _salvage_dex_strings(raw: bytes, *, limit: int = 50_000) -> list[str]:
    """Recover printable strings from a DEX when it cannot be fully parsed.

    Used only when androguard declines the file - which is itself worth
    reporting.  Marked ``strings_available = True`` would overstate the coverage,
    so the caller checks :attr:`StringEvidence.strings_available` and reports the
    gap.  This function exists to salvage *some* signal while still being honest
    that the DEX was not parsed.
    """
    import re

    out: list[str] = []
    for match in re.finditer(rb"[\x20-\x7e]{4,200}", raw):
        out.append(match.group(0).decode("ascii"))
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------- #
# module-level convenience
# ---------------------------------------------------------------------- #

_default: ApkAnalyzer | None = None


def analyze_apk_bytes(
    data: bytes, filename: str | None = None, **kwargs: Any
) -> AnalysisResult:
    """Analyse APK bytes with the shared default :class:`ApkAnalyzer`."""
    global _default
    if _default is None:
        _default = ApkAnalyzer()
    if kwargs:
        _default = ApkAnalyzer(ApkAnalysisConfig(**kwargs))
    return _default.analyze_bytes(data, filename)


def analyze_apk_path(path: str | Path, **kwargs: Any) -> AnalysisResult:
    """Analyse the APK at *path* with the shared default :class:`ApkAnalyzer`."""
    return analyze_apk_bytes(Path(path).read_bytes(), Path(path).name, **kwargs)