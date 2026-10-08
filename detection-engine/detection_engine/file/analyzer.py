"""File analysis orchestration.

``FileAnalyzer`` is the single entry point for scanning any file a user shares.
It owns the *pipeline order* and the *coverage bookkeeping*; each step lives in
its own module.

Pipeline
--------
1. **Identity** - hashes and the true type, detected from content.  The
   extension is recorded as an untrusted claim, never as the answer.
2. **Entropy** - compression and packing indicators, interpreted against the
   detected format so a PNG does not get flagged for looking random.
3. **Structure** - Office, PDF, image or archive parsing, depending on type.
   This is where embedded payloads, active content and hidden text surface.
4. **Text** - when the document yields readable text, the social-engineering
   analyser runs over it.
5. **Signatures** - ClamAV and YARA, over the raw bytes.
6. **Archive members** - for containers, each member is signature-scanned too.

Degradation policy
------------------
Every optional dependency is probed and its absence is recorded in
``metadata['coverage']``.  When a capability is missing the analyser emits an
INFO-severity finding so the user can see what was *not* checked.  Silent
partial scans are the main way a security tool misleads the people relying on
it, so they are treated as a bug rather than a tradeoff.

What this module deliberately does not do
------------------------------------------
It never executes, detonates or emulates the file.  It never renders an image or
renders a document.  Every step is static analysis of bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..models import AnalysisResult, Finding, ObjectType, Severity, SignalSource
from ..scanners.clamav import ClamAvScanner
from ..scanners.clamav import get_scanner as get_clamav
from ..yara.engine import YaraEngine
from ..yara.engine import get_engine as get_yara
from . import archive as archive_mod
from . import entropy as entropy_mod
from . import hashing as hashing_mod
from . import magic as magic_mod
from . import office as office_mod
from .image import analyze_image, image_findings
from .pdf import analyze_pdf, pdf_findings

__all__ = ["FileAnalyzer", "FileAnalysisConfig", "Coverage", "analyze_bytes", "analyze_path"]


#: Files above this size skip the structural parsers.  The signature engines
#: still see the whole file.  The skip is reported, never hidden.
STRUCTURAL_LIMIT = 40 * 1024 * 1024

#: Bytes of the file handed to the type detector.
HEADER_BYTES = 4096


@dataclass(slots=True)
class Coverage:
    """Which capabilities actually ran, for honest confidence reporting.

    The distinction that matters is between a step that was **skipped** because
    the capability was missing and a step that was **not applicable** to this
    file.  A plain text file has no document structure to parse, and that is not
    a gap in the scan.  Only genuinely missing capability counts towards
    ``incomplete``, which is what drives the UNKNOWN verdict.
    """

    ran: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    reasons: dict[str, str] = field(default_factory=dict)
    not_applicable: list[str] = field(default_factory=list)
    na_reasons: dict[str, str] = field(default_factory=dict)
    #: Steps switched off by configuration, as opposed to unavailable ones.
    disabled: list[str] = field(default_factory=list)

    def note(self, step: str) -> None:
        if step not in self.ran:
            self.ran.append(step)

    def skip(self, step: str, reason: str) -> None:
        """Record a step that should have run but could not.

        This marks the scan incomplete, which is the honest outcome: a capability
        the operator expects to be available was not.
        """
        if step not in self.skipped:
            self.skipped.append(step)
            self.reasons[step] = reason

    def na(self, step: str, reason: str) -> None:
        """Record a step that does not apply to this object at all."""
        if step not in self.not_applicable:
            self.not_applicable.append(step)
            self.na_reasons[step] = reason

    def turn_off(self, step: str) -> None:
        """Record a step deliberately disabled by configuration.

        A disabled engine lowers confidence but does not make the scan
        *incomplete*: the operator chose this configuration, so the result is
        still a real verdict rather than an absence of evidence.
        """
        if step not in self.disabled:
            self.disabled.append(step)

    @property
    def complete(self) -> bool:
        return not self.skipped

    @property
    def ratio(self) -> float:
        total = len(self.ran) + len(self.skipped) + len(self.disabled)
        return len(self.ran) / total if total else 1.0

    def to_dict(self) -> dict[str, object]:
        return {
            "ran": sorted(self.ran),
            "skipped": sorted(self.skipped),
            "reasons": self.reasons,
            "not_applicable": sorted(self.not_applicable),
            "na_reasons": self.na_reasons,
            "disabled": sorted(self.disabled),
            "complete": self.complete,
            "ratio": round(self.ratio, 3),
        }


@dataclass(slots=True)
class FileAnalysisConfig:
    """Tunables for :class:`FileAnalyzer`.

    The defaults are the ones used in production.  Tests and the offline CLI
    narrow them so a scan stays fast.
    """

    clamav: bool = True
    yara: bool = True
    #: Extract document text and run the social-engineering analyser on it.
    extract_text: bool = True
    #: Run OCR on images.  Needs ``tesseract``; off by default because it is slow.
    ocr: bool = False
    #: Signature-scan each archive member.
    scan_archive_members: bool = True
    #: Cap on members extracted from one container.
    max_archive_members: int = 200
    #: Per-member read cap.
    max_member_bytes: int = 20 * 1024 * 1024
    #: Filename used when the caller supplies none.
    default_name: str = "shared file"


class FileAnalyzer:
    """Static, non-executing analysis of an arbitrary file."""

    def __init__(
        self,
        config: FileAnalysisConfig | None = None,
        *,
        clamav: ClamAvScanner | None = None,
        yara: YaraEngine | None = None,
    ) -> None:
        self.config = config or FileAnalysisConfig()
        self._clamav = clamav if clamav is not None else get_clamav()
        self._yara = yara if yara is not None else get_yara()

    # ------------------------------------------------------------------ #
    # entry points
    # ------------------------------------------------------------------ #

    def analyze_bytes(
        self,
        data: bytes,
        filename: str | None = None,
        *,
        declared_mime: str | None = None,
    ) -> AnalysisResult:
        """Analyse in-memory file bytes."""
        name = filename or self.config.default_name
        coverage = Coverage()
        header = data[:HEADER_BYTES]
        result = AnalysisResult(
            object_type=magic_mod.detect_type(header, filename=name).object_type,
            object_name=name,
        )
        result.metadata["size_bytes"] = len(data)

        # ---- 1. identity and true type ----------------------------- #
        hashes = hashing_mod.hash_bytes(data)
        result.metadata["hashes"] = hashes.to_dict()
        coverage.note("hashing")
        for kind, value in (("sha256", hashes.sha256), ("sha1", hashes.sha1), ("md5", hashes.md5)):
            if value:
                result.add_indicator(f"{kind}_hash", value, context="computed from file content")

        info = magic_mod.detect_type(
            header, filename=name, declared_mime=declared_mime, full_data=data
        )
        result.metadata["type_detection"] = info.to_dict()
        coverage.note("content_type_detection")
        result.object_type = info.object_type
        if info.libmagic_mime or info.magic_mime:
            result.add_indicator(
                "mime_type",
                info.libmagic_mime or info.magic_mime or "unknown",
                context="detected from file content; the extension is not trusted",
            )
        result.engines_ran.append("file_identity")

        # ``magic`` already knows how to explain an extension/content mismatch,
        # and it has the extension table the other modules share.
        result.extend(magic_mod.findings_for_type(info, size=len(data)))

        # ---- 2. entropy -------------------------------------------- #
        ent = entropy_mod.analyze_entropy(data)
        result.metadata["entropy"] = ent.to_dict()
        coverage.note("entropy")
        result.extend(entropy_mod.entropy_findings(ent, family=info.detected_family, object_type=info.object_type.value))

        # ---- 3. structure ------------------------------------------ #
        oversize = len(data) > STRUCTURAL_LIMIT
        family = info.detected_family
        is_ooxml = family in ("ooxml", "opendocument")
        is_ole2 = family == "ole2"
        is_pdf = family == "pdf" or data[:5] == b"%PDF-"
        is_image = family in ("png", "jpeg", "gif", "webp", "tiff", "bmp", "heic")
        is_archive = archive_mod.is_archive(data)

        if oversize:
            coverage.skip(
                "document_structure",
                f"the file is {len(data) / 1_048_576:.1f} MB, above the "
                f"{STRUCTURAL_LIMIT // 1_048_576} MB limit for structural parsing; "
                "the signature engines still scanned the whole file",
            )
        elif is_ooxml or is_ole2:
            report = office_mod.analyze_office(data, filename=name)
            result.metadata["office"] = report.to_dict()
            coverage.note("office_structure")
            result.extend(office_mod.office_findings(report, filename=name))
            self._add_office_indicators(result, report)
            if self.config.extract_text and report.text_chars:
                self._analyze_text(result, report.text, origin="Office document")
            elif self.config.extract_text:
                coverage.skip(
                    "office_text",
                    "no text layer could be extracted; the document may be image-only",
                )
        elif is_pdf:
            report = analyze_pdf(data)
            result.metadata["pdf"] = report.to_dict()
            coverage.note("pdf_structure")
            result.extend(pdf_findings(report))
            for url in report.urls[:50]:
                result.add_indicator("url", url, context="URL found inside the PDF")
            if self.config.extract_text and report.text_chars:
                self._analyze_text(result, report.text, origin="PDF document")
            elif self.config.extract_text:
                coverage.skip(
                    "pdf_text",
                    "the PDF has no extractable text layer, which usually means it is "
                    "a scanned image; phishing wording inside it was not analysed",
                )
        elif is_image:
            report = analyze_image(data, run_ocr=self.config.ocr)
            result.metadata["image"] = report.to_dict()
            coverage.note("image_structure")
            result.extend(image_findings(report))
        elif is_archive:
            result.extend(self._analyze_archive(result, data, name, coverage))
        else:
            # Not a gap: a text or raw-binary file simply has no container
            # structure to parse.  Counting this as skipped would wrongly mark
            # every text scan as incomplete.
            coverage.na(
                "document_structure",
                f"content type '{family or info.object_type.value}' has no "
                "container structure to parse",
            )

        # ---- 4. signatures ----------------------------------------- #
        result.extend(self._run_signatures(data, name, coverage))

        # ---- 5. archive members ------------------------------------ #
        if is_archive and self.config.scan_archive_members and not oversize:
            result.extend(self._scan_archive_members(data, name, coverage, family))
        elif is_archive and self.config.scan_archive_members:
            coverage.skip("archive_members", "file is above the structural-analysis size limit")

        result.metadata["coverage"] = coverage.to_dict()
        result.engines_ran = list(dict.fromkeys(result.engines_ran))
        result.incomplete = not coverage.complete
        return result

    def analyze_path(
        self, path: str | Path, *, filename: str | None = None
    ) -> AnalysisResult:
        """Analyse a file on disk.

        The path is used only to read bytes; nothing is written, executed or
        resolved outside the caller's chosen directory.
        """
        target = Path(path)
        return self.analyze_bytes(target.read_bytes(), filename=filename or target.name)

    # ------------------------------------------------------------------ #
    # steps
    # ------------------------------------------------------------------ #

    def _run_signatures(self, data: bytes, name: str, coverage: Coverage) -> list[Finding]:
        findings: list[Finding] = []

        if self.config.clamav:
            findings.extend(self._clamav.findings(data, object_name=name))
            if self._clamav.status().available:
                coverage.note("clamav")
            else:
                # ClamAV missing is a genuine gap: the operator expects an
                # antivirus engine to be present.
                coverage.skip("clamav", self._clamav.status().message)
        else:
            coverage.turn_off("clamav")
            findings.append(
                Finding(
                    code="CLAMAV.DISABLED",
                    title="Antivirus scanning was turned off for this scan",
                    detail=(
                        "This scanner is configured not to run ClamAV. The verdict "
                        "therefore rests on structural and heuristic evidence only, and "
                        "its confidence has been reduced to reflect that."
                    ),
                    severity=Severity.INFO,
                    source=SignalSource.CLAMAV,
                    category="coverage",
                    weight=0.0,
                )
            )

        if self.config.yara:
            findings.extend(self._yara.findings(data, source_label="file"))
            if self._yara.available:
                coverage.note("yara")
            else:
                coverage.skip(
                    "yara",
                    "; ".join(self._yara.status().errors) or "no rules compiled",
                )
        else:
            coverage.turn_off("yara")

        return findings

    def _analyze_text(self, result: AnalysisResult, text: str, *, origin: str) -> None:
        """Run the social-engineering analyser over extracted document text."""
        from ..phishing.text import analyze_text, findings_from_profile

        profile = analyze_text(text)
        summary = profile.to_dict()
        summary.update({"origin": origin, "characters": len(text)})
        result.metadata.setdefault("text_analysis", {})["summary"] = summary
        findings = findings_from_profile(profile)
        for finding in findings:
            finding.detail = f"[{origin}] {finding.detail}"
            finding.source = finding.source
        result.extend(findings)
        result.engines_ran.append("phishing_text")

    def _add_office_indicators(
        self, result: AnalysisResult, report: office_mod.OfficeReport
    ) -> None:
        for url in report.urls[:100]:
            result.add_indicator("url", url, context="URL inside the Office document")
        for relationship in report.external_relationships[:50]:
            target = relationship.get("target", "")
            if target.startswith(("http://", "https://")):
                result.add_indicator("url", target, context="external document relationship")
        for marker in report.macro_markers[:10]:
            result.add_indicator("macro_marker", marker, context="Office macro detection")

    def _analyze_archive(
        self, result: AnalysisResult, data: bytes, name: str, coverage: Coverage
    ) -> list[Finding]:
        report = archive_mod.analyze_archive(data)
        result.metadata["archive"] = report.to_dict()
        coverage.note("archive_structure")
        for member in report.members[:100]:
            result.add_indicator(
                "archive_member",
                member.name,
                context=f"{report.format} entry, {member.compressed_size} -> {member.file_size} bytes",
            )
        for url in office_mod.extract_urls(data)[:100]:
            result.add_indicator("url", url, context="URL inside the archive")
        return archive_mod.archive_findings(report, object_type=result.object_type.value)

    def _scan_archive_members(
        self, data: bytes, name: str, coverage: Coverage, family: str = ""
    ) -> list[Finding]:
        """Signature-scan every decompressed member, bounded by safety caps."""
        findings: list[Finding] = []
        scanned = 0
        skipped_oversize = 0
        budget = self.config.max_member_bytes

        if family in ("zip", "ooxml", "jar"):
            try:
                members = list(
                    archive_mod.iter_archive(
                        data, max_members=self.config.max_archive_members
                    )
                )
            except (ValueError, OSError, RuntimeError) as exc:
                coverage.skip("archive_members", f"the archive could not be expanded: {exc}")
                return findings
        elif family in ("tar", "gzip", "bzip2"):
            members = list(_iter_tar_members(data, self.config.max_archive_members))
        else:
            # 7z, xz, zstd and friends are listed and measured by
            # ``analyze_archive`` but their entries are not expanded.  Saying so
            # beats implying they were.
            coverage.na(
                "archive_members",
                f"member-level scanning is implemented for ZIP and TAR families; "
                f"this '{family}' container's listing was analysed but its entries "
                "were not expanded",
            )
            return findings

        for member_name, payload in members:
            if not payload:
                skipped_oversize += 1
                continue
            scanned += 1
            label = f"{name}::{member_name}"
            child = list(self._clamav.findings(payload, object_name=label))
            child += self._yara.findings(payload, source_label=f"archive member '{member_name}'")
            for finding in child:
                finding.code = f"ARCHIVE_MEMBER.{finding.code}"
                finding.detail = f"[archive member '{member_name}'] {finding.detail}"
            findings.extend(child)

        coverage.note("archive_members")
        if skipped_oversize:
            coverage.skip(
                "archive_members_oversize",
                f"{skipped_oversize} archive member(s) exceeded the "
                f"{budget // 1_048_576} MB per-member read limit and were not scanned",
            )
        return findings


def _iter_tar_members(data: bytes, max_members: int):
    """Yield ``(name, bytes)`` for TAR entries, including gz/bz2-wrapped tars."""
    import gzip
    import io
    import tarfile

    payload = data
    if data[:2] == b"\x1f\x8b":
        payload = gzip.decompress(data)
    elif data[:3] == b"BZh":
        import bz2

        payload = bz2.decompress(data)

    limit = 20 * 1024 * 1024
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as tar:
            for index, info in enumerate(tar):
                if index >= max_members:
                    return
                # Symlinks and devices have no file content to scan.
                if info.issym() or info.islnk() or info.isdir() or not info.isfile():
                    continue
                if info.size > limit:
                    yield info.name, b""
                    continue
                handle = tar.extractfile(info)
                if handle is None:
                    yield info.name, b""
                    continue
                with handle:
                    yield info.name, handle.read(limit)
    except (tarfile.TarError, OSError, ValueError, EOFError):
        return


# ---------------------------------------------------------------------- #
# module-level convenience API
# ---------------------------------------------------------------------- #

_default: FileAnalyzer | None = None


def analyze_bytes(data: bytes, filename: str | None = None, **kwargs: object) -> AnalysisResult:
    """Analyse *data* with the shared default :class:`FileAnalyzer`."""
    global _default
    if _default is None:
        _default = FileAnalyzer()
    return _default.analyze_bytes(data, filename, **kwargs)  # type: ignore[arg-type]


def analyze_path(path: str | Path, **kwargs: object) -> AnalysisResult:
    """Analyse a file on disk with the shared default :class:`FileAnalyzer`."""
    global _default
    if _default is None:
        _default = FileAnalyzer()
    return _default.analyze_path(path, **kwargs)  # type: ignore[arg-type]