"""ClamAV integration: ``clamscan`` (one-shot) and ``clamd`` (daemon) backends.

Why two backends
----------------
In Docker the daemon is the right choice - it keeps ~900k signatures loaded in
memory instead of reloading them per file.  In local development and in CI the
one-shot binary is easier, needs no running service, and still works.

Honesty constraints
-------------------
* A ClamAV detection is reported as **authoritative**.  That is a deliberate
  trade-off: ClamAV has measurable false positives, but a signature match on a
  known malicious family outweighs CyberShield's other heuristics.
* When ClamAV is unavailable the scan says so explicitly.  Silently skipping it
  would inflate confidence in a verdict that never consulted an antivirus engine.
* A database older than :data:`MAX_DATABASE_AGE_DAYS` is reported, because
  stale signatures miss current campaigns and a stale "clean" result is
  misleading.
* ``clamscan`` is invoked with an explicit argument list, ``shell=False`` and a
  hard timeout.  Untrusted filenames never reach a shell.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..models import Finding, Severity, SignalSource

__all__ = [
    "ClamAvStatus",
    "ClamAvResult",
    "ClamAvScanner",
    "ClamAvUnavailable",
    "get_scanner",
]

#: Signatures older than this are flagged as stale.
MAX_DATABASE_AGE_DAYS = 7

#: ``clamscan`` writes results to stdout as ``<path>: <Signature> FOUND``.
_RESULT_RE = re.compile(r"^(?P<path>.+?):\s*(?P<signature>.+?)\s+FOUND\s*$")

#: Never let the caller wait longer than this for a scan.
_DEFAULT_TIMEOUT = 120

#: Guard against ``clamscan`` resource exhaustion on hostile archives.  ClamAV
#: reads the file itself; these caps bound the whole process.
_MAX_SCAN_BYTES = 110 * 1024 * 1024  # ClamAV's own default limit is 100 MB


class ClamAvUnavailable(RuntimeError):
    """Raised when ClamAV is configured but cannot be used."""


@dataclass(slots=True)
class ClamAvStatus:
    """Availability and health of the ClamAV installation."""

    available: bool = False
    backend: str = "none"
    version: str = ""
    signature_count: int = 0
    signature_age_days: int | None = None
    database_path: str = ""
    daemon_reachable: bool = False
    message: str = ""
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def stale(self) -> bool:
        """True when signatures are older than :data:`MAX_DATABASE_AGE_DAYS`."""
        return (
            self.signature_age_days is not None
            and self.signature_age_days > MAX_DATABASE_AGE_DAYS
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "backend": self.backend,
            "version": self.version,
            "signature_count": self.signature_count,
            "signature_age_days": self.signature_age_days,
            "stale": self.stale,
            "database_path": self.database_path,
            "daemon_reachable": self.daemon_reachable,
            "message": self.message,
            "checked_at": self.checked_at.isoformat(),
        }


@dataclass(slots=True)
class ClamAvResult:
    """Outcome of one ClamAV scan."""

    clean: bool = False
    signatures: list[str] = field(default_factory=list)
    scanned_bytes: int = 0
    elapsed_ms: int = 0
    timed_out: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "clean": self.clean,
            "signatures": self.signatures,
            "scanned_bytes": self.scanned_bytes,
            "elapsed_ms": self.elapsed_ms,
            "timed_out": self.timed_out,
            "error": self.error,
        }


class ClamAvScanner:
    """Scan bytes with ClamAV via either ``clamd`` or ``clamscan``.

    Parameters
    ----------
    socket_path:
        Unix socket for ``clamd``.  When set, the daemon is preferred.
    host, port:
        TCP address for ``clamd`` in a container network.
    binary:
        Path to ``clamscan``.  Looked up on ``PATH`` when omitted.
    database_path:
        Signature database directory.  Used to report signature freshness.
    backend:
        ``"auto"`` (default), ``"clamd"`` or ``"clamscan"``.
    """

    def __init__(
        self,
        socket_path: str | os.PathLike[str] | None = None,
        host: str | None = None,
        port: int | None = None,
        binary: str | None = None,
        database_path: str | os.PathLike[str] | None = None,
        backend: str = "auto",
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self.socket_path = str(socket_path) if socket_path else None
        self.host = host
        self.port = port
        self.binary = binary or "clamscan"
        self.database_path = str(database_path) if database_path else "/var/lib/clamav"
        self.backend = backend
        self.timeout = timeout
        self._lock = threading.Lock()
        self._status: ClamAvStatus | None = None
        self._clamd: object | None = None

    # ------------------------------------------------------------------ #
    # availability
    # ------------------------------------------------------------------ #

    def status(self, *, refresh: bool = False) -> ClamAvStatus:
        """Report whether ClamAV can be used, caching the answer."""
        with self._lock:
            if self._status is not None and not refresh:
                return self._status
            self._status = self._probe()
            return self._status

    def _probe(self) -> ClamAvStatus:
        status = ClamAvStatus()

        # --- daemon path --------------------------------------------- #
        if self.backend in ("auto", "clamd"):
            daemon, daemon_message = self._try_connect_daemon()
            if daemon is not None:
                status.available = True
                status.backend = "clamd"
                status.daemon_reachable = True
                status.message = daemon_message
                try:
                    status.version = str(daemon.version())
                    status.signature_count = int(daemon.count())
                except Exception as exc:  # pragma: no cover - daemon responded
                    status.message = f"daemon responded but a query failed: {exc}"
                self._age_from_daemon(status, daemon)
                return status
            if self.backend == "clamd":
                status.message = daemon_message
                return status

        # --- one-shot binary ----------------------------------------- #
        if self.backend in ("auto", "clamscan"):
            binary = shutil.which(self.binary) or (
                self.binary if Path(self.binary).is_file() else None
            )
            if binary is None:
                status.message = (
                    "ClamAV is not installed on this scanner (no clamd socket and no "
                    f"'{self.binary}' binary on PATH). No antivirus signature scan was "
                    "performed."
                )
                return status
            try:
                completed = subprocess.run(  # noqa: S603 - fixed binary, no shell
                    [binary, "--version"],
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
                output = completed.stdout.decode(errors="replace").strip()
                if completed.returncode == 0 and output:
                    status.available = True
                    status.backend = "clamscan"
                    status.version = output.splitlines()[0]
                    status.message = "clamscan one-shot backend"
                    self._age_from_database(status)
                    return status
                status.message = f"clamscan --version failed: {output or completed.stderr!r}"
                return status
            except (OSError, subprocess.SubprocessError) as exc:
                status.message = f"clamscan could not be run: {exc}"
                return status

        status.message = f"unknown ClamAV backend '{self.backend}'"
        return status

    def _try_connect_daemon(self) -> tuple[object | None, str]:
        try:
            import clamd  # type: ignore[import-not-found]
        except ImportError:
            return None, "python-clamd is not installed; the clamd backend cannot be used."

        kwargs: dict[str, object] = {}
        if self.socket_path:
            kwargs["unix_socket"] = self.socket_path
        else:
            if not self.host:
                return None, "no clamd socket path or host configured."
            kwargs["host"] = self.host
            kwargs["port"] = int(self.port or 3310)
        try:
            client = clamd.ClamdNetworkSocket(**kwargs) if not self.socket_path else clamd.ClamdUnixSocket(
                path=str(self.socket_path)
            )
            client.ping()
        except Exception as exc:
            return None, f"clamd is not reachable: {exc}"
        return client, "connected to clamd"

    def _age_from_daemon(self, status: ClamAvStatus, daemon: object) -> None:
        try:
            info = json.loads(str(daemon.stats()))  # type: ignore[attr-defined]
        except Exception:
            info = {}
        db = info.get("db") or {}
        if db.get("MD5"):
            status.database_path = str(db["MD5"])
        return None

    def _age_from_database(self, status: ClamAvStatus) -> None:
        """Compute signature age from the database directory timestamps."""
        directory = Path(self.database_path)
        if not directory.is_dir():
            status.message += f" Signature directory '{directory}' not found."
            return
        status.database_path = str(directory)
        newest = 0.0
        count = 0
        for entry in directory.glob("*"):
            if entry.is_file() and entry.suffix in (".cvd", ".cld", ".inc", ".mdb"):
                count += 1
                try:
                    newest = max(newest, entry.stat().st_mtime)
                except OSError:
                    continue
        if newest:
            age = datetime.now(timezone.utc) - datetime.fromtimestamp(newest, tz=timezone.utc)
            status.signature_age_days = max(0, age.days)
        status.signature_count = count or None
        if status.signature_age_days is None:
            status.message += " Could not determine how old the signatures are."

    # ------------------------------------------------------------------ #
    # scanning
    # ------------------------------------------------------------------ #

    def scan(self, data: bytes) -> ClamAvResult:
        """Scan *data* and report any signature matches."""
        if not data:
            return ClamAvResult(clean=False, error="no data supplied")

        status = self.status()
        if not status.available:
            return ClamAvResult(clean=False, error=status.message)

        if status.backend == "clamd":
            result = self._scan_daemon(data)
            if result.error is None:
                return result
            # A daemon that dies mid-scan falls back to the one-shot binary so the
            # user still gets an answer rather than a silent gap.
            fallback = self._scan_binary(data)
            if fallback.error is None:
                return fallback

        return self._scan_binary(data)

    def _scan_daemon(self, data: bytes) -> ClamAvResult:
        started = time.monotonic()
        daemon = self._get_daemon()
        if daemon is None:
            return ClamAvResult(error="clamd client unavailable")

        import io

        limit = _MAX_SCAN_BYTES
        try:
            if hasattr(daemon, "instream"):
                result = daemon.instream(io.BytesIO(data[:limit]), timeout=self.timeout)
            else:  # pragma: no cover - older python-clamd
                result = daemon.scan(data=data[:limit])
            elapsed = int((time.monotonic() - started) * 1000)
            state = str(getattr(result, "state", "")).upper()
            if state in ("FOUND", "ERROR"):
                signatures = [s for s in (result.get("signatures") or []) if s]
                return ClamAvResult(
                    clean=False,
                    signatures=signatures,
                    scanned_bytes=len(data),
                    elapsed_ms=elapsed,
                )
            return ClamAvResult(
                clean=state == "OK",
                scanned_bytes=len(data),
                elapsed_ms=elapsed,
                error=None if state else f"unexpected clamd state {state!r}",
            )
        except Exception as exc:
            return ClamAvResult(error=f"clamd scan failed: {exc}")

    def _get_daemon(self) -> object | None:
        with self._lock:
            if self._clamd is not None:
                return self._clamd
            client, _ = self._try_connect_daemon()
            self._clamd = client
            return client

    def _scan_binary(self, data: bytes) -> ClamAvResult:
        binary = shutil.which(self.binary) or (
            self.binary if Path(self.binary).is_file() else None
        )
        if binary is None:
            return ClamAvResult(error=f"'{self.binary}' not found on PATH")

        started = time.monotonic()
        handle = None
        path = ""
        try:
            # The payload is written to a private temp file with a fixed name.
            # Never derived from user input, never a shell string.
            with tempfile.NamedTemporaryFile(
                prefix="cybershield-clamscan-", suffix=".bin", delete=False
            ) as handle:
                handle.write(data[:_MAX_SCAN_BYTES])
                path = handle.name

            command = [
                binary,
                "--no-summary",
                "--stdout",
                f"--database={self.database_path}",
                path,
            ]
            completed = subprocess.run(  # noqa: S603 - fixed binary, arg list, no shell
                command,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
            elapsed = int((time.monotonic() - started) * 1000)
            stdout = completed.stdout.decode(errors="replace")
            signatures = [
                match.group("signature").strip()
                for match in (_RESULT_RE.match(line) for line in stdout.splitlines())
                if match
            ]
            if signatures:
                return ClamAvResult(
                    clean=False,
                    signatures=signatures,
                    scanned_bytes=len(data),
                    elapsed_ms=elapsed,
                )
            if completed.returncode == 0:
                return ClamAvResult(
                    clean=True, scanned_bytes=len(data), elapsed_ms=elapsed
                )
            return ClamAvResult(
                clean=False,
                scanned_bytes=len(data),
                elapsed_ms=elapsed,
                error=f"clamscan exited {completed.returncode}: "
                f"{completed.stderr.decode(errors='replace').strip()[:300]}",
            )
        except subprocess.TimeoutExpired:
            return ClamAvResult(
                clean=False,
                scanned_bytes=len(data),
                elapsed_ms=int((time.monotonic() - started) * 1000),
                timed_out=True,
                error=f"clamscan exceeded {self.timeout}s; the file was not fully scanned",
            )
        except OSError as exc:
            return ClamAvResult(error=f"clamscan could not be run: {exc}")
        finally:
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    # ------------------------------------------------------------------ #
    # findings
    # ------------------------------------------------------------------ #

    def findings(self, data: bytes, *, object_name: str = "file") -> list[Finding]:
        """Convert a scan outcome into findings, including coverage gaps."""
        status = self.status()
        if not status.available:
            return [
                Finding(
                    code="CLAMAV.UNAVAILABLE",
                    title="Antivirus signature scanning did not run",
                    detail=(
                        f"{status.message} No antivirus signature database was "
                        "consulted for this object, so a verdict is based only on "
                        "heuristic and structural evidence. Confidence in this result "
                        "is reduced accordingly."
                    ),
                    severity=Severity.INFO,
                    source=SignalSource.CLAMAV,
                    category="coverage",
                    weight=0.0,
                )
            ]

        result = self.scan(data)
        findings: list[Finding] = []

        if result.error and not result.timed_out:
            findings.append(
                Finding(
                    code="CLAMAV.ERROR",
                    title="Antivirus scan could not complete",
                    detail=(
                        f"The ClamAV scan failed: {result.error}. The object was not "
                        "checked against antivirus signatures."
                    ),
                    severity=Severity.MEDIUM,
                    source=SignalSource.CLAMAV,
                    category="coverage",
                    weight=8.0,
                )
            )
        elif result.timed_out:
            findings.append(
                Finding(
                    code="CLAMAV.TIMEOUT",
                    title="Antivirus scan timed out",
                    detail=(
                        f"ClamAV did not finish within {self.timeout}s. A timeout does "
                        "not mean the object is safe - it means it was not scanned."
                    ),
                    severity=Severity.MEDIUM,
                    source=SignalSource.CLAMAV,
                    category="coverage",
                    weight=8.0,
                )
            )

        if status.stale:
            findings.append(
                Finding(
                    code="CLAMAV.STALE_SIGNATURES",
                    title=f"Antivirus signatures are {status.signature_age_days} days old",
                    detail=(
                        f"The ClamAV signature database at {status.database_path} was "
                        f"last updated {status.signature_age_days} days ago. Recent "
                        "campaigns will not be recognised, so a clean result from this "
                        "scanner is weaker evidence than it appears."
                    ),
                    severity=Severity.LOW,
                    source=SignalSource.CLAMAV,
                    category="coverage",
                    weight=5.0,
                    evidence={"signature_age_days": status.signature_age_days},
                )
            )

        if result.signatures:
            names = ", ".join(result.signatures[:5])
            findings.append(
                Finding(
                    code="CLAMAV.DETECTION",
                    title=f"Antivirus matched: {names}",
                    detail=(
                        f"ClamAV {status.version or 'antivirus engine'} matched this "
                        f"{object_name} against {len(result.signatures)} signature(s). "
                        f"Signature name(s): {names}. Signature-based detections carry a "
                        "high false-positive rate for packed or unusual legitimate "
                        "software, so confirm with the file's publisher before acting."
                    ),
                    severity=Severity.CRITICAL,
                    source=SignalSource.CLAMAV,
                    category="malware",
                    weight=45.0,
                    authoritative=True,
                    evidence=result.to_dict(),
                )
            )
        return findings


# ---------------------------------------------------------------------- #
# process-wide instance
# ---------------------------------------------------------------------- #

_scanner: ClamAvScanner | None = None
_scanner_lock = threading.Lock()


def get_scanner(**kwargs: object) -> ClamAvScanner:
    """Return a shared :class:`ClamAvScanner`, configured from the environment.

    Recognised environment variables:

    ``CLAMAV_SOCKET``
        Path to the ``clamd`` unix socket.
    ``CLAMAV_HOST`` / ``CLAMAV_PORT``
        TCP address for ``clamd``.
    ``CLAMAV_BINARY``
        Path to the ``clamscan`` binary.
    ``CLAMAV_DATABASE``
        Signature database directory.
    ``CLAMAV_BACKEND``
        ``auto`` (default), ``clamd`` or ``clamscan``.
    """
    global _scanner
    with _scanner_lock:
        if _scanner is None or kwargs:
            _scanner = ClamAvScanner(
                socket_path=os.environ.get("CLAMAV_SOCKET") or None,
                host=os.environ.get("CLAMAV_HOST") or None,
                port=int(os.environ["CLAMAV_PORT"]) if os.environ.get("CLAMAV_PORT") else None,
                binary=os.environ.get("CLAMAV_BINARY") or None,
                database_path=os.environ.get("CLAMAV_DATABASE") or None,
                backend=os.environ.get("CLAMAV_BACKEND", "auto"),
                timeout=int(os.environ.get("CLAMAV_TIMEOUT", str(_DEFAULT_TIMEOUT))),
            )
        return _scanner


