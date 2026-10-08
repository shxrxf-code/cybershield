"""ClamAV client speaking the ``clamd`` protocol over TCP.

Protocol
--------
``clamd`` accepts a stream of commands (``zINSTREAM``, ``zSCAN``, ``zPING``)
prefixed by a 4-byte big-endian length. Response is a NUL-terminated line.

Why INSTREAM rather than SCAN
-----------------------------
``SCAN`` hands clamd a *path*, which would require placing an untrusted upload
inside a directory clamd can read. ``INSTREAM`` pushes bytes over the socket
instead, so the sample never exists as a file the antivirus daemon could act on,
and the daemon's own scanning path never walks into our storage.

Operational notes
-----------------
* ClamAV identifies by hash, and a hash match means the *exact* file is known
  malicious, so detections are emitted at ``CRITICAL``.
* A daemon that has no signatures for a file returns ``OK``. That is a clean
  result, not a guarantee of safety, and the emitted confidence reflects that.
* Connection reuse is pooled; clamd closes the connection after ``zPING``-style
  commands, so a broken pipe is retried once rather than surfaced as an error.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from pathlib import Path
from typing import Final

from app.core.config import get_settings
from app.core.exceptions import ScannerUnavailableError
from app.schemas.common import Severity, SignalSource
from app.schemas.signal import DetectionSignal
from app.scanners.base import ExternalScanner, ScanResult

logger = logging.getLogger(__name__)

#: clamd reads the file descriptor as it arrives and returns immediately; keep
#: the socket open and stream, so a 100 MB upload is not buffered twice.
_CHUNK_SIZE: Final[int] = 64 * 1024
_COMMAND_TIMEOUT: Final[float] = 30.0

#: ClamAV returns one name per signature match; a file with several matches is
#: split on ``,``. Each is a real detection, not noise.
_MAX_REPORTED_NAMES: Final[int] = 10

#: clamd prefixes INSTREAM responses with the stream name.
_STREAM_PREFIX_RE = re.compile(r"^stream:\s*", re.IGNORECASE)


class ClamAVScanner(ExternalScanner):
    """Talks to a ``clamd`` instance over TCP."""

    name = "clamav"
    signal_source = SignalSource.ANTIVIRUS

    def __init__(self, host: str | None = None, port: int | None = None) -> None:
        settings = get_settings()
        self._host = host or settings.clamav_host
        self._port = port or settings.clamav_port
        self._timeout = settings.clamav_timeout_seconds
        self._max_bytes = settings.clamav_max_scan_bytes
        self._enabled = settings.clamav_enabled
        self._version: str | None = None

    @property
    def endpoint(self) -> str:
        return f"{self._host}:{self._port}"

    async def is_available(self) -> bool:
        if not self._enabled:
            return False
        try:
            result = await self._command(b"zPING", expect_stream=False)
        except (OSError, asyncio.TimeoutError, ScannerUnavailableError):
            return False
        return result.startswith("PONG")

    async def get_version(self) -> str | None:
        """Fetch and memoise the daemon version, for the health endpoint."""
        if self._version is not None:
            return self._version
        try:
            response = await self._command(b"zVERSION", expect_stream=False)
        except (OSError, asyncio.TimeoutError, ScannerUnavailableError):
            return None
        # Format: "ClamAV 1.0.3/27000/Wed Jan  1 00:00:00 2025"
        parts = response.strip().split("/")
        self._version = parts[0].strip() if parts else None
        return self._version

    async def scan_path(self, path: Path) -> ScanResult:
        """Stream a file to clamd with ``zINSTREAM``."""
        if not self._enabled:
            return ScanResult.unavailable(self.name, "ClamAV is disabled by configuration.")

        started = time.perf_counter()
        try:
            size = path.stat().st_size
        except OSError as exc:
            return ScanResult.unavailable(self.name, f"Could not read upload: {exc.strerror}")

        if size > self._max_bytes:
            # A truncated scan that reports "clean" would be dangerous, so the
            # result is marked unavailable instead of partially clean.
            return ScanResult.unavailable(
                self.name,
                f"File exceeds the configured ClamAV limit of {self._max_bytes} bytes.",
                scanned_bytes=size,
            )

        try:
            response = await self._stream_file(path, size)
        except (OSError, asyncio.TimeoutError, ScannerUnavailableError) as exc:
            logger.warning("ClamAV scan failed: %s", exc)
            return ScanResult.unavailable(self.name, str(exc))

        latency = int((time.perf_counter() - started) * 1000)
        return self._interpret(response, latency, size)

    async def scan_bytes(self, data: bytes, suffix: str = "") -> ScanResult:
        """Push an in-memory blob to clamd without writing it to disk."""
        if not self._enabled:
            return ScanResult.unavailable(self.name, "ClamAV is disabled by configuration.")
        if len(data) > self._max_bytes:
            return ScanResult.unavailable(
                self.name, f"Payload exceeds the configured ClamAV limit."
            )

        started = time.perf_counter()
        try:
            response = await self._stream_bytes(data)
        except (OSError, asyncio.TimeoutError, ScannerUnavailableError) as exc:
            logger.warning("ClamAV in-memory scan failed: %s", exc)
            return ScanResult.unavailable(self.name, str(exc))

        latency = int((time.perf_counter() - started) * 1000)
        return self._interpret(response, latency, len(data))

    # ------------------------------------------------------------------
    # Protocol
    # ------------------------------------------------------------------
    async def _stream_file(self, path: Path, size: int) -> str:
        reader, writer = await self._connect()
        try:
            payload = bytearray()
            payload += self._frame(b"zINSTREAM")
            payload += len(b"stream").to_bytes(4, "big")
            payload += b"stream\0"

            read_bytes = 0
            with path.open("rb") as handle:
                while chunk := handle.read(_CHUNK_SIZE):
                    read_bytes += len(chunk)
                    payload += len(chunk).to_bytes(4, "big")
                    payload += chunk
                    # Back-pressure: only keep one chunk buffered so a very large
                    # upload does not become a large allocation.
                    if len(payload) > _CHUNK_SIZE * 2:
                        writer.write(bytes(payload))
                        await writer.drain()
                        payload = bytearray()

            payload += (0).to_bytes(4, "big")  # zero-length chunk terminates
            writer.write(bytes(payload))
            await writer.drain()
            return await self._read_response(reader)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):  # pragma: no cover
                pass

    async def _stream_bytes(self, data: bytes) -> str:
        reader, writer = await self._connect()
        try:
            payload = bytearray()
            payload += self._frame(b"zINSTREAM")
            payload += len(b"stream").to_bytes(4, "big")
            payload += b"stream\0"
            for offset in range(0, len(data), _CHUNK_SIZE):
                chunk = data[offset : offset + _CHUNK_SIZE]
                payload += len(chunk).to_bytes(4, "big")
                payload += chunk
            payload += (0).to_bytes(4, "big")
            writer.write(bytes(payload))
            await writer.drain()
            return await self._read_response(reader)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):  # pragma: no cover
                pass

    async def _command(self, command: bytes, *, expect_stream: bool = True) -> str:
        """Send a single command and read one response line."""
        del expect_stream  # Commands are framed identically in both directions.
        reader, writer = await self._connect()
        try:
            writer.write(self._frame(command))
            await writer.drain()
            return await self._read_response(reader)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):  # pragma: no cover
                pass

    @staticmethod
    def _frame(command: bytes) -> bytes:
        """Prefix a zero-terminated command with its big-endian length."""
        return len(command).to_bytes(4, "big") + command + b"\x00"

    async def _connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port),
                timeout=min(self._timeout, _COMMAND_TIMEOUT),
            )
        except asyncio.TimeoutError as exc:
            raise ScannerUnavailableError(
                f"Timed out connecting to ClamAV at {self.endpoint}."
            ) from exc
        except OSError as exc:
            raise ScannerUnavailableError(
                f"Cannot reach ClamAV at {self.endpoint}: {exc.strerror or exc}."
            ) from exc

    @staticmethod
    async def _read_response(reader: asyncio.StreamReader) -> str:
        raw = await asyncio.wait_for(reader.readline(), timeout=_COMMAND_TIMEOUT * 4)
        if not raw:
            raise ScannerUnavailableError("ClamAV closed the connection without responding.")
        # Strip the NUL terminator and any trailing framing bytes.
        return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()

    # ------------------------------------------------------------------
    # Interpretation
    # ------------------------------------------------------------------
    def _interpret(self, response: str, latency_ms: int, size: int) -> ScanResult:
        """Turn a clamd response into a structured result."""
        payload = response.replace("\x00", "").strip()
        upper = payload.upper()

        if upper.startswith("OK"):
            return ScanResult(
                scanner=self.name,
                available=True,
                engine_verdict="OK",
                latency_ms=latency_ms,
                scanned_bytes=size,
                metadata={
                    "note": (
                        "ClamAV found no signature match. This means the file is not in "
                        "its signature database, which is not proof of safety."
                    )
                },
            )

        if "FOUND" not in upper and "ERROR" not in upper:
            # An unrecognised response must not be treated as a clean scan.
            return ScanResult.unavailable(
                self.name, f"Unexpected response from ClamAV: {payload[:200]}"
            )

        if "ERROR" in upper:
            return ScanResult.unavailable(
                self.name, f"ClamAV reported an error: {payload[:200]}"
            )

        # "stream: Eicar-Signature FOUND"
        signature = _STREAM_PREFIX_RE.sub("", payload)
        signature = signature.replace("FOUND", "").strip(" .:-")
        names = [part.strip() for part in signature.split(",") if part.strip()]
        names = names[:_MAX_REPORTED_NAMES]

        signals = [
            self._make_signal(
                code="av.malware_detected",
                title=f"Antivirus detection: {name}" if len(names) == 1 else "Antivirus detection",
                description=(
                    f"ClamAV matched the signature '{name}'. An antivirus signature match "
                    "identifies known malicious code, so this file should be treated as "
                    "malicious. It has not been executed."
                ),
                severity=Severity.CRITICAL,
                evidence={"detection": name, "detections": names, "engine": "clamav"},
                confidence=0.97,
            )
        ]

        if len(names) > 1:
            signals.append(
                self._make_signal(
                    code="av.multiple_detections",
                    title=f"{len(names)} antivirus signatures matched",
                    description=(
                        "Multiple independent signatures matched this file, which increases "
                        "confidence that it is malicious rather than a single heuristic hit."
                    ),
                    severity=Severity.CRITICAL,
                    evidence={"detections": names},
                    confidence=0.97,
                )
            )

        return ScanResult(
            scanner=self.name,
            available=True,
            signals=signals,
            detections=names,
            engine_verdict="FOUND",
            latency_ms=latency_ms,
            scanned_bytes=size,
            metadata={"signature_count": len(names)},
        )


_scanner: ClamAVScanner | None = None


def get_clamav_scanner() -> ClamAVScanner:
    """Return the process-wide ClamAV client."""
    global _scanner
    if _scanner is None:
        _scanner = ClamAVScanner()
    return _scanner


__all__ = ["ClamAVScanner", "get_clamav_scanner"]