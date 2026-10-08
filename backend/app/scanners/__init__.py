"""External scanner backends (antivirus, YARA)."""

from app.scanners.base import ExternalScanner, ScanResult
from app.scanners.clamav import ClamAVScanner, get_clamav_scanner
from app.scanners.yara_scanner import YaraScanner, get_yara_scanner

__all__ = [
    "ClamAVScanner",
    "ExternalScanner",
    "ScanResult",
    "YaraScanner",
    "get_clamav_scanner",
    "get_yara_scanner",
]