"""Signature-based scanners.

Only two: ClamAV (antivirus signatures) and YARA (CyberShield's own defensive
rule set).  Both degrade gracefully and both report their own unavailability as
a finding, because a verdict produced without them must not be presented with
the same confidence as one produced with them.
"""

from __future__ import annotations

from .clamav import (
    MAX_DATABASE_AGE_DAYS,
    ClamAvResult,
    ClamAvScanner,
    ClamAvStatus,
    ClamAvUnavailable,
    get_scanner,
)

__all__ = [
    "MAX_DATABASE_AGE_DAYS",
    "ClamAvResult",
    "ClamAvScanner",
    "ClamAvStatus",
    "ClamAvUnavailable",
    "get_scanner",
]