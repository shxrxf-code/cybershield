"""Test fixtures for the CyberShield detection engine.

Everything the suite analyses is generated here.  No live malware, no network
fetches and no committed binaries: hostile samples are assembled from
declarative descriptions so that every field a test asserts on is visible at the
point where it is set, and so that a reviewer can read *why* a fixture is
expected to score highly.
"""

from __future__ import annotations

from .apk_builder import apk_bytes, build_apk

__all__ = ["apk_bytes", "build_apk"]