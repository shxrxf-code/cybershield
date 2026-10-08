"""Shared pytest configuration for the CyberShield test suite."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Iterator

import pytest

# ``detection-engine`` is a standalone package that lives outside the import
# root, so it has to be put on the path explicitly.  Doing it in ``conftest``
# keeps every test module free of path juggling.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "detection-engine"))
sys.path.insert(0, str(_REPO_ROOT))

from detection_engine import AnalysisResult, RiskEngine, Verdict  # noqa: E402
from detection_engine.models import ScanStatus  # noqa: E402


@pytest.fixture(scope="session")
def risk_engine() -> RiskEngine:
    """A default :class:`RiskEngine` shared by the read-only assertions."""
    return RiskEngine()


@pytest.fixture
def empty_result() -> AnalysisResult:
    """A result with no findings, for scoring-unit tests."""
    return AnalysisResult(object_id="test-object", object_type="test")


def verdict_of(result: AnalysisResult) -> Verdict:
    """Convenience accessor so tests read as ``assert verdict_of(r) is ...``."""
    return result.verdict


def findings_with_source(result: AnalysisResult, source: Any) -> list[Any]:
    """Every finding attributed to *source*."""
    return [f for f in result.findings if f.source == source]


def assert_no_certainty_language(text: str) -> None:
    """Fail if *text* asserts certainty.

    The product promise is that CyberShield reports *evidence*, never truth.  A
    verdict of MALICIOUS means "the evidence we gathered is consistent with
    malware", not "this is malware".  Any user-facing string that overclaims
    breaks that promise, so the wording is asserted mechanically rather than
    reviewed by eye.
    """
    forbidden = (
        "guaranteed",
        "guarantee",
        "100% safe",
        "100% malicious",
        "definitely",
        "certainly",
        "proven safe",
        "proven malware",
        "absolutely safe",
        "cannot be",
        "impossible",
    )
    lowered = text.lower()
    for phrase in forbidden:
        assert phrase not in lowered, f"certainty language {phrase!r} in {text!r}"


@pytest.fixture(autouse=True)
def _ignore_dependency_warnings() -> Iterator[None]:
    """Silence third-party parse warnings that are not actionable in tests."""
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        yield


@pytest.fixture
def status_is_complete() -> Any:
    """Assert a scan ran to completion."""

    def _check(result: AnalysisResult) -> None:
        assert result.status == ScanStatus.COMPLETED, result.status

    return _check