"""CyberShield detection engine.

A dependency-light, framework-agnostic library for explainable threat analysis.
The engine has no knowledge of HTTP, databases or job queues, so the same code
runs inside the FastAPI backend, in the offline CLI, and in tests.

What this engine will not do
----------------------------
It never claims certainty.  Every result carries a score, a verdict, an explicit
confidence figure and the list of reasons behind them, and the confidence is
capped below 1.0 because heuristic analysis is by definition fallible.  See
:data:`detection_engine.constants.DISCLAIMER` for the user-facing wording.

It never executes a sample.  Analysis is entirely static: parsing, hashing,
pattern matching and, for URLs, fetching remote content through an SSRF-guarded
client.  Nothing is detonated, emulated or rendered.

Layout
------
``models``      core value types shared by every analyser
``scoring``     the risk engine that turns findings into a verdict
``security``    SSRF protection, filename and path hardening
``url``         URL syntax, domain intelligence, DNS, TLS and redirects
``phishing``    social-engineering text analysis and link deception
``file``        type detection, structure, entropy, archives, documents
``email``       RFC 822 parsing and mail authentication evaluation
``apk``         Android package analysis
``yara``        the CyberShield rule set
``scanners``    third-party engines (ClamAV)
``reputation``  threat-intelligence providers and consensus
``ml``          optional statistical scoring, always reported as one component
"""

from __future__ import annotations

__version__ = "1.2.0"

from .constants import DISCLAIMER
from .exceptions import (
    AnalysisTimeoutError,
    DetectionEngineError,
    MalformedObjectError,
    NameResolutionError,
    ParserError,
    ScannerUnavailableError,
    ThreatIntelError,
    UnsupportedObjectError,
)
from .models import (
    AnalysisResult,
    Finding,
    Indicator,
    ObjectType,
    Recommendation,
    ScanStatus,
    Severity,
    SignalSource,
    Verdict,
    verdict_for_score,
)
from .scoring import RiskEngine, ScoreBreakdown

__all__ = [
    "AnalysisResult",
    "AnalysisTimeoutError",
    "DetectionEngineError",
    "DISCLAIMER",
    "Finding",
    "Indicator",
    "MalformedObjectError",
    "NameResolutionError",
    "ObjectType",
    "ParserError",
    "Recommendation",
    "RiskEngine",
    "ScanStatus",
    "ScoreBreakdown",
    "ScannerUnavailableError",
    "Severity",
    "SignalSource",
    "ThreatIntelError",
    "UnsupportedObjectError",
    "Verdict",
    "__version__",
    "verdict_for_score",
]