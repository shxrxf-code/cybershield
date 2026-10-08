"""Email threat analysis: RFC 822 parsing, authentication review and correlation.

The entry point is :func:`analyze_email`, which returns an
:class:`EmailReport` holding the parsed message plus every observation made
about it.  :func:`to_analysis_result` wraps that report in an
:class:`~detection_engine.models.AnalysisResult` so the risk engine can score it
alongside URLs and files.

Two boundaries matter here:

* CyberShield never *claims* an SPF, DKIM or DMARC result it did not observe.
  It reads the receiving MTA's ``Authentication-Results`` header, and when that
  header is absent it reports authentication as unverifiable - neither pass nor
  fail.  Recomputing SPF would need the original sending IP, and recomputing
  DKIM would need the exact signed bytes, which a forwarded or re-saved message
  no longer has.
* Nothing is executed and nothing is fetched.  Links are recorded as indicators;
  the caller decides whether to analyse them further through the URL pipeline.
"""

from __future__ import annotations

from .analyzer import (
    AuthResult,
    EmailReport,
    HeaderAuth,
    ParsedEmail,
    analyze_email,
    analyze_email_async,
    email_findings,
    parse_email,
    to_analysis_result,
)
from .indicators import extract_indicators, normalize_domain

__all__ = [
    "AuthResult",
    "EmailReport",
    "HeaderAuth",
    "ParsedEmail",
    "analyze_email",
    "analyze_email_async",
    "email_findings",
    "extract_indicators",
    "normalize_domain",
    "parse_email",
    "to_analysis_result",
]