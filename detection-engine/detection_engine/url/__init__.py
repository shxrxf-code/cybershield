"""URL structure, domain intelligence, DNS, TLS and redirect analysis.

Pipeline (executed by :mod:`detection_engine.url.analyzer`)::

    original URL
        -> normalization        (normalizer.parse_url)
        -> syntax analysis      (syntax.analyze_url_syntax)
        -> domain analysis      (domain.analyze_domain)
        -> DNS analysis         (dns.analyze_dns)
        -> TLS analysis         (tls.analyze_tls)
        -> redirect analysis    (redirect.analyze_redirects)
        -> reputation lookup    (reputation layer)
        -> ML / heuristic score (scoring.RiskEngine)
        -> final verdict
"""

from __future__ import annotations

from .analyzer import UrlAnalyzer, UrlAnalyzerConfig
from .domain import analyze_domain, find_brand_matches
from .normalizer import ParsedUrl, normalize_url, parse_url, registrable_domain
from .syntax import analyze_url_syntax

__all__ = [
    "ParsedUrl",
    "UrlAnalyzer",
    "UrlAnalyzerConfig",
    "analyze_domain",
    "analyze_url_syntax",
    "find_brand_matches",
    "normalize_url",
    "parse_url",
    "registrable_domain",
]