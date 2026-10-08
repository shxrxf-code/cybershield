"""URL analysis orchestrator.

Executes the documented pipeline and assembles a single
:class:`~detection_engine.models.AnalysisResult`::

    original URL
      -> normalization      (normalizer.parse_url)
      -> syntax analysis    (syntax.analyze_url_syntax)
      -> domain analysis    (domain.analyze_domain)
      -> DNS analysis       (dns.analyze_dns)
      -> TLS analysis       (tls.probe_tls)
      -> redirect analysis  (security.ssrf.SsrfSafeFetcher + redirect.analyze_redirects)
      -> reputation lookup  (reputation.ReputationAggregator)
      -> risk engine        (scoring.RiskEngine)
      -> final verdict

Every stage is independently optional.  When a stage cannot run (no network, DNS
down, TLS disabled) the result is marked ``incomplete`` and the risk engine
reduces its confidence rather than silently assuming "no problems found".
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from ..exceptions import DetectionEngineError
from ..models import AnalysisResult, Finding, ObjectType, Recommendation, Severity, SignalSource
from ..phishing.text import analyze_text, findings_from_profile
from ..reputation import IndicatorType, ReputationAggregator
from ..scoring import RiskEngine
from ..security.ssrf import FetchResult, SsrfBlockedError, SsrfSafeFetcher
from . import dns as dns_module
from . import redirect as redirect_module
from . import tls as tls_module
from .domain import analyze_domain, summarize_domain_analysis
from .normalizer import DANGEROUS_SCHEMES, ParsedUrl, parse_url
from .syntax import analyze_url_syntax

__all__ = ["UrlAnalyzer", "UrlAnalyzerConfig", "analyze_url"]

#: Text extracted from a fetched page is capped before phishing analysis.
_MAX_PAGE_TEXT = 400_000


@dataclass(slots=True)
class UrlAnalyzerConfig:
    """Feature switches for the URL pipeline."""

    enable_network: bool = True
    enable_dns: bool = True
    enable_tls_probe: bool = True
    enable_redirect_analysis: bool = True
    enable_page_text_analysis: bool = True
    max_redirects: int = 10
    request_timeout: float = 8.0
    connect_timeout: float = 5.0
    domain_age_days: int | None = None
    #: Extra context supplied by the caller (e.g. the text of an email the URL
    #: was found in).  Used to correlate URL and surrounding text.
    context_text: str | None = None
    allow_private_targets: bool = False


@dataclass(slots=True)
class UrlAnalyzer:
    """Analyses URLs end-to-end."""

    config: UrlAnalyzerConfig = field(default_factory=UrlAnalyzerConfig)
    reputation: ReputationAggregator | None = None
    fetcher: SsrfSafeFetcher | None = None
    risk_engine: RiskEngine = field(default_factory=RiskEngine)
    _engines_ran: list[str] = field(default_factory=list, init=False, repr=False)

    async def __aenter__(self) -> UrlAnalyzer:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self.fetcher is not None:
            await self.fetcher.aclose()

    # ------------------------------------------------------------------ #

    async def analyze(self, url: str) -> AnalysisResult:
        """Analyse *url* and return the completed result."""
        started = time.perf_counter()
        parsed = parse_url(url)
        result = AnalysisResult(object_type=ObjectType.URL, object_name=parsed.normalized)
        engines_ran: list[str] = ["normalizer", "syntax"]

        if not parsed.is_supported_scheme:
            dangerous = parsed.scheme in DANGEROUS_SCHEMES
            if dangerous:
                result.add(
                    Finding(
                        code="URL.DANGEROUS_SCHEME",
                        title=f"'{parsed.scheme}:' links are actively dangerous",
                        detail=(
                            f"The '{parsed.scheme}' scheme is not a web address. It "
                            "executes locally in the browser: "
                            + (
                                "javascript: runs attacker-supplied script on the "
                                "current page, which is how session cookies and "
                                "credentials are stolen without any server "
                                "involvement."
                                if parsed.scheme == "javascript"
                                else "data: embeds content inline and can be used "
                                "to build phishing pages with no domain to report."
                                if parsed.scheme == "data"
                                else "this scheme can read local files or invoke "
                                "system handlers."
                            )
                            + " Never open a link like this from an email, chat or "
                            "message you did not type yourself."
                        ),
                        severity=Severity.CRITICAL,
                        source=SignalSource.URL_SYNTAX,
                        category="payload",
                        weight=30.0,
                        authoritative=True,
                        evidence={"scheme": parsed.scheme},
                    )
                )
            else:
                result.add(
                    Finding(
                        code="URL.UNSUPPORTED_SCHEME",
                        title=f"'{parsed.scheme}:' is not a web address",
                        detail=(
                            "This link launches another application instead of a "
                            "page. CyberShield cannot inspect the content it opens, "
                            "so no verdict can be given."
                        ),
                        severity=Severity.INFO,
                        source=SignalSource.URL_SYNTAX,
                        category="structure",
                        weight=3.0,
                        evidence={"scheme": parsed.scheme},
                    )
                )
            result.metadata["parsed_url"] = _parsed_summary(parsed)
            result.engines_ran = engines_ran
            result.incomplete = not dangerous
            self._finalise(result, started)
            return result

        # 1. syntax -------------------------------------------------------
        result.extend(analyze_url_syntax(parsed))
        for indicator_value in _indicators_from_url(parsed):
            result.add_indicator("url", indicator_value)
        result.add_indicator("domain", parsed.host, context="url-host")
        if parsed.registrable and parsed.registrable != parsed.host:
            result.add_indicator("domain", parsed.registrable, context="registrable-domain")

        # 2. domain intelligence -----------------------------------------
        result.extend(analyze_domain(parsed, domain_age_days=self.config.domain_age_days))
        engines_ran.append("domain")

        # 3-5. network stages run concurrently ----------------------------
        fetch_result: FetchResult | None = None
        dns_analysis: dns_module.DnsAnalysis | None = None
        tls_analysis: tls_module.TlsAnalysis | None = None
        network_errors: list[str] = []

        tasks: dict[str, asyncio.Task[Any]] = {}

        if self.config.enable_network:
            if self.config.enable_dns and not parsed.is_ip_literal:
                tasks["dns"] = asyncio.create_task(
                    dns_module.analyze_dns(parsed.host), name="cybershield.dns"
                )
            if self.config.enable_tls_probe and parsed.is_https:
                # ``probe_tls`` opens a blocking socket, so it runs in a worker
                # thread rather than on the event loop.
                tasks["tls"] = asyncio.create_task(
                    asyncio.to_thread(
                        tls_module.probe_tls,
                        parsed,
                        allow_private=self.config.allow_private_targets,
                    ),
                    name="cybershield.tls",
                )
            if self.config.enable_redirect_analysis:
                tasks["http"] = asyncio.create_task(
                    self._fetch(parsed), name="cybershield.http"
                )

        for name, task in tasks.items():
            try:
                outcome = await task
            except SsrfBlockedError as exc:
                network_errors.append(f"{name}: {exc.message}")
                result.add(
                    Finding(
                        code="URL.SSRF_BLOCKED",
                        title="Request blocked by CyberShield's SSRF protection",
                        detail=(
                            f"{exc.message} The scanner refused to make this "
                            "request so it cannot be used to reach internal "
                            "services or cloud metadata endpoints."
                        ),
                        severity=Severity.INFO,
                        source=SignalSource.URL_SYNTAX,
                        category="network",
                        weight=0.0,
                        evidence={"stage": name, "error": exc.message},
                    )
                )
                continue
            except DetectionEngineError as exc:
                network_errors.append(f"{name}: {exc.message}")
                continue
            except Exception as exc:  # defensive: never fail a scan on one stage
                network_errors.append(f"{name}: {type(exc).__name__}: {exc}")
                continue

            if name == "dns" and outcome is not None:
                dns_analysis, dns_findings = outcome
                result.extend(dns_findings)
                engines_ran.append("dns")
            elif name == "tls" and outcome is not None:
                tls_analysis = outcome
                result.extend(tls_module.analyze_tls(parsed, outcome))
                engines_ran.append("tls")
            elif name == "http" and outcome is not None:
                fetch_result = outcome
                result.extend(redirect_module.analyze_redirects(parsed, fetch_result))
                engines_ran.append("redirect")

        # 6. page content --------------------------------------------------
        page_text = ""
        if self.config.enable_page_text_analysis and fetch_result is not None and fetch_result.ok:
            page_text = _decode_page(fetch_result)
            if page_text:
                engines_ran.append("page-text")
                result.extend(_analyze_page_text(page_text, parsed))

        # 7. reputation ----------------------------------------------------
        if self.reputation is not None and self.reputation.providers:
            await self._add_reputation(result, parsed)
            engines_ran.append("threat-intel")

        # 8. surrounding context (e.g. email body the link came from) -------
        if self.config.context_text:
            result.extend(_correlate_context(parsed, self.config.context_text))

        # 9. metadata -------------------------------------------------------
        result.metadata["parsed_url"] = _parsed_summary(parsed)
        result.metadata["domain_analysis"] = summarize_domain_analysis(
            parsed, domain_age_days=self.config.domain_age_days
        )
        if dns_analysis is not None:
            result.metadata["dns"] = dns_analysis.to_dict()
        if tls_analysis is not None:
            result.metadata["tls"] = tls_analysis.to_dict()
        if fetch_result is not None:
            result.metadata["http"] = {
                "status_code": fetch_result.status_code,
                "final_url": fetch_result.final_url,
                "redirects": redirect_module.build_redirect_analysis(parsed, fetch_result).to_dict(),
                "resolved_ips": fetch_result.resolved_ips,
                "elapsed_ms": fetch_result.elapsed_ms,
                "server": fetch_result.headers.get("server"),
                "content_type": fetch_result.headers.get("content-type"),
                "blocked": fetch_result.blocked,
                "error": fetch_result.error,
            }
            if fetch_result.status_code and fetch_result.status_code >= 500:
                result.add(
                    Finding(
                        code="URL.SERVER_ERROR",
                        title=f"Server returned HTTP {fetch_result.status_code}",
                        detail="The origin is unreachable or misconfigured, so its content cannot be assessed.",
                        severity=Severity.LOW,
                        source=SignalSource.URL_REDIRECT,
                        category="availability",
                        weight=5.0,
                        evidence={"status": fetch_result.status_code},
                    )
                )
        if network_errors:
            result.metadata["network_errors"] = network_errors

        if self.config.enable_network and not engines_ran_dns(engines_ran) and self.config.enable_dns:
            result.incomplete = True

        result.engines_ran = engines_ran
        result.recommendations = _recommendations_for(result)
        self._finalise(result, started)
        return result

    # ------------------------------------------------------------------ #

    async def _fetch(self, parsed: ParsedUrl) -> FetchResult:
        fetcher = self.fetcher
        if fetcher is None:
            from ..security.ssrf import SsrfPolicy

            fetcher = SsrfSafeFetcher(
                SsrfPolicy(
                    connect_timeout=self.config.connect_timeout,
                    read_timeout=self.config.request_timeout,
                    total_timeout=self.config.request_timeout * 2,
                    max_redirects=self.config.max_redirects,
                    allow_private=self.config.allow_private_targets,
                )
            )
            self.fetcher = fetcher
        return await fetcher.fetch(parsed.normalized, max_redirects=self.config.max_redirects)

    async def _add_reputation(self, result: AnalysisResult, parsed: ParsedUrl) -> None:
        assert self.reputation is not None
        targets: list[tuple[str, IndicatorType]] = [(parsed.normalized, IndicatorType.URL)]
        for value in filter(None, (parsed.registrable, parsed.host)):
            if value != parsed.host or parsed.registrable == parsed.host:
                targets.append((value, IndicatorType.DOMAIN))
        for address in result.metadata.get("dns", {}).get("addresses", []) or []:
            targets.append((str(address), IndicatorType.IP))

        seen: set[tuple[str, str]] = set()
        for indicator, kind in targets:
            key = (indicator.lower(), kind.value)
            if key in seen:
                continue
            seen.add(key)
            provider_result = await self.reputation.check(indicator, kind)
            if kind is IndicatorType.URL:
                findings = ReputationAggregator.findings_for_url(provider_result)
            elif kind is IndicatorType.DOMAIN:
                findings = ReputationAggregator.findings_for_domain(provider_result)
            elif kind is IndicatorType.IP:
                findings = ReputationAggregator.findings_for_ip(provider_result)
            else:  # pragma: no cover - exhaustive
                continue
            result.extend(findings)
            result.metadata.setdefault("threat_intel", {})[kind.value] = provider_result.to_dict()
            if provider_result.any_suspicious:
                result.add_indicator(
                    "domain" if kind is IndicatorType.DOMAIN else kind.value,
                    indicator,
                    malicious=provider_result.any_malicious,
                    context="threat-intel",
                )

    def _finalise(self, result: AnalysisResult, started: float) -> None:
        result.metadata["analysis_duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        result.metadata["engine_version"] = ENGINE_VERSION
        self.risk_engine.finalise(result)


ENGINE_VERSION = "1.0.0"


# ---------------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------------- #


def engines_ran_dns(engines: list[str]) -> bool:
    return "dns" in engines


def _indicators_from_url(parsed: ParsedUrl) -> list[str]:
    out: list[str] = []
    if parsed.query:
        out.append(parsed.normalized)
    return out


def _decode_page(fetch: FetchResult) -> str:
    content_type = fetch.headers.get("content-type", "")
    if "html" not in content_type and "text" not in content_type:
        return ""
    body = fetch.body[:_MAX_PAGE_TEXT]
    charset = "utf-8"
    if "charset=" in content_type:
        charset = content_type.split("charset=")[-1].split(";")[0].strip().strip('"') or "utf-8"
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _strip_html(html: str) -> str:
    import re

    without_scripts = re.sub(r"<(script|style|noscript)[^>]*>.*?</\1>", " ", html, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", without_scripts)
    text = (
        text.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
    )
    return re.sub(r"\s+", " ", text).strip()


def _analyze_page_text(page_text: str, parsed: ParsedUrl) -> list[Finding]:
    """Phishing-linguistic analysis of the fetched page's visible text."""
    visible = _strip_html(page_text)
    if not visible:
        return []
    profile = analyze_text(visible)
    findings = findings_from_profile(profile)
    return findings


def _correlate_context(parsed: ParsedUrl, context: str) -> list[Finding]:
    """Findings from the text the URL appeared in (e.g. an email body)."""
    findings: list[Finding] = []
    lowered = context.lower()
    if parsed.normalized.lower() not in lowered and parsed.host.lower() not in lowered:
        return findings
    profile = analyze_text(context)
    if profile.matches.get("credential"):
        findings.append(
            Finding(
                code="PHISH.CREDENTIAL_CONTEXT_LINK",
                title="Credential-themed message contains this link",
                detail=(
                    "This URL appears in text that also asks for credentials or "
                    "sensitive data. A legitimate message does not need to combine "
                    "both."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.PHISHING,
                category="phishing",
                weight=14.0,
            )
        )
    return findings


def _recommendations_for(result: AnalysisResult) -> list[Recommendation]:
    from ..constants import VERDICT_ACTIONS

    codes = {f.code for f in result.findings}
    recommendations: list[Recommendation] = []
    verdict_action = VERDICT_ACTIONS.get(result.verdict.value, "")
    if verdict_action:
        recommendations.append(Recommendation(action=verdict_action, priority="high"))
    if "URL.NO_TLS" in codes:
        recommendations.append(
            Recommendation(
                action="Do not enter any credentials or personal data on this page; the connection is not encrypted.",
                priority="high",
                rationale="Plain HTTP exposes all transmitted data.",
            )
        )
    if {"URL.BRAND_IMPERSONATION", "PHISH.LINK_TEXT_MISMATCH"} & codes:
        recommendations.append(
            Recommendation(
                action="Verify the organisation through its official website or app, typed manually, not via this link.",
                priority="high",
                rationale="The domain impersonates a known brand.",
            )
        )
    if "URL.HOSTNAME_MISMATCH" in codes or "TLS.SELF_SIGNED" in codes:
        recommendations.append(
            Recommendation(
                action="Treat any browser certificate warning as a hard stop and do not click through it.",
                priority="high",
                rationale="The certificate does not authenticate this host.",
            )
        )
    if "URL.SSRF_BLOCKED" in codes or "URL.BLOCKED_REDIRECT" in codes:
        recommendations.append(
            Recommendation(
                action="Report this URL to your security team; it attempted to reach internal network resources.",
                priority="high",
                rationale="Possible SSRF / internal-reconnaissance attempt.",
            )
        )
    return recommendations


def _parsed_summary(parsed: ParsedUrl) -> dict[str, Any]:
    return {
        "raw": parsed.raw,
        "normalized": parsed.normalized,
        "scheme": parsed.scheme,
        "host": parsed.host,
        "registrable_domain": parsed.registrable,
        "tld": parsed.tld,
        "port": parsed.port,
        "path": parsed.path,
        "subdomain_count": parsed.subdomain_count,
        "is_ip_literal": parsed.is_ip_literal,
        "is_punycode": parsed.is_punycode,
        "url_length": parsed.full_url_length,
        "host_length": parsed.host_length,
        "warnings": parsed.warnings,
    }


async def analyze_url(
    url: str,
    *,
    config: UrlAnalyzerConfig | None = None,
    reputation: ReputationAggregator | None = None,
) -> AnalysisResult:
    """Convenience entry point for a one-off URL analysis."""
    analyzer = UrlAnalyzer(config=config or UrlAnalyzerConfig(), reputation=reputation)
    try:
        return await analyzer.analyze(url)
    finally:
        await analyzer.aclose()