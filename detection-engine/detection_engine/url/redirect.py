"""Redirect-chain analysis.

Redirect chains are where most benign-looking links become malicious:

``https://tinyurl.com/xyz`` -> ``https://bit.ly/abc`` -> ``http://10.0.0.5/...``

Every hop is re-validated by :class:`~detection_engine.security.ssrf.SsrfSafeFetcher`
before it is followed, so a public URL can never be used to reach private space.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..models import Finding, Severity, SignalSource
from ..security.ssrf import FetchResult
from .normalizer import ParsedUrl, registrable_domain

__all__ = ["RedirectAnalysis", "analyze_redirects"]


@dataclass(slots=True)
class RedirectAnalysis:
    """Summary of an observed redirect chain."""

    chain: list[str] = field(default_factory=list)
    hops: list[dict[str, object]] = field(default_factory=list)
    final_url: str = ""
    final_host: str = ""
    final_scheme: str = ""
    cross_domain_hops: int = 0
    https_downgrade: bool = False
    host_changes: list[tuple[str, str]] = field(default_factory=list)
    blocked_hop: dict[str, object] | None = None
    destination_hidden: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "chain": self.chain,
            "hops": self.hops,
            "final_url": self.final_url,
            "final_host": self.final_host,
            "cross_domain_hops": self.cross_domain_hops,
            "https_downgrade": self.https_downgrade,
            "host_changes": [{"from": a, "to": b} for a, b in self.host_changes],
            "blocked_hop": self.blocked_hop,
            "destination_hidden": self.destination_hidden,
        }


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _registrable(url: str) -> str:
    try:
        return registrable_domain(urlsplit(url).hostname or "")[0]
    except Exception:  # pragma: no cover - defensive
        return ""


def analyze_redirects(parsed: ParsedUrl, fetch: FetchResult | None) -> list[Finding]:
    """Derive findings from a completed (or failed) fetch."""
    findings: list[Finding] = []
    if fetch is None:
        return findings

    hops = fetch.redirects
    chain = [parsed.normalized] + [str(h.get("to")) for h in hops]
    if fetch.final_url:
        chain.append(fetch.final_url)
    # de-duplicate while preserving order
    seen: set[str] = set()
    ordered_chain = [c for c in chain if not (c in seen or seen.add(c))]

    original_registrable = _registrable(parsed.normalized)
    final_host = _host(fetch.final_url or parsed.normalized)

    cross_domain = [
        h for h in hops if str(h.get("to")) and _registrable(str(h["to"])) != original_registrable
    ]
    host_changes = [
        (str(h.get("from")), str(h.get("to"))) for h in hops if _host(str(h.get("from"))) != _host(str(h.get("to")))
    ]

    # ------------------------------------------------------- blocked hop
    if fetch.blocked and fetch.error:
        # Only a policy refusal is evidence about the *destination*.  An
        # unreachable host, a redirect loop and an over-long chain are all
        # "blocked" in the sense that the fetch stopped, but none of them is an
        # SSRF attempt and none of them should dominate the verdict.
        policy_block = fetch.blocked_reason == "ssrf_policy"
        if policy_block:
            title = "Redirect led to a blocked destination"
            detail = (
                f"{fetch.error}. CyberShield refused to follow the redirect "
                "because the destination pointed at private or reserved network "
                "space (a Server-Side Request Forgery attempt)."
            )
            severity, weight, authoritative = Severity.CRITICAL, 30.0, True
        elif fetch.blocked_reason == "redirect_limit":
            title = "Redirect chain is too long"
            detail = (
                f"{fetch.error}. Long redirect chains are used to launder a "
                "shortened or deceptive link past URL filters and to hide the "
                "real destination behind several hops."
            )
            severity, weight, authoritative = Severity.MEDIUM, 12.0, False
        elif fetch.blocked_reason == "redirect_loop":
            title = "Redirect loop detected"
            detail = (
                f"{fetch.error}. A link that redirects to itself has no reachable "
                "destination and is often used to keep a tracking pixel or a "
                "malicious destination reachable without appearing to change."
            )
            severity, weight, authoritative = Severity.LOW, 6.0, False
        else:
            title = "The destination could not be reached"
            detail = (
                f"{fetch.error}. This is not a security signal by itself - the "
                "site may simply be offline - but it does mean no page content "
                "was retrieved for analysis."
            )
            severity, weight, authoritative = Severity.INFO, 0.0, False

        findings.append(
            Finding(
                code="URL.BLOCKED_REDIRECT",
                title=title,
                detail=detail,
                severity=severity,
                source=SignalSource.URL_REDIRECT,
                category="network",
                weight=weight,
                authoritative=authoritative,
                evidence={
                    "error": fetch.error,
                    "reason": fetch.blocked_reason,
                    "chain": ordered_chain,
                },
            )
        )
        return findings

    # ------------------------------------------------------- long chains
    hop_count = len(hops)
    if hop_count == 0 and fetch.final_url:
        # No redirect observed. Nothing to report.
        if fetch.final_url != parsed.normalized and _host(fetch.final_url) != parsed.host:
            findings.append(
                Finding(
                    code="URL.SILENT_REDIRECT",
                    title="Destination differs from the submitted link",
                    detail=(
                        f"After fetching, the live destination was {fetch.final_url} "
                        f"rather than {parsed.normalized}. The submitted host "
                        "'redirects' without a Location header visible to the client."
                    ),
                    severity=Severity.MEDIUM,
                    source=SignalSource.URL_REDIRECT,
                    category="redirect",
                    weight=12.0,
                    evidence={"final_url": fetch.final_url},
                )
            )
        return findings

    if hop_count >= 3:
        findings.append(
            Finding(
                code="URL.EXCESSIVE_REDIRECTS",
                title=f"Long redirect chain ({hop_count} hops)",
                detail=(
                    f"The link passes through {hop_count} redirects before reaching "
                    "its destination. Long chains are used to dilute link scanners, "
                    "hide the final host from users and rotate infrastructure."
                ),
                severity=Severity.MEDIUM if hop_count < 6 else Severity.HIGH,
                source=SignalSource.URL_REDIRECT,
                category="redirect",
                weight=12.0 if hop_count < 6 else 18.0,
                evidence={"hops": ordered_chain},
            )
        )
    elif hop_count >= 2:
        findings.append(
            Finding(
                code="URL.MULTI_HOP_REDIRECT",
                title="Link passes through multiple redirects",
                detail=(
                    f"{hop_count} redirects were followed. Multi-hop chains make it "
                    "hard to see where a link really goes."
                ),
                severity=Severity.LOW,
                source=SignalSource.URL_REDIRECT,
                category="redirect",
                weight=6.0,
                evidence={"hops": ordered_chain},
            )
        )

    # ----------------------------------------------------- cross-domain
    if cross_domain and original_registrable and _registrable(fetch.final_url) != original_registrable:
        distinct = {(_registrable(str(h["to"]))) for h in cross_domain}
        findings.append(
            Finding(
                code="URL.CROSS_DOMAIN_REDIRECT",
                title="Redirect leaves the submitted domain",
                detail=(
                    f"The submitted host '{parsed.host}' redirects to "
                    f"'{final_host}'. {len(distinct)} unrelated registrable "
                    "domain(s) participate in the chain: "
                    f"{', '.join(sorted(d for d in distinct if d))}. Legitimate "
                    "links rarely bounce through unrelated domains."
                ),
                severity=Severity.MEDIUM,
                source=SignalSource.URL_REDIRECT,
                category="redirect",
                weight=12.0,
                evidence={
                    "from": original_registrable,
                    "to": _registrable(fetch.final_url),
                    "hosts": sorted({_host(str(h["to"])) for h in cross_domain}),
                },
            )
        )

    # ------------------------------------------------- HTTPS downgrade
    final_scheme = urlsplit(fetch.final_url or parsed.normalized).scheme.lower()
    if parsed.is_https and final_scheme == "http":
        findings.append(
            Finding(
                code="URL.HTTPS_DOWNGRADE",
                title="Connection downgraded to plain HTTP",
                detail=(
                    "The link started on HTTPS but ends on HTTP. Anything you "
                    "submit on the final page travels unencrypted and can be "
                    "intercepted."
                ),
                severity=Severity.HIGH,
                source=SignalSource.URL_REDIRECT,
                category="network",
                weight=15.0,
                evidence={"final_url": fetch.final_url},
            )
        )

    # ------------------------------------------- cross-registrable payload
    if _registrable(fetch.final_url) != original_registrable:
        original_label = original_registrable.split(".")[0]
        final_label = _registrable(fetch.final_url).split(".")[0]
        from ..url.domain import _is_dissimilar_but_close

        explanation = _is_dissimilar_but_close(final_label, original_label)
        if explanation:
            findings.append(
                Finding(
                    code="URL.REDIRECT_TO_LOOKALIKE",
                    title="Redirect target mimics the submitted domain",
                    detail=(
                        f"'{_registrable(fetch.final_url)}' ({explanation}) is a "
                        "different domain designed to be confused with "
                        f"'{original_registrable}'. This is the standard way a "
                        "shortened or legitimate-looking link delivers a "
                        "credential-stealing page."
                    ),
                    severity=Severity.HIGH,
                    source=SignalSource.URL_REDIRECT,
                    category="phishing",
                    weight=22.0,
                    evidence={
                        "from": original_registrable,
                        "to": _registrable(fetch.final_url),
                        "explanation": explanation,
                    },
                )
            )

    # ------------------------------------------------ hidden destination
    if hops:
        findings.append(
            Finding(
                code="URL.DESTINATION_HIDDEN",
                title="Link hides its real destination",
                detail=(
                    "Because the link redirects, the address bar will not show "
                    f"'{final_host}' until after the click. Verify the destination "
                    "before entering any credentials."
                ),
                severity=Severity.LOW,
                source=SignalSource.URL_REDIRECT,
                category="redirect",
                weight=5.0,
                evidence={"final_host": final_host},
            )
        )
    return findings


def build_redirect_analysis(parsed: ParsedUrl, fetch: FetchResult | None) -> RedirectAnalysis:
    """Structured redirect summary for the report payload."""
    analysis = RedirectAnalysis()
    if fetch is None:
        return analysis
    hops = fetch.redirects
    analysis.hops = list(hops)
    analysis.chain = [parsed.normalized] + [str(h.get("to")) for h in hops]
    analysis.final_url = fetch.final_url or parsed.normalized
    analysis.final_host = _host(analysis.final_url)
    analysis.final_scheme = urlsplit(analysis.final_url).scheme.lower()
    original_registrable = _registrable(parsed.normalized)
    analysis.cross_domain_hops = sum(
        1 for h in hops if str(h.get("to")) and _registrable(str(h["to"])) != original_registrable
    )
    analysis.https_downgrade = parsed.is_https and analysis.final_scheme == "http"
    analysis.host_changes = [
        (str(h.get("from")), str(h.get("to"))) for h in hops if _host(str(h.get("from"))) != _host(str(h.get("to")))
    ]
    analysis.blocked_hop = next((h for h in hops if h.get("blocked")), None)
    analysis.destination_hidden = bool(hops)
    return analysis