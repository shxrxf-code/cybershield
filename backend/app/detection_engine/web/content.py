"""Bounded HTML content analysis for fetched pages.

Nothing here renders, scripts or embeds the page. It extracts the bits of a
document that a human would notice - the title, whether the page asks for a
password, and where a submitted form would send it - and turns each observation
into an explainable signal. Analysis is capped so a pathological page cannot
consume unbounded time.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from app.detection_engine.text import truncate_for_display
from app.schemas.common import Severity, SignalSource
from app.schemas.signal import DetectionSignal, Indicator, IndicatorType

logger = logging.getLogger(__name__)

#: Bounded analysis window. The fetch itself is capped at ``url_fetch_max_bytes``;
#: this is the substring handed to the parser so a huge HTML file is only
#: partially inspected while still seeing the head of the document.
_ANALYSIS_WINDOW = 1_500_000

#: Title keywords that line up with the vocabulary of credential-harvesting
#: pages. Presence alone is an INFO observation; it never decides a verdict.
_LOGIN_TITLE_RE = re.compile(
    r"\b(sign\s*in|log\s*in|verify|verification|authenticate|confirm\s+(your\s+)?(account|identity)|"
    r"secure\s+(your\s+)?account|unlock\s+(your\s+)?account|session\s+expired)\b",
    re.IGNORECASE,
)

#: Keywords suggesting an account or financial focus; used to grade a page that
#: also collects a password.
_SENSITIVE_TITLE_RE = re.compile(
    r"\b(account|bank|wallet|payment|billing|password|credential|identity|security)\b",
    re.IGNORECASE,
)


@dataclass(slots=True)
class WebContentResult:
    """Observations from a fetched page."""

    title: str | None = None
    signals: list[DetectionSignal] = field(default_factory=list)
    form_count: int = 0
    password_form_count: int = 0
    external_form_action_count: int = 0
    truncated: bool = False

    @property
    def has_password_collection(self) -> bool:
        return self.password_form_count > 0


class _FormParser(HTMLParser):
    """Collects form actions and input types without rendering anything."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[tuple[str | None, bool]] = []  # (action or None, has_password)
        self._in_form = False
        self._current_action: str | None = None
        self._current_has_password = False
        self.title: str | None = None
        self._in_title = False
        self._title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:  # noqa: N802
        attributes = dict(attrs)
        lowered = tag.lower()
        if lowered == "form":
            self._in_form = True
            self._current_action = attributes.get("action")
            self._current_has_password = False
        elif lowered == "input":
            if self._in_form and (attributes.get("type") or "text").lower() in (
                "password",
                "text",
            ):
                # Any visible input that can hold a secret counts as collection.
                self._current_has_password = True
        elif lowered == "title":
            self._in_title = True
            self._title_parts = []

    def handle_endtag(self, tag: str) -> None:  # noqa: N802
        lowered = tag.lower()
        if lowered == "form" and self._in_form:
            self.forms.append((self._current_action, self._current_has_password))
            self._in_form = False
            self._current_action = None
            self._current_has_password = False
        elif lowered == "title" and self._in_title:
            self._in_title = False
            title = " ".join("".join(self._title_parts).split()).strip()
            if title:
                self.title = title[:200]

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)


def analyse_web_content(html: bytes, *, page_host: str) -> WebContentResult:
    """Extract title and form observations from fetched HTML bytes."""
    result = WebContentResult()

    # Decode pragmatically: HTML declares its charset mid-document, so a blind
    # utf-8 decode would turn windows-1252 pages into mojibake. latin-1 never
    # fails and preserves byte identity for pattern matching.
    text = html[:_ANALYSIS_WINDOW].decode("latin-1", errors="replace")

    parser = _FormParser()
    try:
        parser.feed(text)
    except Exception:  # noqa: BLE001 - a pathological page must not fail the scan
        logger.warning("HTML parsing failed; page content analysis degraded")

    result.title = truncate_for_display(parser.title, 200) if parser.title else None
    result.form_count = len(parser.forms)
    result.truncated = len(html) > _ANALYSIS_WINDOW

    password_forms: list[tuple[str | None, bool]] = []
    for action, has_password in parser.forms:
        if has_password:
            password_forms.append((action, has_password))
    result.password_form_count = len(password_forms)

    external_actions: list[str] = []
    for action, _has_password in parser.forms:
        if not action:
            continue
        target = urljoin(f"http://{page_host}/", action)
        target_host = urlsplit(target).hostname or ""
        target_host = target_host.lower()
        if target_host and target_host != page_host.lower():
            external_actions.append(target_host)

    result.external_form_action_count = len(external_actions)

    # ---------------------------------------------------------------
    # Signals
    # ---------------------------------------------------------------
    if result.truncated:
        result.signals.append(
            DetectionSignal(
                code="web.truncated_fetch",
                title="Page was only partially analysed",
                description=(
                    f"The fetched page exceeded the analysis window of {_ANALYSIS_WINDOW} bytes, "
                    "so only its beginning was inspected. Content beyond the cap was not examined."
                ),
                severity=Severity.LOW,
                category="policy",
                source=SignalSource.POLICY,
                confidence=0.9,
                evidence={"window_bytes": _ANALYSIS_WINDOW},
            )
        )

    if parser.title and _LOGIN_TITLE_RE.search(parser.title):
        result.signals.append(
            DetectionSignal(
                code="web.login_page_title",
                title="Page title advertises a login or verification flow",
                description=(
                    f"The page title '{truncate_for_display(parser.title, 120)}' matches the "
                    "vocabulary of sign-in and account-verification pages, which is the standard "
                    "pretext for credential phishing."
                ),
                severity=Severity.INFO,
                category="reputation_context",
                source=SignalSource.HEURISTIC,
                confidence=0.5,
                evidence={"title": parser.title[:200]},
            )
        )

    if result.password_form_count:
        evidence: dict[str, object] = {
            "password_form_count": result.password_form_count,
            "form_count": result.form_count,
        }
        title_hint = bool(parser.title and _SENSITIVE_TITLE_RE.search(parser.title))
        evidence["sensitive_title"] = title_hint

        # A page that asks for a password and would POST it to a different host
        # is the concrete structure of a credential-harvesting page.
        if external_actions and not title_hint:  # design: cross-host is the high-signal case
            pass
        if external_actions:
            result.signals.append(
                DetectionSignal(
                    code="web.cross_host_form_submission",
                    title="Password form submits to a different host",
                    description=(
                        "The page collects a password or secret through a form whose action "
                        "points to a different host (" + ", ".join(external_actions[:3])
                        + "). Legitimate sites submit to their own origin, so a cross-host "
                        "form action is a strong indicator of credential theft."
                    ),
                    severity=Severity.HIGH,
                    category="deception",
                    source=SignalSource.STRUCTURAL,
                    confidence=0.75,
                    evidence=evidence,
                    indicators=tuple(
                        Indicator(type=IndicatorType.DOMAIN, value=host)
                        for host in external_actions[:5]
                    ),
                )
            )
        else:
            result.signals.append(
                DetectionSignal(
                    code="web.password_form",
                    title="Page collects a password or secret",
                    description=(
                        f"The page contains {result.password_form_count} form(s) with a field "
                        "for a password or secret. Credential harvesting is the most common "
                        "phishing objective, and a login form is the collection point."
                    ),
                    severity=Severity.MEDIUM if title_hint else Severity.LOW,
                    category="deception",
                    source=SignalSource.HEURISTIC,
                    confidence=0.5,
                    evidence=evidence,
                )
            )

    return result


__all__ = ["WebContentResult", "analyse_web_content"]