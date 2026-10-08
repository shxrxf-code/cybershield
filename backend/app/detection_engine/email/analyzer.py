"""Email scan pipeline: parse, analyse headers and body, run URL detectors.

Order of operations
-------------------
1. Parse the message (:mod:`.parser`).
2. Run header-based detectors - authentication, identity, transport anomalies.
3. Run body detectors - text/social engineering, HTML markup.
4. Run the URL detector over every URL in the body and in the ``From`` /
   ``Reply-To`` domains, so a phishing message's link gets the same scrutiny as
   one submitted directly.
5. Ask the file pipeline about each attachment's *structure only*.

Nothing in this pipeline renders HTML, fetches a URL, opens an attachment or
executes a macro.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.detection_engine.email.header_analyzer import (
    analyse_attachments,
    analyse_authentication,
    analyse_headers,
    analyse_identity,
    analyse_recipient_analysis,
)
from app.detection_engine.email.parser import ParsedEmail, parse_email
from app.detection_engine.phishing.heuristics import (
    analyse_html_markup,
    analyse_text_content,
)
from app.detection_engine.text import extract_urls
from app.detection_engine.url.analyzer import analyse_url_structure
from app.detection_engine.url.parser import parse_url
from app.schemas.common import Severity, SignalSource
from app.schemas.signal import DetectionSignal, Indicator, IndicatorType, SignalBundle

logger = logging.getLogger(__name__)

#: Cap on URLs analysed per message. A message quoting a forum thread can contain
#: hundreds of links; analysing all of them would let an attacker pad a message
#: with clean URLs to dilute the malicious ones.
MAX_URLS_ANALYSED = 40


@dataclass(slots=True)
class EmailAnalysisResult:
    """Structural email analysis, before external scanners and scoring."""

    parsed: ParsedEmail
    signals: list[DetectionSignal] = field(default_factory=list)
    bundle: SignalBundle = field(default_factory=SignalBundle)
    urls: list[str] = field(default_factory=list)
    #: Subject-line and body risk, kept separate for the report's explanation.
    phishing_score_hint: float = 0.0

    @property
    def attachment_count(self) -> int:
        return len(self.parsed.attachments)


def analyse_email(
    raw_message: bytes | str,
    *,
    subject_override: str | None = None,
    sender_override: str | None = None,
    headers_only: bool = False,
    max_bytes: int = 25 * 1024 * 1024,
) -> EmailAnalysisResult:
    """Run the full static email analysis pipeline.

    Args:
        raw_message: Complete RFC 5322 source.
        subject_override: Client-supplied subject, used when the message could
            not be parsed.
        sender_override: Client-supplied sender, same purpose.
        headers_only: Analyse headers and skip body/URL work, for a fast
            preliminary check.
        max_bytes: Size ceiling; a larger message is refused.

    Returns:
        An :class:`EmailAnalysisResult` holding the parsed message and the
        signals produced. Scoring is *not* performed here.

    Raises:
        ValueError: If the message exceeds ``max_bytes``.
    """
    parsed = parse_email(raw_message, max_bytes=max_bytes)

    if subject_override and not parsed.subject:
        parsed.subject = subject_override[:998]
    if sender_override and not parsed.sender:
        from app.security.sanitize import sanitize_email_address

        parsed.sender = sanitize_email_address(sender_override)
        if parsed.sender and "@" in parsed.sender:
            parsed.sender_domain = parsed.sender.rsplit("@", 1)[1]

    result = EmailAnalysisResult(parsed=parsed)

    # ---- Headers ---------------------------------------------------
    result.signals.extend(analyse_authentication(parsed))
    result.signals.extend(analyse_identity(parsed))
    result.signals.extend(analyse_headers(parsed))
    result.signals.extend(analyse_recipient_analysis(parsed))
    result.signals.extend(_analyse_subject(parsed))

    if headers_only:
        result.bundle = SignalBundle(signals=result.signals)
        return result

    # ---- Body ------------------------------------------------------
    body_text = parsed.body_text
    if parsed.body_html:
        result.signals.extend(analyse_html_markup(parsed.body_html))
        # Scan the HTML as text too: markup analysis alone misses the wording.
        body_text = f"{body_text}\n{parsed.body_html}"

    combined_text = "\n\n".join(part for part in parsed.text_parts if part)
    if combined_text:
        result.signals.extend(analyse_text_content(combined_text))
        result.signals.extend(_analyse_to_separators(combined_text))

    # ---- URLs ------------------------------------------------------
    result.signals.extend(_analyse_message_urls(parsed, body_text))
    result.signals.extend(analyse_attachments(parsed))

    # ---- Body phishing strength hint -------------------------------
    result.phishing_score_hint = _phishing_hint(result.signals)
    result.bundle = SignalBundle(signals=result.signals)
    return result


def _analyse_subject(parsed: ParsedEmail) -> list[DetectionSignal]:
    """Analyse the subject line on its own.

    The subject is what a user decides on in a notification preview, so it is
    worth its own pass: a subject that combines urgency with a money-related
    noun is a classic lure even when the body is empty.
    """
    if not parsed.subject:
        return []
    signals = analyse_text_content(parsed.subject)
    return [signal for signal in signals if signal.code.startswith("phish.")]


def _analyse_to_separators(text: str) -> list[DetectionSignal]:
    """Detect spaced-out and homoglyph-obfuscated text.

    Attackers write ``V-I-E-W S-U-S-P-E-C-T-I-O-N`` and leetspeak to defeat
    keyword filters. Reconstructing the word is cheap and catches a real evasion
    technique that a plain keyword search misses.
    """
    from app.detection_engine.text import compact_text

    compacted = compact_text(text)
    if compacted == text:
        return []

    # Only report when compaction reveals keyword hits that the raw text missed.
    raw_hits = sum(1 for signal in analyse_text_content(text))
    compacted_signals = [
        signal
        for signal in analyse_text_content(compacted)
        if signal.code.startswith(("phish.urgency", "phish.credential", "phish.financial", "phish.secrecy"))
    ]
    if not compacted_signals or raw_hits >= len(compacted_signals):
        return []

    return [
        DetectionSignal(
            code="phish.character_separated_obfuscation",
            title="Text contains obfuscated keywords",
            description=(
                "Removing separators, spacing and character substitutions from the message "
                "reveals phishing keywords that are not directly readable. This is a "
                "deliberate technique to defeat keyword-based filters and to make the text "
                "appear unusual to the reader."
            ),
            severity=Severity.MEDIUM,
            category="obfuscation",
            source=SignalSource.HEURISTIC,
            confidence=0.7,
            evidence={"revealed_signals": [s.code for s in compacted_signals]},
        )
    ]


def _analyse_message_urls(parsed: ParsedEmail, body_text: str) -> list[DetectionSignal]:
    """Run the URL detector over every link in the message."""
    urls = extract_urls(body_text or "\n".join(parsed.text_parts))
    # De-obfuscated URLs: the visible text of an anchor tag is analysed by the
    # HTML detector, and the href attribute is what extract_urls picks up.
    signals: list[DetectionSignal] = []
    seen: set[str] = set()
    analysed = 0

    for raw in urls:
        if analysed >= MAX_URLS_ANALYSED:
            break
        key = raw.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        analysed += 1

        try:
            parsed_url = parse_url(raw)
        except Exception:  # noqa: BLE001 - a malformed URL is itself a finding
            continue

        signals.extend(analyse_url_structure(parsed_url, source_text=body_text[:4000]))

    # Sender domain and reply-to are part of the attack surface too.
    for domain in filter(None, (parsed.sender_domain, parsed.reply_to_domain)):
        synthetic = f"http://{domain}/"
        try:
            signals.extend(analyse_url_structure(parse_url(synthetic)))
        except Exception:  # noqa: BLE001
            continue

    if analysed >= MAX_URLS_ANALYSED and len(urls) > MAX_URLS_ANALYSED:
        signals.append(
            DetectionSignal(
                code="email.url_count_capped",
                title=f"Only the first {MAX_URLS_ANALYSED} links were analysed",
                description=(
                    f"The message contains {len(urls)} links, more than the analysis cap. "
                    "Links beyond the cap were not examined, so a malicious link placed "
                    "after the cap would not be reported."
                ),
                severity=Severity.LOW,
                category="policy",
                source=SignalSource.POLICY,
                confidence=0.9,
                evidence={"url_count": len(urls), "analysed": analysed},
            )
        )

    return signals


def _phishing_hint(signals: list[DetectionSignal]) -> float:
    """A coarse 0-1 hint for the report, not the score itself.

    Derived from the body-content signals only, so a report can say "the wording
    scored X on phishing indicators" without implying the overall verdict came
    from language alone.
    """
    relevant = [s for s in signals if s.code.startswith("phish.")]
    if not relevant:
        return 0.0
    total = sum(s.impact for s in relevant)
    return round(min(1.0, total), 3)


def summarise_parsed(parsed: ParsedEmail) -> dict[str, Any]:
    """Serialise the parts of a message that belong in the report."""
    return {
        "subject": parsed.subject,
        "sender": parsed.sender,
        "sender_name": parsed.sender_name,
        "sender_domain": parsed.sender_domain,
        "reply_to": parsed.reply_to,
        "return_path": parsed.return_path,
        "recipient_count": len(parsed.recipients) + len(parsed.cc) + len(parsed.bcc),
        "date": parsed.date,
        "message_id": parsed.message_id,
        "authentication": parsed.authentication,
        "originating_ip": parsed.originating_ip,
        "mail_client": parsed.mail_client,
        "attachment_count": len(parsed.attachments),
        "attachments": [
            {
                "filename": item.filename,
                "content_type": item.content_type,
                "size_bytes": item.size,
                "sha256": item.sha256,
                "is_inline": item.is_inline,
            }
            for item in parsed.attachments[:25]
        ],
        "inline_image_count": parsed.inline_image_count,
        "received_hops": len(parsed.received_chain),
        "parse_errors": parsed.parse_errors,
        "truncated": parsed.truncated,
    }


__all__ = [
    "MAX_URLS_ANALYSED",
    "EmailAnalysisResult",
    "analyse_email",
    "summarise_parsed",
]