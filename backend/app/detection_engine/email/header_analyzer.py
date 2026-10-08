"""Email-specific detectors: authentication, header anomalies and attachments.

Each detector returns :class:`~app.schemas.signal.DetectionSignal` objects and
never a verdict. Email is the scan type where the *headers* usually carry more
decisive evidence than the body: a message whose DMARC policy is ``reject`` but
whose SPF and DKIM both fail is spoofed regardless of how polished the body is.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

from app.detection_engine.email.parser import ParsedEmail
from app.schemas.common import Severity, SignalSource
from app.schemas.signal import DetectionSignal, Indicator, IndicatorType

logger = logging.getLogger(__name__)

#: Free-mail and webmail domains. A message claiming to be from a bank but sent
#: from one of these is not spoofed - it is simply not a bank.
CONSUMER_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "yahoo.com",
        "yahoo.co.uk",
        "ymail.com",
        "icloud.com",
        "me.com",
        "aol.com",
        "protonmail.com",
        "proton.me",
        "gmx.com",
        "mail.com",
        "yandex.ru",
        "qq.com",
        "163.com",
        "naver.com",
        "zoho.com",
    }
)

#: Authentication verdicts that indicate the sending domain was not verified.
_AUTH_FAILURES = frozenset({"fail", "softfail", "permerror", "temperror"})

#: Brand names whose messages are the most impersonated, mapped to the domains
#: that legitimately send them. Used for display-name/domain mismatch.
_IMPERSONATED_BRANDS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com", "paypal.me", "paypalobjects.com"}),
    "apple": frozenset({"apple.com", "icloud.com", "me.com"}),
    "microsoft": frozenset({"microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com"}),
    "google": frozenset({"google.com", "gmail.com", "googlemail.com"}),
    "amazon": frozenset({"amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com"}),
    "netflix": frozenset({"netflix.com"}),
    "facebook": frozenset({"facebook.com", "fb.com", "meta.com"}),
    "instagram": frozenset({"instagram.com"}),
    "linkedin": frozenset({"linkedin.com"}),
    "dropbox": frozenset({"dropbox.com"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "office365": frozenset({"microsoft.com", "office.com", "microsoftonline.com"}),
    "chase": frozenset({"chase.com"}),
    "wells fargo": frozenset({"wellsfargo.com"}),
    "bank of america": frozenset({"bankofamerica.com", "bofa.com"}),
    "barclays": frozenset({"barclays.co.uk", "barclays.com"}),
    "hsbc": frozenset({"hsbc.co.uk", "hsbc.com"}),
    "santander": frozenset({"santander.co.uk", "santander.com"}),
    "irs": frozenset({"irs.gov", "treasury.gov"}),
    "hmrc": frozenset({"hmrc.gov.uk", "gov.uk"}),
    "social security": frozenset({"ssa.gov"}),
    "netflix billing": frozenset({"netflix.com"}),
    "coinbase": frozenset({"coinbase.com"}),
    "binance": frozenset({"binance.com"}),
    "metamask": frozenset({"metamask.io"}),
}

#: Attachment types that execute code or enable it on a common platform.
DANGEROUS_ATTACHMENT_TYPES: dict[str, str] = {
    "application/x-msdownload": "Windows executable",
    "application/x-dosexec": "Windows executable",
    "application/x-executable": "Executable",
    "application/vnd.microsoft.portable-executable": "Windows executable",
    "application/x-dosexec": "Windows executable",
    "application/x-msdos-program": "DOS executable",
    "application/x-sh": "Shell script",
    "application/x-shellscript": "Shell script",
    "application/javascript": "JavaScript",
    "text/javascript": "JavaScript",
    "application/x-ms-shortcut": "Windows shortcut (LNK)",
    "application/x-msi": "Windows installer",
    "application/vnd.ms-cab-compressed": "Windows cabinet (may embed executables)",
    "application/x-bat": "Batch script",
    "application/vnd.ms-cab-compressed": "Windows cabinet",
    "application/x-ms-shortcut": "Windows shortcut",
    "application/hta": "HTML application (runs script on open)",
    "application/x-java-archive": "Java archive",
    "application/java-archive": "Java archive",
}

#: Office documents can carry macros or external references.
_MACRO_RISKY_OFFICE_TYPES: frozenset[str] = frozenset(
    {
        "application/msword",
        "application/vnd.ms-word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/rtf",
    }
)

_HOST_LABEL_RE = re.compile(r"^[\w\-.]{1,63}$")


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
def analyse_authentication(parsed: ParsedEmail) -> list[DetectionSignal]:
    """Evaluate SPF, DKIM and DMARC from ``Authentication-Results``.

    The results come from a receiving mail server, not from the sender, which
    makes them the most trustworthy field in a message. A ``reject`` DMARC policy
    plus failing SPF *and* DKIM is about as close to proof of spoofing as email
    analysis gets.
    """
    auth = parsed.authentication
    if not auth.get("available"):
        return []

    signals: list[DetectionSignal] = []
    spf = str(auth.get("spf", "absent"))
    dkim = str(auth.get("dkim", "absent"))
    dmarc = str(auth.get("dmarc", "absent"))
    failures = [m for m in ("spf", "dkim") if auth.get(m) in _AUTH_FAILURES]

    if not failures:
        return signals

    has_reject_policy = _dmarc_policy_is_reject(auth)
    both_failed = len(failures) == 2

    if both_failed and has_reject_policy:
        severity = Severity.CRITICAL
        title = "Message failed email authentication (SPF, DKIM and DMARC)"
        description = (
            "The receiving mail server reports that the message failed both SPF and DKIM, "
            "and the sender's DMARC policy is set to reject. That combination means the "
            "message was not sent from the domain it claims to come from."
        )
    elif both_failed:
        severity = Severity.HIGH
        title = "Message failed SPF and DKIM authentication"
        description = (
            "The receiving mail server reports that neither SPF nor DKIM validated for the "
            "sending domain. The visible sender address therefore cannot be trusted."
        )
    else:
        failed = failures[0].upper()
        severity = Severity.HIGH if has_reject_policy else Severity.MEDIUM
        title = f"{failed} authentication failed"
        description = (
            f"The receiving mail server reports that {failed} validation failed for the "
            "sending domain. "
            + (
                "The sender's DMARC policy requires rejection of such mail, so it should "
                "never have been delivered."
                if has_reject_policy
                else "The visible sender address may not represent the real sender."
            )
        )

    signals.append(
        DetectionSignal(
            code=f"email.auth_{failures[0]}_failure",
            title=title,
            description=description,
            severity=severity,
            category="authentication",
            source=SignalSource.AUTHENTICATION,
            confidence=0.92 if both_failed else 0.8,
            evidence={
                "spf": spf,
                "dkim": dkim,
                "dmarc": dmarc,
                "dmarc_policy": auth.get("dmarc_policy"),
                "failed_mechanisms": failures,
            },
        )
    )

    if dmarc in _AUTH_FAILURES:
        signals.append(
            DetectionSignal(
                code="email.dmarc_failure",
                title="DMARC alignment check failed",
                description=(
                    "DMARC requires the visible From domain to match the domain that "
                    "authenticated the message. It does not, which is the standard way a "
                    "spoofed message passes a mail client's 'verified sender' indicator."
                ),
                severity=Severity.CRITICAL if both_failed else Severity.HIGH,
                category="authentication",
                source=SignalSource.AUTHENTICATION,
                confidence=0.9,
                evidence={"dmarc": dmarc, "spf": spf, "dkim": dkim},
            )
        )

    return signals


def _dmarc_policy_is_reject(auth: dict[str, Any]) -> bool:
    raw = str(auth.get("raw") or "").lower()
    return "p=reject" in raw or "sp=reject" in raw


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
def analyse_identity(parsed: ParsedEmail) -> list[DetectionSignal]:
    """Compare the visible sender against authentication and reply routing."""
    signals: list[DetectionSignal] = []
    domain = (parsed.sender_domain or "").lower()

    # 1. Display name claims a brand the sending domain does not own.
    display = (parsed.sender_name or "").strip()
    if display and domain:
        normalised_display = _normalise_brand(display)
        for brand, owned_domains in _IMPERSONATED_BRANDS.items():
            if normalised_display != brand:
                continue
            if domain in owned_domains:
                break
            if domain in CONSUMER_DOMAINS:
                # Still worth reporting: a bank name on a free-mail domain is a
                # deliberate impersonation, just a clumsy one.
                signals.append(
                    DetectionSignal(
                        code="email.brand_on_free_domain",
                        title=f"'{display}' sending address is a free-mail domain",
                        description=(
                            f"The message claims to be from {display} but was sent from "
                            f"'{domain}', a consumer mail provider. {display} does not send "
                            "corporate mail from consumer domains."
                        ),
                        severity=Severity.HIGH,
                        category="impersonation",
                        source=SignalSource.STRUCTURAL,
                        confidence=0.85,
                        evidence={
                            "display_name": display,
                            "sender_domain": domain,
                            "brand": brand,
                        },
                        indicators=(
                            Indicator(type=IndicatorType.EMAIL_ADDRESS, value=parsed.sender or ""),
                        ),
                    )
                )
            else:
                signals.append(
                    DetectionSignal(
                        code="email.display_name_brand_mismatch",
                        title=f"Display name claims '{display}' but the domain is '{domain}'",
                        description=(
                            f"The sender is displayed as '{display}', but the actual sending "
                            f"domain is '{domain}', which is not a domain {display} uses. "
                            "Display names are chosen by the sender and are not verified."
                        ),
                        severity=Severity.HIGH,
                        category="impersonation",
                        source=SignalSource.STRUCTURAL,
                        confidence=0.88,
                        evidence={
                            "display_name": display,
                            "sender_domain": domain,
                            "brand": brand,
                            "legitimate_domains": sorted(owned_domains),
                        },
                    )
                )
            break

    # 2. Reply-To points somewhere other than the sending domain.
    reply_domain = parsed.reply_to_domain
    if reply_domain and domain and reply_domain != domain:
        signals.append(
            DetectionSignal(
                code="email.reply_to_mismatch",
                title="Reply-To address uses a different domain",
                description=(
                    f"The message is sent from '{domain}' but a reply would go to "
                    f"'{reply_domain}'. Replying reveals that the message did not come from "
                    "the organisation it appears to, and sends the reply - and anything "
                    "attached to it - to a third party."
                ),
                severity=Severity.HIGH,
                category="impersonation",
                source=SignalSource.STRUCTURAL,
                confidence=0.8,
                evidence={"sender_domain": domain, "reply_to_domain": reply_domain},
                indicators=(
                    Indicator(type=IndicatorType.DOMAIN, value=reply_domain),
                ),
            )
        )

    # 3. Return-Path domain unrelated to the visible sender.
    if parsed.return_path and "@" in parsed.return_path:
        return_domain = parsed.return_path.rsplit("@", 1)[1].lower()
        if domain and return_domain != domain and return_domain not in CONSUMER_DOMAINS:
            # Bounce addresses legitimately differ (SPF alignment uses them), so
            # this is only a mild signal.
            signals.append(
                DetectionSignal(
                    code="email.return_path_mismatch",
                    title="Envelope sender differs from the visible sender",
                    description=(
                        f"The envelope sender is '{parsed.return_path}' while the visible "
                        f"sender is '{parsed.sender}'. This is legal for bounce handling but "
                        "is also how bulk senders hide their infrastructure."
                    ),
                    severity=Severity.LOW,
                    category="transparency",
                    source=SignalSource.STRUCTURAL,
                    confidence=0.5,
                    evidence={"return_path": parsed.return_path, "sender": parsed.sender},
                )
            )

    # 4. Free-mail domain claiming to be a business.
    if domain and domain in CONSUMER_DOMAINS and parsed.has_attachments:
        signals.append(
            DetectionSignal(
                code="email.free_domain_with_attachments",
                title="Consumer mail domain sending attachments",
                description=(
                    f"The message comes from '{domain}' and carries "
                    f"{len(parsed.attachments)} attachment(s). Bulk phishing commonly uses "
                    "free consumer mail accounts, which have no organisational controls."
                ),
                severity=Severity.MEDIUM,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.6,
                evidence={"sender_domain": domain, "attachments": len(parsed.attachments)},
            )
        )

    return signals


def _normalise_brand(display: str) -> str:
    """Reduce a display name to a comparable brand token."""
    lowered = display.lower()
    # Strip common decoration used by attackers.
    for token in (" support", " helpdesk", " service", " team", " official", " admin", " billing", " security", " no-reply", " noreply"):
        if lowered.endswith(token):
            lowered = lowered[: -len(token)]
    return lowered.strip(" .:-").strip()


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------
def analyse_headers(parsed: ParsedEmail) -> list[DetectionSignal]:
    """Look for header anomalies that indicate bulk or deceptive sending."""
    signals: list[DetectionSignal] = []

    # Missing or generic Message-ID is a weak but free signal.
    if not parsed.message_id:
        signals.append(
            DetectionSignal(
                code="email.no_message_id",
                title="Message has no Message-ID header",
                description=(
                    "RFC 5322 requires a Message-ID. Bulk senders frequently omit it "
                    "because it makes threading and deduplication harder for their tooling."
                ),
                severity=Severity.LOW,
                category="transparency",
                source=SignalSource.STRUCTURAL,
                confidence=0.4,
            )
        )

    # Received chain of exactly one hop means nothing was verified in transit.
    if len(parsed.received_chain) == 1:
        signals.append(
            DetectionSignal(
                code="email.single_received_hop",
                title="Message passed through only one mail server",
                description=(
                    "Only one Received header is present, meaning no intermediary mail "
                    "server verified the message's origin. Real mail almost always crosses "
                    "at least one provider hop."
                ),
                severity=Severity.LOW,
                category="transparency",
                source=SignalSource.STRUCTURAL,
                confidence=0.45,
            )
        )

    # Originating IP in a hosting range.
    if parsed.originating_ip:
        try:
            address = ipaddress.ip_address(parsed.originating_ip)
        except ValueError:
            address = None
        if address is not None and _is_hosting_ip(address):
            signals.append(
                DetectionSignal(
                    code="email.originating_ip_datacenter",
                    title="Message originated from a hosting provider",
                    description=(
                        f"The originating IP {parsed.originating_ip} belongs to a cloud or "
                        "hosting provider rather than to a mail provider. Phishing campaigns "
                        "send from rented infrastructure; legitimate corporate mail does not."
                    ),
                    severity=Severity.MEDIUM,
                    category="reputation_context",
                    source=SignalSource.REPUTATION,
                    confidence=0.65,
                    evidence={"originating_ip": parsed.originating_ip},
                    indicators=(
                        Indicator(type=IndicatorType.IP_ADDRESS, value=parsed.originating_ip),
                    ),
                )
            )

    # A header value containing a raw line break means an extra header was
    # appended to the message, which is how header-splitting works. Each value is
    # checked individually: joining them for a report would manufacture exactly
    # the newline this test looks for.
    for key, value in parsed.headers.items():
        if "\n" in value or "\r" in value or "\x00" in value:
            signals.append(
                DetectionSignal(
                    code="email.header_injection",
                    title=f"Header '{key}' contains an embedded line break",
                    description=(
                        f"The '{key}' header contains an embedded newline or null byte. "
                        "Line breaks inside a header are how header-injection and "
                        "header-splitting attacks append extra headers or start a new "
                        "message body that mail clients and gateways render differently."
                    ),
                    severity=Severity.HIGH,
                    category="structural",
                    source=SignalSource.STRUCTURAL,
                    confidence=0.75,
                    evidence={"header": key},
                )
            )
            break

    return signals


_HOSTING_NETWORKS: tuple[tuple[str, int], ...] = (
    ("3.0.0.0", 8),        # Amazon (legacy)
    ("13.32.0.0", 13),     # AWS CloudFront
    ("18.32.0.0", 13),     # AWS CloudFront
    ("34.64.0.0", 10),     # GCP
    ("35.190.0.0", 13),    # GCP
    ("52.0.0.0", 8),       # AWS
    ("54.64.0.0", 11),     # AWS
    ("64.233.160.0", 19),  # Google
    ("104.196.0.0", 14),   # GCP
    ("142.250.0.0", 15),   # Google
    ("157.240.0.0", 16),   # Meta
    ("167.99.0.0", 16),    # DigitalOcean
    ("185.199.108.0", 22), # GitHub Pages
    ("199.232.0.0", 16),   # Fastly
    ("207.241.224.0", 19), # LinkedIn
)

_HOSTING_NETWORKS_V6: tuple[tuple[str, int], ...] = (
    ("2600:1f00::", 24),   # AWS
    ("2a00:1450::", 32),   # Google
)


def _is_hosting_ip(address: Any) -> bool:
    """Whether an address falls in a well-known hosting or CDN range."""
    try:
        if address.version == 4:
            return any(
                address in ipaddress.ip_network(f"{network}/{bits}", strict=False)
                for network, bits in _HOSTING_NETWORKS
            )
        return any(
            address in ipaddress.ip_network(f"{network}/{bits}", strict=False)
            for network, bits in _HOSTING_NETWORKS_V6
        )
    except ValueError:  # pragma: no cover - malformed network constants
        return False


# ---------------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------------
def analyse_attachments(parsed: ParsedEmail) -> list[DetectionSignal]:
    """Flag attachments by type, extension and naming behaviour.

    Attachments are described, never opened or executed. The analyser's only
    interaction with an attachment is reading its bytes, which the file pipeline
    does separately and safely.
    """
    signals: list[DetectionSignal] = []
    dangerous: list[dict[str, str]] = []
    macro_risky: list[dict[str, str]] = []
    double_extension: list[dict[str, str]] = []
    script_attachments: list[dict[str, str]] = []

    for attachment in parsed.attachments:
        content_type = (attachment.content_type or "").lower().split(";")[0].strip()
        filename = attachment.filename or "(unnamed)"
        lowered = filename.lower()

        if content_type in DANGEROUS_ATTACHMENT_TYPES:
            dangerous.append(
                {
                    "filename": filename,
                    "content_type": content_type,
                    "kind": DANGEROUS_ATTACHMENT_TYPES[content_type],
                }
            )

        if content_type in _MACRO_RISKY_OFFICE_TYPES:
            macro_risky.append({"filename": filename, "content_type": content_type})

        # Extensions that execute on their own, or via a double extension.
        if re.search(r"\.(exe|scr|bat|cmd|com|pif|js|jse|vbs|vbe|ps1|psm1|jar|hta|wsf|lnk|reg|msi|apk|dll)$", lowered):
            script_attachments.append({"filename": filename, "content_type": content_type})

        if re.search(r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png|gif|zip|rar)\.(exe|scr|bat|cmd|js|jar|hta|com|pif)$", lowered):
            double_extension.append({"filename": filename, "content_type": content_type})

        # Filenames that spoof an organisation to gain trust before opening.
        if re.search(r"^(?:invoice|payment|receipt|statement|payslip|order|refund|wire)", lowered) and re.search(
            r"\.(exe|scr|zip|js|iso|img|bat|cmd)$", lowered
        ):
            script_attachments.append(
                {"filename": filename, "content_type": content_type, "reason": "lure filename"}
            )

    if double_extension:
        signals.append(
            DetectionSignal(
                code="email.attachment_double_extension",
                title="Attachment name hides an executable behind a document extension",
                description=(
                    "An attachment is named so that only its final extension is visible in a "
                    "file list (for example 'invoice.pdf.exe'). Windows shows the final "
                    "extension, so the executable is hidden until the warnings are disabled."
                ),
                severity=Severity.CRITICAL,
                category="deception",
                source=SignalSource.STRUCTURAL,
                confidence=0.92,
                evidence={"attachments": double_extension},
            )
        )

    if script_attachments:
        signals.append(
            DetectionSignal(
                code="email.executable_attachment",
                title="Message carries an executable or script attachment",
                description=(
                    f"{len(script_attachments)} attachment(s) have a filename ending in an "
                    "executable or script extension. Executing such a file runs attacker code "
                    "with the user's privileges. It has not been executed here."
                ),
                severity=Severity.HIGH,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.9,
                evidence={"attachments": script_attachments},
            )
        )

    if dangerous:
        signals.append(
            DetectionSignal(
                code="email.dangerous_content_type",
                title="Attachment declares a dangerous content type",
                description=(
                    "One or more attachments declare a MIME type that is capable of executing "
                    "code or of fetching and running further content."
                ),
                severity=Severity.HIGH,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.85,
                evidence={"attachments": dangerous},
            )
        )

    if macro_risky:
        signals.append(
            DetectionSignal(
                code="email.macro_capable_attachment",
                title="Message carries a macro-capable document",
                description=(
                    f"{len(macro_risky)} attachment(s) are Office or RTF documents, which can "
                    "carry macros that run automatically when the file is opened."
                ),
                severity=Severity.LOW,
                category="transparency",
                source=SignalSource.STRUCTURAL,
                confidence=0.5,
                evidence={"attachments": macro_risky},
            )
        )

    # Archive names that hide their contents.
    for attachment in parsed.attachments:
        name = (attachment.filename or "").lower()
        if re.search(r"\.(zip|rar|7z)$", name) and not name.endswith((".docx.zip",)):
            signals.append(
                DetectionSignal(
                    code="email.archive_attachment",
                    title="Archive attachment hides its contents until extracted",
                    description=(
                        "The recipient cannot see what is inside an archive before opening it. "
                        "Archives are used to get malware past mail gateways and to obscure the "
                        "real file name. The archive was not extracted."
                    ),
                    severity=Severity.LOW,
                    category="transparency",
                    source=SignalSource.STRUCTURAL,
                    confidence=0.5,
                    evidence={"filename": attachment.filename},
                )
            )
            break

    return signals


def analyse_recipient_analysis(parsed: ParsedEmail) -> list[DetectionSignal]:
    """Spot BCC mass-mailing patterns."""
    signals: list[DetectionSignal] = []

    total = len(parsed.recipients) + len(parsed.cc)
    if total >= 15:
        signals.append(
            DetectionSignal(
                code="email.mass_recipient_count",
                title=f"Message addressed to {total} recipients",
                description=(
                    f"{total} recipients are visible in To and Cc. Bulk phishing commonly "
                    "sends one message to many people so that no single target can quietly "
                    "report it."
                ),
                severity=Severity.LOW,
                category="transparency",
                source=SignalSource.STRUCTURAL,
                confidence=0.5,
                evidence={"recipients": total},
            )
        )

    # Many recipients spread across unrelated domains is a bulk-mail signature.
    domains = {
        address.rsplit("@", 1)[1].lower()
        for address in (*parsed.recipients, *parsed.cc)
        if "@" in address
    }
    if len(domains) >= 10:
        signals.append(
            DetectionSignal(
                code="email.scattered_recipient_domains",
                title=f"Recipients span {len(domains)} unrelated domains",
                description=(
                    f"The visible recipients belong to {len(domains)} different domains. A "
                    "genuine business message normally goes to a small number of related "
                    "addresses; this pattern is characteristic of bulk mailings."
                ),
                severity=Severity.MEDIUM,
                category="structural",
                source=SignalSource.STRUCTURAL,
                confidence=0.65,
                evidence={"domain_count": len(domains)},
            )
        )

    return signals


__all__ = [
    "CONSUMER_DOMAINS",
    "DANGEROUS_ATTACHMENT_TYPES",
    "analyse_attachments",
    "analyse_authentication",
    "analyse_headers",
    "analyse_identity",
    "analyse_recipient_analysis",
]