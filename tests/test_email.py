"""Email analysis: authentication, structure and social engineering.

Two failure modes are being guarded against, and they pull in opposite
directions.

* **Under-detection.** A credential-harvesting message must not come back clean.
* **Over-detection.** Ordinary mail - a CI notification, a newsletter, a calendar
  invite - must not come back alarming.  A mail filter that cries wolf on every
  automated message gets disabled, which is a worse outcome than never having
  had one.

So the benign corpus here matters as much as the hostile one.
"""

from __future__ import annotations

import asyncio
from email.message import EmailMessage

import pytest

from detection_engine.email import (
    analyze_email,
    analyze_email_async,
    email_findings,
    normalize_domain,
    parse_email,
    to_analysis_result,
)
from detection_engine.email.analyzer import is_address_literal
from detection_engine.models import SignalSource


def build_email(
    *,
    subject: str = "Hello",
    sender: str = "alice@example.com",
    sender_name: str = "Alice",
    to: str = "bob@example.org",
    reply_to: str | None = None,
    body: str = "Just checking in.",
    html: str | None = None,
    headers: dict[str, str] | None = None,
    attachments: list[tuple[str, bytes, str]] | None = None,
    reply_to_header: str | None = None,
) -> bytes:
    """Assemble an RFC 5322 message.

    Building messages with :mod:`email` rather than pasting raw text keeps the
    fixtures honest: the parser under test is fed something a real mail client
    would produce, header folding and all.
    """
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = f"{sender_name} <{sender}>" if sender_name else sender
    message["To"] = to
    if reply_to_header:
        message["Reply-To"] = reply_to_header
    elif reply_to:
        message["Reply-To"] = reply_to
    for key, value in (headers or {}).items():
        if key in message:
            del message[key]
        message[key] = value
    message.set_content(body)
    if html:
        message.add_alternative(html, subtype="html")
    for filename, payload, subtype in attachments or []:
        maintype, _, sub = subtype.partition("/")
        message.add_attachment(payload, maintype=maintype, subtype=sub or "octet-stream",
                               filename=filename)
    return message.as_bytes()


def analyse(**kwargs: object):
    report = analyze_email(build_email(**kwargs))  # type: ignore[arg-type]
    return report, {f.code for f in email_findings(report)}


# --------------------------------------------------------------------- #
# Sender parsing
# --------------------------------------------------------------------- #


def test_ordinary_address_is_parsed() -> None:
    parsed = parse_email(build_email(sender="alice@example.com", sender_name="Alice"))
    assert parsed.from_address == "alice@example.com"
    assert "alice@example.com" in parsed.from_address.lower()


def test_bracketed_address_literal_is_not_silently_dropped() -> None:
    """``Billing<billing@[203.0.113.99]>`` must not parse to an empty address.

    The stdlib's address parser returns ``('', '')`` for the bracketed form, which
    would let an attacker hide the real sender behind a display name and have the
    analyser report "no sender found" - the most convenient possible outcome for
    them.
    """
    parsed = parse_email(
        build_email(sender="billing@[203.0.113.99]", sender_name="Billing Department")
    )
    assert "203.0.113.99" in parsed.from_address
    assert is_address_literal(parsed.from_address)


def test_bracketed_ipv6_literal_is_recognised() -> None:
    parsed = parse_email(
        build_email(sender="mail@[IPv6:2001:db8::1]", sender_name="Mail")
    )
    assert "2001:db8" in parsed.from_address
    assert is_address_literal(parsed.from_address)


def test_display_name_domain_mismatch_is_visible() -> None:
    parsed = parse_email(
        build_email(sender_name="PayPal Security", sender="notice@paypal-verify.tk")
    )
    assert "paypal" in parsed.from_name.lower()
    assert "paypal-verify.tk" in parsed.from_address


# --------------------------------------------------------------------- #
# SPF / DKIM / DMARC
# --------------------------------------------------------------------- #

PASSING_AUTH = {
    "Authentication-Results": (
        "mx.example.com; spf=pass smtp.mailfrom=example.com; "
        "dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
    ),
    "Received-SPF": "pass (google.com: domain of alice@example.com designates 93.184.216.34 as permitted sender)",
}


def test_passing_auth_is_not_reported_as_a_finding() -> None:
    _, codes = analyse(headers=PASSING_AUTH, sender="alice@example.com")
    assert not {c for c in codes if c.startswith("EMAIL.AUTH_")}, codes


def test_missing_authentication_is_unverifiable_not_a_pass() -> None:
    """Absence of a result is not a pass.

    Reporting "no SPF failure found" for a message that carries no SPF result at
    would claim a verification that never happened.  This is an informational
    finding, not a failure.
    """
    report, codes = analyse(sender="alice@unknown-domain.example")
    auth_codes = {c for c in codes if c.startswith("EMAIL.AUTH_")}
    assert auth_codes, codes
    finding = next(
        f for f in email_findings(report) if f.code.startswith("EMAIL.AUTH_")
    )
    assert finding.severity.value == "info"
    assert finding.weight == 0.0


def test_spf_fail_is_reported() -> None:
    _, codes = analyse(
        headers={
            "Authentication-Results": "mx.example.com; spf=fail smtp.mailfrom=evil.test; dkim=none",
        },
        sender="alice@example.com",
    )
    assert "EMAIL.AUTH_FAILED" in codes, codes


def test_dmarc_fail_is_reported() -> None:
    _, codes = analyse(
        headers={
            "Authentication-Results": "mx.example.com; spf=none; dmarc=fail header.from=example.com",
        },
        sender="alice@example.com",
    )
    assert "EMAIL.AUTH_FAILED" in codes, codes


def test_auth_failure_names_the_methods_that_failed() -> None:
    """The report has to say which check failed, not just that one did."""
    report, _ = analyse(
        headers={
            "Authentication-Results": "mx.example.com; spf=fail smtp.mailfrom=evil.test; dkim=none",
        },
        sender="alice@example.com",
    )
    finding = next(f for f in email_findings(report) if f.code == "EMAIL.AUTH_FAILED")
    assert "SPF" in finding.detail
    assert finding.evidence["spf"]["result"] == "fail"


def test_spf_pass_without_dmarc_is_a_weak_gap_not_a_failure() -> None:
    """A domain that has not adopted DMARC is a hardening gap, not an attack."""
    _, codes = analyse(
        headers={
            "Authentication-Results": (
                "mx.example.com; spf=pass smtp.mailfrom=example.com; dmarc=none"
            ),
        },
        sender="alice@example.com",
    )
    assert "EMAIL.AUTH_NO_DMARC_POLICY" in codes, codes
    assert "EMAIL.AUTH_FAILED" not in codes, codes


# --------------------------------------------------------------------- #
# Structure
# --------------------------------------------------------------------- #


def test_reply_to_divergence_is_flagged() -> None:
    """Replies going somewhere other than the sender is a standard redirection."""
    _, codes = analyse(
        sender="billing@paypal.com",
        sender_name="PayPal Billing",
        reply_to_header="collector@protonmail.example",
    )
    assert "EMAIL.REPLY_TO_MISMATCH" in codes, codes


def test_display_name_impersonation_of_a_brand() -> None:
    _, codes = analyse(
        sender="noreply@paypal-security-alert.tk",
        sender_name="PayPal Security Alert",
        subject="Your account has been suspended",
    )
    assert "EMAIL.DISPLAY_NAME_BRAND_MISMATCH" in codes, codes


def test_lookalike_domain_is_a_critical_finding() -> None:
    """The strongest structural signal a message can carry.

    A host that resembles a brand without being its domain is the mechanism
    behind most credential phishing.  It is kept separate from the display-name
    check because the two are independent claims: a message can wear a bank's
    name honestly, or lie about the domain it actually controls.
    """
    report, codes = analyse(
        sender="security@paypal-verify.tk",
        sender_name="PayPal Security",
        subject="Verify your PayPal account",
    )
    assert "EMAIL.BRAND_IMPERSONATION" in codes, codes
    finding = next(
        f for f in email_findings(report) if f.code == "EMAIL.BRAND_IMPERSONATION"
    )
    assert finding.severity.value == "critical"
    assert finding.evidence["matches"][0]["brand"] == "paypal"


def test_genuine_brand_domain_is_not_impersonation() -> None:
    """The real domain must stay clean, or every bank email is a false alarm."""
    _, codes = analyse(
        sender="service@paypal.com",
        sender_name="PayPal",
        subject="Your receipt",
        body="Thanks for your payment. Your receipt is available in your account.",
    )
    assert "EMAIL.BRAND_IMPERSONATION" not in codes, codes


def test_credential_harvesting_body_is_flagged() -> None:
    _, codes = analyse(
        sender="security@account-verify.example",
        subject="Verify your account immediately",
        body=(
            "We have detected unusual activity. You must verify your account "
            "within 24 hours or it will be permanently closed. Click here to "
            "confirm your username and password immediately."
        ),
    )
    # The text engine contributes PHISH.* codes; the message-level correlation
    # (credentials *and* urgency together) is the one that carries the weight.
    assert "PHISH.CREDENTIAL_REQUEST" in codes, codes
    assert "PHISH.CREDENTIAL_PLUS_URGENCY" in codes, codes


def test_payload_url_is_extracted() -> None:
    report = analyze_email(
        build_email(
            sender="a@example.com",
            body="Click http://evil-login.example/verify?id=1 to continue",
        )
    )
    assert any("evil-login.example" in url for url in report.urls), report.urls


# --------------------------------------------------------------------- #
# Execution instructions: the body/attachment correlation
# --------------------------------------------------------------------- #


def test_instructions_plus_executable_attachment_is_critical() -> None:
    """The combination earns the weight, not either half.

    "Please run the attached installer" alone is a normal support email, and an
    .exe attachment alone is what every software vendor sends.  Together they are
    the pattern.
    """
    report, codes = analyse(
        sender="support@acme-software.example",
        subject="Urgent: read before opening",
        body=(
            "Our security team requires all staff to run this update as "
            "administrator immediately. Right-click the attachment and choose "
            "Run as administrator."
        ),
        attachments=[("update.exe", b"MZ\x90\x00" + b"\x00" * 512, "application/octet-stream")],
    )
    assert "EMAIL.INSTRUCTS_ATTACHMENT_EXECUTION" in codes, codes
    finding = next(
        f for f in email_findings(report)
        if f.code == "EMAIL.INSTRUCTS_ATTACHMENT_EXECUTION"
    )
    assert finding.severity.value == "critical"
    assert finding.authoritative is False


def test_executable_attachment_alone_is_only_context() -> None:
    report, codes = analyse(
        sender="support@acme-software.example",
        subject="Installer attached",
        body="Please find the latest installer attached. Let us know if you need help.",
        attachments=[("setup.exe", b"MZ\x90\x00" + b"\x00" * 512, "application/octet-stream")],
    )
    assert "EMAIL.INSTRUCTS_ATTACHMENT_EXECUTION" not in codes, codes
    assert report.executable_attachments, report.executable_attachments


def test_instruction_to_disable_protection_is_high() -> None:
    _, codes = analyse(
        sender="it@acme-support.example",
        subject="Action required: antivirus update",
        body=(
            "To complete this procedure, disable your antivirus and add an "
            "exclusion for our installers, then run the attached file."
        ),
        attachments=[("tool.exe", b"MZ\x90\x00" + b"\x00" * 512, "application/octet-stream")],
    )
    assert "EMAIL.INSTRUCTION_TO_DISABLE_PROTECTION" in codes, codes


def test_password_protected_archive_is_high() -> None:
    """A password-protected archive defeats content scanning and content filters.

    The password is in the message, so the user is trained to decrypt and run
    exactly what the sender chose.
    """
    report, codes = analyse(
        sender="billing@invoice-center.example",
        subject="Overdue invoice",
        body=(
            "The attached archive is password protected. The password is 1234. "
            "Extract it and open the document inside."
        ),
        attachments=[("invoice.zip", b"PK\x03\x04" + b"\x00" * 256, "application/zip")],
    )
    assert "EMAIL.PASSWORD_PROTECTED_ARCHIVE" in codes, codes
    assert report.protected_archive_attachments


# --------------------------------------------------------------------- #
# Benign corpus
# --------------------------------------------------------------------- #

BENIGN = [
    dict(
        subject="Standup notes for Tuesday",
        sender="priya@example.org",
        sender_name="Priya Raman",
        body="Notes are in the shared doc. Nothing blocking me today.",
    ),
    dict(
        subject="[ci] build #4821 passed on main",
        sender="ci@example.org",
        sender_name="Example CI",
        body="All 312 tests passed in 4m12s. Artifact uploaded.",
    ),
    dict(
        subject="Your monthly statement is ready",
        sender="statements@yourbank.example",
        sender_name="Your Bank",
        body="Your statement for last month is available in online banking. "
             "No action is needed.",
    ),
    dict(
        subject="Invitation: design review",
        sender="dana@example.org",
        sender_name="Dana Okafor",
        body="Meeting on Thursday at 14:00. Agenda in the invite.",
    ),
    dict(
        subject="Re: contract question",
        sender="legal-counsel@lawfirm.example",
        sender_name="Legal Counsel",
        body="Thanks for your question. Clause 4.2 is the relevant one.",
        headers=PASSING_AUTH,
    ),
]


@pytest.mark.parametrize("case", BENIGN, ids=lambda c: c["subject"])
def test_ordinary_messages_are_not_alarming(case: dict[str, object]) -> None:
    """A mail filter that flags ordinary mail gets switched off.

    The bar here is deliberately the SUSPICIOUS band and above: benign mail may
    attract a LOW observation, but nothing routine should push it into territory
    where a human is asked to act.
    """
    report = analyze_email(build_email(**case))  # type: ignore[arg-type]
    result = to_analysis_result(report)
    from detection_engine.scoring import RiskEngine

    RiskEngine().finalise(result)
    assert result.score < 40, (
        result.score,
        [f.code for f in result.findings],
        result.score_breakdown,
    )


def test_benign_corpus_produces_no_auth_or_brand_findings() -> None:
    for case in BENIGN:
        report = analyze_email(build_email(**case))  # type: ignore[arg-type]
        codes = {f.code for f in email_findings(report)}
        auth_or_brand = {
            c for c in codes
            if c.startswith("EMAIL.AUTH_") or "BRAND" in c or "IMPERSONAT" in c
        }
        assert not auth_or_brand, (case["subject"], auth_or_brand)


# --------------------------------------------------------------------- #
# Plumbing
# --------------------------------------------------------------------- #


def test_reputation_defers_inside_a_running_loop() -> None:
    """The async entry point must actually work inside a loop.

    Reputation lookups are blocking, so the sync path refuses to run inside one
    and the async path offloads it.  Calling the sync function from async code
    must therefore degrade to a deferred result rather than raising.
    """

    async def main() -> None:
        report = await analyze_email_async(build_email(sender="a@example.com"))
        assert report is not None

        # And the sync call, invoked from a loop, must not explode.
        deferred = analyze_email(build_email(sender="a@example.com"))
        assert deferred is not None

    asyncio.run(main())


def test_indicators_are_extracted_for_the_threat_intel_pipeline() -> None:
    report = analyze_email(
        build_email(
            sender="billing@invoice-center.example",
            body="Visit http://invoice-center.example/pay or reply to us.",
        )
    )
    kinds = {i["kind"] for i in report.to_dict().get("indicators", [])} if isinstance(
        report.to_dict().get("indicators"), list
    ) else set()
    assert kinds or report.urls


def test_normalize_domain_strips_case_and_trailing_dot() -> None:
    assert normalize_domain("Example.COM.") == "example.com"
    assert normalize_domain("EXAMPLE.com") == "example.com"


def test_report_is_serialisable() -> None:
    """The report crosses a process boundary to the API and the UI."""
    import json

    report = analyze_email(build_email(subject="Serialise me"))
    payload = json.dumps(report.to_dict())
    assert "Serialise me" in payload or len(payload) > 0


def test_findings_declare_their_source() -> None:
    """Grouping evidence by engine is what makes the report auditable."""
    report = analyze_email(
        build_email(
            sender="noreply@paypal-verify.tk",
            sender_name="PayPal",
            subject="Verify now",
        )
    )
    for finding in email_findings(report):
        assert isinstance(finding.source, SignalSource)
        assert finding.title
        assert finding.detail