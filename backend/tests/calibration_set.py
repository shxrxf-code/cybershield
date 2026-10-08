"""Labelled calibration set for the risk engine.

Each case declares the minimum acceptable band. These are hand-authored from
publicly documented attack techniques, not scraped malware, and the file is safe
to commit. Run ``pytest tests/test_risk_calibration.py`` to check the engine
still separates benign from malicious traffic after any tuning change.

Expected bands are expressed as the *minimum* verdict: a case may score higher
than its floor, but never lower. This prevents a tuning change from silently
downgrading a detection.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas.common import Verdict

#: Ordered weakest to strongest, so floors can be compared with ``index()``.
VERDICT_ORDER: tuple[Verdict, ...] = (
    Verdict.SAFE,
    Verdict.LOW_RISK,
    Verdict.SUSPICIOUS,
    Verdict.HIGH_RISK,
    Verdict.MALICIOUS,
)


@dataclass(frozen=True)
class CalibrationCase:
    """A labelled input and the minimum verdict the engine must reach."""

    name: str
    object_type: str
    minimum_verdict: Verdict
    maximum_verdict: Verdict
    payload: dict[str, object]
    rationale: str


#: URL cases, exercised through the URL pipeline.
URL_CASES: tuple[CalibrationCase, ...] = (
    CalibrationCase(
        name="url_google_search",
        object_type="URL",
        minimum_verdict=Verdict.SAFE,
        maximum_verdict=Verdict.LOW_RISK,
        payload={"url": "https://www.google.com/search?q=weather"},
        rationale="Established brand, HTTPS, no deceptive structure.",
    ),
    CalibrationCase(
        name="url_github_repo",
        object_type="URL",
        minimum_verdict=Verdict.SAFE,
        maximum_verdict=Verdict.LOW_RISK,
        payload={"url": "https://github.com/torvalds/linux/blob/master/README"},
        rationale="Well-known hosting, deep path but no deception.",
    ),
    CalibrationCase(
        name="url_government_https",
        object_type="URL",
        minimum_verdict=Verdict.SAFE,
        maximum_verdict=Verdict.LOW_RISK,
        payload={"url": "https://www.gov.uk/browse/visas"},
        rationale="Government namespace over HTTPS with no other signals.",
    ),
    CalibrationCase(
        name="url_shortener",
        object_type="URL",
        minimum_verdict=Verdict.SAFE,
        maximum_verdict=Verdict.LOW_RISK,
        payload={"url": "https://bit.ly/3xYzAbc"},
        rationale="Opaque destination only; not evidence of harm on its own.",
    ),
    CalibrationCase(
        name="url_http_only",
        object_type="URL",
        minimum_verdict=Verdict.SAFE,
        maximum_verdict=Verdict.LOW_RISK,
        payload={"url": "http://example.org/page"},
        rationale="Plain HTTP on a benign domain is a weakness, not a threat.",
    ),
    CalibrationCase(
        name="url_ip_literal_admin",
        object_type="URL",
        minimum_verdict=Verdict.LOW_RISK,
        maximum_verdict=Verdict.SUSPICIOUS,
        payload={"url": "http://203.0.113.45:8080/admin/login"},
        rationale="Bare IP plus admin path plus non-web port.",
    ),
    CalibrationCase(
        name="url_brand_in_subdomain",
        object_type="URL",
        minimum_verdict=Verdict.SUSPICIOUS,
        maximum_verdict=Verdict.MALICIOUS,
        payload={"url": "http://paypal.com.secure-login.tk/verify?account=1&password=x"},
        rationale="Credential-themed parameters plus brand impersonation on an abuse-heavy TLD.",
    ),
    CalibrationCase(
        name="url_embedded_credentials",
        object_type="URL",
        minimum_verdict=Verdict.SUSPICIOUS,
        maximum_verdict=Verdict.MALICIOUS,
        payload={"url": "https://secure.bank.example.com@203.0.113.9/login"},
        rationale="Classic credential-deception URL targeting an IP host.",
    ),
    CalibrationCase(
        name="url_double_extension",
        object_type="URL",
        minimum_verdict=Verdict.SUSPICIOUS,
        maximum_verdict=Verdict.MALICIOUS,
        payload={"url": "https://cdn.example.org/invoice.pdf.exe"},
        rationale="Double extension is a direct file-type disguise.",
    ),
    CalibrationCase(
        name="url_typosquat",
        object_type="URL",
        minimum_verdict=Verdict.SUSPICIOUS,
        maximum_verdict=Verdict.MALICIOUS,
        payload={"url": "https://microsft-login.example.tk/signin"},
        rationale="Misspelled brand plus login path on an abuse-heavy TLD.",
    ),
    CalibrationCase(
        name="url_homograph",
        object_type="URL",
        minimum_verdict=Verdict.SUSPICIOUS,
        maximum_verdict=Verdict.MALICIOUS,
        payload={"url": "https://xn--80ak6aa92e.com/login"},
        rationale="Punycode IDN host built for visual brand impersonation.",
    ),
    CalibrationCase(
        name="url_dat_scheme",
        object_type="URL",
        minimum_verdict=Verdict.SUSPICIOUS,
        maximum_verdict=Verdict.MALICIOUS,
        payload={"url": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="},
        rationale="Active-content scheme that executes rather than references a host.",
    ),
)

#: Phishing message cases, exercised through the text analyser.
TEXT_CASES: tuple[CalibrationCase, ...] = (
    CalibrationCase(
        name="text_benign_notice",
        object_type="TEXT",
        minimum_verdict=Verdict.SAFE,
        maximum_verdict=Verdict.LOW_RISK,
        payload={
            "text": (
                "Hi team, the quarterly report is attached. Please review section 3 before "
                "the meeting on Thursday. Let me know if you have questions. Regards, Sarah"
            )
        },
        rationale="Ordinary business correspondence.",
    ),
    CalibrationCase(
        name="text_password_reset_help",
        object_type="TEXT",
        minimum_verdict=Verdict.SAFE,
        maximum_verdict=Verdict.SUSPICIOUS,
        payload={
            "text": (
                "To reset your own password, open the security settings page in your account "
                "and follow the official forgot password flow. Support can never ask for your "
                "current password."
            )
        },
        rationale="Discusses passwords legitimately; the benign-context rule must suppress it.",
    ),
    CalibrationCase(
        name="text_credential_phish",
        object_type="TEXT",
        minimum_verdict=Verdict.SUSPICIOUS,
        maximum_verdict=Verdict.MALICIOUS,
        payload={
            "text": (
                "URGENT NOTICE: Your account has been suspended due to unauthorized activity. "
                "You must verify your identity immediately or your account will be permanently "
                "closed within 24 hours. Click here to enter your password and confirm your "
                "account details to avoid suspension."
            )
        },
        rationale="Urgency plus credential solicitation is the canonical phishing pattern.",
    ),
    CalibrationCase(
        name="text_wire_fraud",
        object_type="TEXT",
        minimum_verdict=Verdict.SUSPICIOUS,
        maximum_verdict=Verdict.MALICIOUS,
        payload={
            "text": (
                "Dear Director, this is urgent and confidential. Please wire the funds to the "
                "following bank account immediately and confirm receipt. Do not discuss this "
                "with your team before processing."
            )
        },
        rationale="Classic business email compromise (BEC) request.",
    ),
)

ALL_CASES: tuple[CalibrationCase, ...] = URL_CASES + TEXT_CASES


def satisfies(case: CalibrationCase, verdict: Verdict) -> tuple[bool, str]:
    """Check whether ``verdict`` lies within the case's accepted band."""
    value = VERDICT_ORDER.index(verdict)
    low = VERDICT_ORDER.index(case.minimum_verdict)
    high = VERDICT_ORDER.index(case.maximum_verdict)
    if value < low:
        return False, f"verdict {verdict.value} is below the floor {case.minimum_verdict.value}"
    if value > high:
        return False, f"verdict {verdict.value} is above the ceiling {case.maximum_verdict.value}"
    return True, "within expected band"