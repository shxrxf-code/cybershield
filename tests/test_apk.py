"""Android package analysis: the calibration the APK module was tuned against.

The expectations here are score *bands*, not exact numbers.  A refactor that
improves the analyser will move scores inside a band; a refactor that breaks it
will push one outside, which is what the bands are for.

The benign cases carry as much weight as the hostile ones.  Every benign fixture
is something the analyser used to flag: a password manager (accessibility plus
SMS plus install is its entire job), an expired key, a debug build, a signed
release build.  A detector that cannot tell those apart from malware is not
usable.
"""

from __future__ import annotations

from typing import Any

import pytest

from detection_engine import AnalysisResult, ObjectType, Verdict
from detection_engine.apk import ApkAnalyzer, analyze_apk_bytes
from detection_engine.models import SignalSource
from fixtures.apk_builder import AUTOFILL_PERMISSION, apk_bytes


def analyze(**kwargs: Any) -> AnalysisResult:
    """Build an APK from *kwargs* and analyse its bytes."""
    return analyze_apk_bytes(apk_bytes(**kwargs))


def ids(result: AnalysisResult) -> set[str]:
    return {f.code for f in result.findings}


# --------------------------------------------------------------------- #
# Benign packages
# --------------------------------------------------------------------- #


def test_signed_release_app_is_low_risk_or_better() -> None:
    result = analyze(
        package="com.acme.reader",
        permissions=["INTERNET", "ACCESS_NETWORK_STATE"],
        activities=[(".MainActivity", "true")],
        sign=True,
        cert_cn="Acme Publishing",
        cert_org="Acme Publishing Ltd",
    )
    assert result.verdict in {Verdict.SAFE, Verdict.LOW_RISK}, (
        result.score,
        result.verdict,
        [f.finding_id for f in result.findings],
    )
    assert result.score < 20


def test_password_manager_is_not_treated_as_a_trojan() -> None:
    """A password manager legitimately holds all three permissions.

    Accessibility (to read the page it is filling), SMS (to auto-fill 2FA codes)
    and package installation (to enrol a second factor) are the *product*, not
    a capability the user never intended to grant.  The discriminator is the
    autofill service binding: a component bound to
    ``BIND_AUTOFILL_SERVICE`` is declaring what it is for.
    """
    result = analyze(
        package="com.vault.passwordmanager",
        permissions=[
            "INTERNET",
            "BIND_ACCESSIBILITY_SERVICE",
            "BIND_AUTOFILL_SERVICE",
            "RECEIVE_SMS",
            "READ_SMS",
            "REQUEST_INSTALL_PACKAGES",
        ],
        activities=[(".UnlockActivity", "true")],
        services=[(
            ".AutofillService",
            "true",
            AUTOFILL_PERMISSION,
        )],
        receivers=[(".SmsReceiver", "true")],
        sign=True,
        cert_cn="Vault Inc",
    )
    assert result.verdict in {Verdict.SAFE, Verdict.LOW_RISK}, (
        result.score,
        [f.finding_id for f in result.findings],
    )
    for finding_id in ("APK.ACCESSIBILITY_PLUS_ACCESS", "APK.SMS_AND_INSTALL"):
        assert finding_id not in ids(result), finding_id


def test_expired_certificate_is_flagged_without_calling_it_malware() -> None:
    """An expired certificate is a hygiene problem, not an attack.

    Android does not enforce certificate expiry for app signing, so this earns
    a low score and stays in the SAFE band.  It is still reported, because
    "nobody is renewing this key" is worth knowing.
    """
    result = analyze(
        package="com.legacy.tool",
        permissions=["INTERNET"],
        sign="expired",
    )
    assert "APK.CERTIFICATE_EXPIRED" in ids(result)
    assert result.score < 20, result.score
    assert result.verdict is Verdict.SAFE


def test_platform_signed_certificate_is_suspicious() -> None:
    """A package signed with an AOSP key is claiming to be the OS."""
    result = analyze(
        package="com.fake.system",
        permissions=["INTERNET", "INSTALL_PACKAGES"],
        sign="platform",
    )
    assert result.verdict in {Verdict.SUSPICIOUS, Verdict.HIGH_RISK}, (
        result.score,
        [f.finding_id for f in result.findings],
    )


def test_unsigned_package_is_reported_as_unsigned() -> None:
    result = analyze(package="com.example.unsigned", permissions=["INTERNET"], sign=False)
    assert "APK.UNSIGNED" in ids(result)
    assert result.verdict in {Verdict.LOW_RISK, Verdict.SUSPICIOUS}, result.score


# --------------------------------------------------------------------- #
# Hostile packages
# --------------------------------------------------------------------- #


def test_permission_stacking_escalates() -> None:
    """The classic spyware permission set must land well above SUSPICIOUS."""
    result = analyze(
        package="com.free.video.player",
        permissions=[
            "INTERNET",
            "READ_SMS",
            "RECEIVE_SMS",
            "READ_CONTACTS",
            "RECORD_AUDIO",
            "CAMERA",
            "ACCESS_FINE_LOCATION",
            "READ_CALL_LOG",
            "RECEIVE_BOOT_COMPLETED",
            "SYSTEM_ALERT_WINDOW",
            "REQUEST_INSTALL_PACKAGES",
            "BIND_ACCESSIBILITY_SERVICE",
        ],
        receivers=[(".BootReceiver", "true")],
        sign=True,
        cert_cn="Free Media",
    )
    assert result.verdict in {
        Verdict.HIGH_RISK,
        Verdict.MALICIOUS,
    }, (result.score, [f.finding_id for f in result.findings])
    assert result.score >= 60


def test_embedded_vendor_credential_is_high_risk() -> None:
    """An AWS key identifier is deterministic, unlike generic base64 blobs.

    The split matters: a named vendor key pattern cannot plausibly appear in
    ordinary app data, so it earns authoritative weight.  A long base64 string
    can, so it does not.
    """
    result = analyze(
        package="com.example.cloud",
        permissions=["INTERNET"],
        dex_strings=[
            "Lcom/example/Api;",
            "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
        ],
        sign=True,
    )
    assert "APK.EMBEDDED_CREDENTIAL" in ids(result)
    assert result.verdict >= Verdict.HIGH_RISK, result.score
    credential = next(f for f in result.findings if f.finding_id == "APK.EMBEDDED_CREDENTIAL")
    assert credential.source == SignalSource.APK_SECRET


def test_generic_base64_blob_is_not_weighted_like_a_vendor_key() -> None:
    """The false-positive half of the credential split.

    Ordinary apps ship long opaque strings - cached payloads, compressed
    resources, embedded fonts.  Treating one as a leaked secret would make the
    analyser cry wolf on every app with an embedded asset.
    """
    result = analyze(
        package="com.example.fonts",
        permissions=["INTERNET"],
        dex_strings=[
            "Lcom/example/FontLoader;",
            # 80 base64 characters with no internal padding, which is what a
            # packed constant or a serialised asset actually looks like.
            "payload=Zm9vYmFyYmF6cXV1eGNvcmdlZ3JhdWx0YXJwbGF5bG9hZHBheWxvYWRoYXNoZXNhbHQ",
        ],
        sign=True,
    )
    assert "APK.OPAQUE_SECRETS" in ids(result)
    assert "APK.EMBEDDED_CREDENTIAL" not in ids(result)
    assert result.score < 60, result.score


def test_debuggable_release_build_is_flagged() -> None:
    result = analyze(
        package="com.example.shipping",
        permissions=["INTERNET"],
        debuggable=True,
        sign="debug",
    )
    flagged = ids(result) & {"APK.DEBUGGABLE", "APK.DEBUG_CERTIFICATE"}
    assert flagged, ids(result)


def test_counterfeit_brand_in_package_name() -> None:
    result = analyze(
        package="com.paypal.secure.login.official",
        permissions=["INTERNET"],
        sign=True,
    )
    assert result.score > 0


def test_shared_user_id_escalates() -> None:
    """A fixed shared UID lets the package read another app's private data."""
    result = analyze(
        package="com.example.rogue",
        permissions=["INTERNET"],
        shared_user="com.android.system",
        sign=True,
    )
    assert result.score > 0
    assert result.verdict != Verdict.SAFE


# --------------------------------------------------------------------- #
# Honesty about coverage
# --------------------------------------------------------------------- #


def test_non_apk_input_is_unknown_not_safe() -> None:
    """"This is not an APK" is an identity conclusion, not a safety one.

    Returning SAFE for input that was never analysed would be the single most
    dangerous thing this module could do: an attacker who submits a non-APK gets
    an all-clear on the object they submitted.
    """
    result = analyze_apk_bytes(b"this is definitely not a zip archive")
    assert result.verdict == Verdict.UNKNOWN
    assert result.score == 0.0
    assert result.incomplete is True


def test_truncated_zip_is_unknown() -> None:
    truncated = apk_bytes(package="com.example.app")[:200]
    result = analyze_apk_bytes(truncated)
    assert result.verdict == Verdict.UNKNOWN


def test_integrity_verification_gap_is_recorded() -> None:
    """Repackaging cannot be ruled out, and the report has to say so.

    A signed package whose signature has not been cryptographically verified is
    not the same as a package known to be intact.  The gap belongs in the
    coverage report so the confidence figure reflects it.
    """
    result = analyze(package="com.example.app", permissions=["INTERNET"], sign=True)
    coverage = result.metadata["coverage"]
    assert "apk_integrity_verification" in coverage["skipped"], coverage


def test_every_finding_carries_an_explanation() -> None:
    """A verdict a user cannot interrogate is not actionable."""
    result = analyze(
        package="com.free.video.player",
        permissions=["READ_SMS", "CAMERA", "ACCESS_FINE_LOCATION", "SYSTEM_ALERT_WINDOW"],
        dex_strings=["AKIAIOSFODNN7EXAMPLE"],
        sign=True,
    )
    assert result.findings
    for finding in result.findings:
        assert finding.title, finding.code
        assert finding.detail, finding.code
        assert 0.0 <= finding.effective_weight <= 100.0


@pytest.mark.parametrize("score,expected", [(0, Verdict.SAFE), (25, Verdict.LOW_RISK),
                                            (45, Verdict.SUSPICIOUS), (65, Verdict.HIGH_RISK),
                                            (85, Verdict.MALICIOUS)])
def test_verdict_bands_hold(score: float, expected: Verdict) -> None:
    from detection_engine import verdict_for_score

    assert verdict_for_score(score) is expected