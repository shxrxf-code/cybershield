import pytest
from app.services.ml_engine.url_classifier import url_classifier, URLFeatureExtractor
from app.services.ml_engine.sms_phishing_detector import sms_detector
from app.services.scanner.apk_static_engine import apk_engine
from app.services.scanner.document_security_engine import document_engine
from app.services.ml_engine.email_security_analyzer import email_analyzer


def test_url_classifier_clean():
    result = url_classifier.analyze("https://google.com/search?q=cybersecurity")
    assert result["verdict"] == "SAFE"
    assert result["risk_score"] < 35
    assert not result["is_typosquatting"]
    assert not result["is_homograph"]


def test_url_classifier_typosquatting_and_phishing():
    # Typosquatting paypal with phishing keywords
    result = url_classifier.analyze("http://paypa1-login-verify-account.xyz/secure/update")
    assert result["verdict"] in ["SUSPICIOUS", "MALICIOUS"]
    assert result["risk_score"] >= 40
    assert result["is_typosquatting"] or "paypa" in str(result["reasons"])


def test_url_classifier_homograph():
    # Cyrillic 'a' homograph attack (xn--pple-43d.com)
    result = url_classifier.analyze("http://xn--pple-43d.com/login")
    assert result["is_homograph"] is True
    assert result["risk_score"] >= 45


def test_sms_detector_clean():
    res = sms_detector.analyze("Mom", "Dinner is ready, see you at home!")
    assert res["classification"] == "SAFE"
    assert res["risk_score"] < 30


def test_sms_detector_banking_fraud():
    res = sms_detector.analyze(
        "+18005550199",
        "URGENT: Your Chase account suspended due to unauthorized transaction. Verify at http://chase-update.top"
    )
    assert res["classification"] == "BANKING_FRAUD"
    assert res["risk_score"] >= 70
    assert len(res["extracted_urls"]) == 1


def test_sms_detector_crypto_scam():
    res = sms_detector.analyze(
        "CRYPTO-WIN",
        "Congratulations! You won free bitcoin. Connect wallet to claim your prize now."
    )
    assert res["classification"] == "SCAM"
    assert res["risk_score"] >= 40


def test_apk_scanner_benign():
    report = apk_engine.analyze_package_metadata(
        package_name="com.example.calculator",
        permissions=["android.permission.INTERNET"]
    )
    assert report["verdict"] == "SAFE"
    assert report["risk_score"] < 35


def test_apk_scanner_banking_trojan():
    # Combination of accessibility, overlay, and SMS
    report = apk_engine.analyze_package_metadata(
        package_name="com.fake.update.flash",
        permissions=[
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS"
        ],
        uses_accessibility=True,
        uses_overlay=True
    )
    assert report["verdict"] == "MALICIOUS"
    assert report["risk_score"] >= 70
    assert any("Banking Trojan" in f for f in report["detected_families"])


def test_document_scanner_clean():
    res = document_engine.analyze_document_metadata(
        file_name="Annual_Report_2026.pdf",
        file_extension="pdf",
        file_size_bytes=1048576,
        has_macros=False,
        suspicious_tags=[]
    )
    assert res["verdict"] == "SAFE"
    assert res["safe_to_open"] is True


def test_document_scanner_exploit():
    res = document_engine.analyze_document_metadata(
        file_name="Invoice_Payment.docm",
        file_extension="docm",
        file_size_bytes=512000,
        has_macros=True,
        embedded_scripts=["WScript.Shell.Run powershell.exe -enc ... URLDownloadToFile"],
        suspicious_tags=[]
    )
    assert res["verdict"] == "MALICIOUS"
    assert res["safe_to_open"] is False
    assert res["quarantine_recommended"] is True


def test_email_analyzer_spoofing():
    res = email_analyzer.analyze(
        sender="security@paypa1.com",
        subject="Action Required: Mailbox Suspension",
        body="Verify your account immediately or lose access.",
        headers={"from": "security@paypal.com", "reply-to": "hacker@evil.com"},
        spf="FAIL",
        dkim="FAIL",
        dmarc="FAIL",
        attachments=["invoice.xlsm"]
    )
    assert res["verdict"] == "MALICIOUS"
    assert res["risk_score"] >= 75
