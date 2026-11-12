import sys
import os
import unittest

# Ensure backend root is on sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, backend_dir)

from app.services.ml_engine.url_classifier import url_classifier
from app.services.ml_engine.sms_phishing_detector import sms_detector
from app.services.scanner.apk_static_engine import ANDROGUARD_AVAILABLE, apk_engine
from app.services.scanner.document_security_engine import document_engine
from app.services.ml_engine.email_security_analyzer import email_analyzer
from app.services.report_generator.report_engine import report_engine


class TestShieldGuardSecurityEngines(unittest.TestCase):

    def test_url_classifier_clean(self):
        res = url_classifier.analyze("https://google.com/search?q=cybersecurity")
        self.assertEqual(res["verdict"], "SAFE")
        self.assertLess(res["risk_score"], 35)
        self.assertFalse(res["is_typosquatting"])
        self.assertFalse(res["is_homograph"])

    def test_url_classifier_typosquatting(self):
        res = url_classifier.analyze("http://paypa1-login-verify-account.xyz/secure/update")
        self.assertIn(res["verdict"], ["SUSPICIOUS", "MALICIOUS"])
        self.assertGreaterEqual(res["risk_score"], 40)

    def test_url_classifier_homograph(self):
        res = url_classifier.analyze("http://xn--pple-43d.com/login")
        self.assertTrue(res["is_homograph"])
        self.assertGreaterEqual(res["risk_score"], 45)

    def test_sms_detector_clean(self):
        res = sms_detector.analyze("Mom", "Dinner is ready, see you at home!")
        self.assertEqual(res["classification"], "SAFE")
        self.assertLess(res["risk_score"], 30)

    def test_sms_detector_banking_fraud(self):
        res = sms_detector.analyze(
            "+18005550199",
            "URGENT: Your Chase account suspended due to unauthorized transaction. Verify at http://chase-update.top"
        )
        self.assertEqual(res["classification"], "BANKING_FRAUD")
        self.assertGreaterEqual(res["risk_score"], 70)
        self.assertEqual(len(res["extracted_urls"]), 1)

    def test_sms_detector_crypto_scam(self):
        res = sms_detector.analyze(
            "CRYPTO-WIN",
            "Congratulations! You won free bitcoin. Connect wallet to claim your prize now."
        )
        self.assertEqual(res["classification"], "SCAM")
        self.assertGreaterEqual(res["risk_score"], 40)

    def test_apk_scanner_benign(self):
        report = apk_engine.analyze_package_metadata(
            package_name="com.example.calculator",
            permissions=["android.permission.INTERNET"]
        )
        self.assertEqual(report["verdict"], "SAFE")
        self.assertLess(report["risk_score"], 35)

    def test_apk_scanner_banking_trojan(self):
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
        self.assertEqual(report["verdict"], "MALICIOUS")
        self.assertGreaterEqual(report["risk_score"], 70)
        self.assertTrue(any("Banking Trojan" in f for f in report["detected_families"]))

    def test_document_scanner_clean(self):
        res = document_engine.analyze_document_metadata(
            file_name="Annual_Report_2026.pdf",
            file_extension="pdf",
            file_size_bytes=1048576,
            has_macros=False,
            suspicious_tags=[]
        )
        self.assertEqual(res["verdict"], "SAFE")
        self.assertTrue(res["safe_to_open"])

    def test_document_scanner_exploit(self):
        res = document_engine.analyze_document_metadata(
            file_name="Invoice_Payment.docm",
            file_extension="docm",
            file_size_bytes=512000,
            has_macros=True,
            embedded_scripts=["WScript.Shell.Run powershell.exe -enc ... URLDownloadToFile"],
            suspicious_tags=[]
        )
        self.assertEqual(res["verdict"], "MALICIOUS")
        self.assertFalse(res["safe_to_open"])
        self.assertTrue(res["quarantine_recommended"])

    def test_email_analyzer_spoofing(self):
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
        self.assertEqual(res["verdict"], "MALICIOUS")
        self.assertGreaterEqual(res["risk_score"], 75)

    def test_report_generation(self):
        csv_data = report_engine.generate_csv_log([
            {"module_type": "URL", "verdict": "MALICIOUS", "risk_score": 90, "threat_level": "CRITICAL", "title": "Test Phish", "action_taken": "BLOCKED"}
        ])
        self.assertIn("Test Phish", csv_data)
        self.assertIn("MALICIOUS", csv_data)

    def test_androguard_available_and_invalid_bytes(self):
        self.assertTrue(ANDROGUARD_AVAILABLE)
        with self.assertRaises(ValueError):
            apk_engine.analyze_apk_bytes(b"not-a-valid-apk-archive", "bad.apk")

    def test_androguard_apk_binary_scan(self):
        debug_apk = os.path.abspath(
            os.path.join(backend_dir, "..", "android", "app", "build", "outputs", "apk", "debug", "app-debug.apk")
        )
        if not os.path.exists(debug_apk):
            self.skipTest("app-debug.apk not present in workspace")
        report = apk_engine.analyze_apk_file(debug_apk, is_trusted_store=False)
        self.assertEqual(report["package_name"], "com.shieldguard.ai.debug")
        self.assertEqual(report["analysis_engine"], "androguard-4.1.4")
        self.assertGreater(report["dex_count"], 0)
        self.assertIsNotNone(report["cert_sha256"])


if __name__ == "__main__":
    unittest.main()
