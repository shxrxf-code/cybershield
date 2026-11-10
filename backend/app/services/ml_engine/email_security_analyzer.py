import re
from typing import Dict, Any, List

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".ps1", ".hta", ".apk",
    ".iso", ".img", ".jar", ".xlsm", ".docm", ".pptm"
}


class EmailSecurityAnalyzer:
    def __init__(self):
        pass

    def analyze(
        self,
        sender: str,
        subject: str,
        body: str,
        headers: Dict[str, str],
        spf: str = "PASS",
        dkim: str = "PASS",
        dmarc: str = "PASS",
        attachments: List[str] = None
    ) -> Dict[str, Any]:
        attachments = attachments or []
        risk_score = 0
        suspicious_elements = []

        # 1. Email Authentication Verification (SPF / DKIM / DMARC)
        spf_upper = (spf or "PASS").upper()
        dkim_upper = (dkim or "PASS").upper()
        dmarc_upper = (dmarc or "PASS").upper()

        if spf_upper in ["FAIL", "SOFTFAIL"]:
            risk_score += 25
            suspicious_elements.append(f"SPF verification failed: {spf_upper} (Unauthorized sending IP)")

        if dkim_upper in ["FAIL", "INVALID"]:
            risk_score += 25
            suspicious_elements.append("DKIM cryptographic signature verification failed (Email modified in transit)")

        if dmarc_upper in ["FAIL", "REJECT"]:
            risk_score += 30
            suspicious_elements.append("DMARC policy alignment failed (High probability of domain impersonation)")

        # 2. Sender spoofing checks
        if "from" in headers and "reply-to" in headers:
            from_addr = headers["from"].lower()
            reply_to = headers["reply-to"].lower()
            if from_addr != reply_to and "@" in from_addr and "@" in reply_to:
                from_domain = from_addr.split("@")[-1].strip("> ")
                reply_domain = reply_to.split("@")[-1].strip("> ")
                if from_domain != reply_domain:
                    risk_score += 30
                    suspicious_elements.append(f"Header Mismatch: From domain ({from_domain}) differs from Reply-To ({reply_domain})")

        # 3. Dangerous Attachments
        for att in attachments:
            for ext in DANGEROUS_EXTENSIONS:
                if att.lower().endswith(ext):
                    risk_score += 45
                    suspicious_elements.append(f"Malicious executable/script attachment detected: {att}")

        # 4. Body Content Urgency & Credential Harvest Lures
        body_lower = body.lower()
        if any(term in body_lower for term in ["password expires", "verify mailbox", "account termination", "wire transfer"]):
            risk_score += 15
            suspicious_elements.append("Contains high-pressure social engineering keywords")

        risk_score = min(max(risk_score, 0), 100)
        phishing_prob = round(risk_score / 100.0, 2)

        if risk_score >= 70:
            verdict = "MALICIOUS"
        elif risk_score >= 35:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return {
            "verdict": verdict,
            "risk_score": risk_score,
            "phishing_probability": phishing_prob,
            "auth_status": {
                "spf": spf_upper,
                "dkim": dkim_upper,
                "dmarc": dmarc_upper
            },
            "suspicious_elements": suspicious_elements
        }


email_analyzer = EmailSecurityAnalyzer()
