import re
from typing import Dict, Any, List

URL_REGEX = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*"

BANKING_INDICATORS = [
    "account suspended", "unauthorized transaction", "card blocked", "kyc verification",
    "otp", "debit card", "credit card", "security alert", "transfer pending",
    "direct deposit", "fraud alert", "wire transfer", "login attempt"
]

SCAM_INDICATORS = [
    "you have won", "lottery", "claim your prize", "congratulations", "gift card",
    "exclusive reward", "free bitcoin", "crypto giveaway", "airdrop claim", "guaranteed returns",
    "double your money", "urgent response required", "package delayed click here",
    "unpaid toll balance", "delivery fee pending"
]

HIGH_RISK_KEYWORDS = [
    "click here", "urgent", "immediate action", "expires in", "verify now",
    "claim now", "confirm password", "wire funds"
]


class SMSPhishingDetector:
    def __init__(self):
        pass

    def extract_urls(self, text: str) -> List[str]:
        return re.findall(URL_REGEX, text)

    def analyze(self, sender: str, text: str) -> Dict[str, Any]:
        text_lower = text.lower()
        extracted_urls = self.extract_urls(text)
        
        risk_score = 0
        matched_patterns = []
        classification = "SAFE"
        threat_level = "LOW"

        # Check banking fraud triggers
        banking_matches = [ind for ind in BANKING_INDICATORS if ind in text_lower]
        if banking_matches:
            risk_score += 45
            matched_patterns.extend(banking_matches)
            classification = "BANKING_FRAUD"

        # Check scam lures
        scam_matches = [ind for ind in SCAM_INDICATORS if ind in text_lower]
        if scam_matches:
            risk_score += 40
            matched_patterns.extend(scam_matches)
            if classification == "SAFE":
                classification = "SCAM"

        # Check high urgency keywords
        urgency_matches = [ind for ind in HIGH_RISK_KEYWORDS if ind in text_lower]
        if urgency_matches:
            risk_score += 20
            matched_patterns.extend(urgency_matches)

        # Embedded link presence increases risk heavily if combined with scam or banking language
        if extracted_urls:
            risk_score += 25
            matched_patterns.append("Contains unverified action link")
            if classification == "SAFE" and risk_score >= 25:
                classification = "SUSPICIOUS"

        # Sender checks (e.g. random shortcode or alphanumeric spoofing)
        sender_clean = sender.strip().upper()
        if re.match(r"^\+?\d{1,4}\d{9,12}$", sender_clean):
            # Normal phone number sending banking messages is highly suspicious
            if classification in ["BANKING_FRAUD", "SCAM"]:
                risk_score += 20
                matched_patterns.append("Official banking message sent from unofficial peer phone number")

        risk_score = min(max(risk_score, 0), 100)

        if risk_score >= 70:
            threat_level = "CRITICAL" if classification == "BANKING_FRAUD" else "HIGH"
            if classification == "SAFE":
                classification = "PHISHING"
            recommendation = "DO NOT CLICK ANY LINKS. Block sender and delete message immediately."
        elif risk_score >= 35:
            threat_level = "MEDIUM"
            if classification == "SAFE":
                classification = "SCAM"
            recommendation = "Exercise caution. Verify the sender through official telephone or web channels."
        else:
            threat_level = "LOW"
            classification = "SAFE"
            recommendation = "Message appears legitimate. Standard caution applies."

        return {
            "sender": sender,
            "classification": classification,
            "risk_score": risk_score,
            "threat_level": threat_level,
            "extracted_urls": extracted_urls,
            "matched_patterns": list(set(matched_patterns)),
            "recommended_action": recommendation
        }


sms_detector = SMSPhishingDetector()
