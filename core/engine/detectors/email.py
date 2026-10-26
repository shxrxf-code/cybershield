from __future__ import annotations
import re
from typing import Dict, Any, List

PHISH_INDICATORS = ["verify", "suspended", "urgent", "password", "click", "login", "bank", "account", "update", "security"]

def analyze_email(sender: str, subject: str, body: str, urls: List[str] = None) -> Dict[str, Any]:
    features = {}
    reasons = []
    text = f"{subject} {body}".lower()
    sender_l = sender.lower()
    
    # Strong phishing indicators
    if any(k in text for k in ["urgent", "immediate", "suspended", "verify now", "click now"]):
        features["phishing_indicators"] = True
        reasons.append("Urgent phishing language detected")
    elif sum(1 for k in PHISH_INDICATORS if k in text) >= 2:
        features["phishing_indicators"] = True
        reasons.append("Multiple phishing indicators in content")
    
    # Spoofing detection
    if any(dom in sender_l for dom in ['micr0soft', 'paypa1', 'amaz0n', 'g00gle', 'app1e']):
        features["phishing_indicators"] = True
        reasons.append("Possible sender spoofing (typosquatting)")
    elif re.search(r'(support|security|noreply).*@(?!gmail|outlook|yahoo|hotmail)', sender_l):
        if any(k in text for k in PHISH_INDICATORS):
            features["phishing_indicators"] = True
            reasons.append("Suspicious sender with phishing content")
    
    if urls:
        for u in urls:
            u_l = u.lower()
            if any(k in u_l for k in ["login", "verify", "secure", "account"]) and ("." in u_l):
                features["phishing_indicators"] = True
                reasons.append("Suspicious URL in email")
                break
    
    return {"features": features, "reasons": reasons, "suspicious": len(features) > 0}
