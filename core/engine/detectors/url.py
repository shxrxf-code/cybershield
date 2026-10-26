from __future__ import annotations
import re
from urllib.parse import urlparse, parse_qs
import tldextract

SUSPICIOUS_TLDS = {"zip", "top", "click", "loan", "gq", "ml", "tk", "work", "rest", "buzz", "xyz"}
PHISHING_KEYWORDS = ["login", "verify", "update", "secure", "bank", "signin", "account", "password", "auth", "confirm"]

def analyze_url(url: str) -> dict:
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        domain = ext.top_domain_under_public_suffix.lower() if hasattr(ext, 'top_domain_under_public_suffix') and ext.top_domain_under_public_suffix else (ext.registered_domain.lower() if ext.registered_domain else parsed.netloc.lower())
        sub = ext.subdomain.lower()
        tld = ext.suffix.lower()
        features = {}
        reasons = []
        url_l = url.lower()
        
        if tld in SUSPICIOUS_TLDS:
            features["new_domain"] = True
            reasons.append(f"Suspicious TLD: .{tld}")
        if any(k in url_l for k in PHISHING_KEYWORDS):
            features["phishing_indicators"] = True
            reasons.append("Phishing-related keywords in URL")
        if re.search(r'\d{1,3}(?:\.\d{1,3}){3}', parsed.netloc):
            features["ip_reputation"] = True
            reasons.append("URL uses IP address instead of domain")
        if len(sub.split('.')) >= 3:
            features["phishing_indicators"] = True
            reasons.append("Suspicious subdomain structure")
        if parsed.query and any(k in parsed.query.lower() for k in ['redirect', 'url', 'next', 'goto']):
            features["suspicious_redirects"] = True
            reasons.append("Possible redirect parameter detected")
        if 'evil' in domain or 'phish' in domain or 'fake' in domain:
            features["phishing_indicators"] = True
            features["malware_signatures"] = True
            reasons.append("Known malicious domain pattern")
        
        return {"domain": domain, "tld": tld, "features": features, "reasons": reasons, "suspicious": len(features) > 0}
    except Exception as e:
        return {"domain": None, "features": {"phishing_indicators": True}, "reasons": [f"Parse error: {e}"], "suspicious": True}
