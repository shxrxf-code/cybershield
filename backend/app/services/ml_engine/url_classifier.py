import re
import math
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple
from difflib import SequenceMatcher

try:
    import tldextract
except ImportError:
    tldextract = None


class DomainExtractFallback:
    def __init__(self, domain: str, suffix: str, subdomain: str):
        self.domain = domain
        self.suffix = suffix
        self.subdomain = subdomain


def extract_domain_parts(url: str):
    if tldextract:
        return tldextract.extract(url)
    # Standard library fallback
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.split(":")[0]
    parts = host.split(".")
    if len(parts) >= 2:
        suffix = parts[-1]
        domain = parts[-2]
        subdomain = ".".join(parts[:-2])
    else:
        suffix = ""
        domain = host
        subdomain = ""
    return DomainExtractFallback(domain=domain, suffix=suffix, subdomain=subdomain)

POPULAR_DOMAINS = [
    "google.com", "apple.com", "microsoft.com", "amazon.com", "paypal.com",
    "netflix.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "facebook.com", "instagram.com", "whatsapp.com", "telegram.org",
    "binance.com", "coinbase.com", "metamask.io", "twitter.com", "linkedin.com"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "buzz", "club", "gq", "cf", "tk", "ml", "ga",
    "date", "racing", "download", "stream", "bid", "accountant", "loan"
}

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "account", "banking", "update", "signin",
    "confirm", "wallet", "suspend", "billing", "recover", "authenticate",
    "password", "airdrop", "free", "gift", "bonus", "reward", "security"
]


class URLFeatureExtractor:
    @staticmethod
    def calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    @staticmethod
    def is_ip_address(hostname: str) -> bool:
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        return bool(re.match(ip_pattern, hostname))

    @staticmethod
    def detect_homograph(domain: str) -> bool:
        """Detects punycode or Cyrillic/Greek lookalike characters in Latin domains."""
        if domain.startswith("xn--"):
            return True
        # Check non-ascii in domain
        try:
            domain.encode("ascii")
            return False
        except UnicodeEncodeError:
            return True

    @staticmethod
    def check_typosquatting(domain_name: str) -> Tuple[bool, str]:
        """Calculates Levenshtein similarity to known high-value targets."""
        for target in POPULAR_DOMAINS:
            target_name = target.split(".")[0]
            similarity = SequenceMatcher(None, domain_name, target_name).ratio()
            if 0.80 <= similarity < 1.0 and domain_name != target_name:
                return True, target
        return False, ""

    @classmethod
    def extract_features(cls, url: str) -> Dict[str, Any]:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        extracted = extract_domain_parts(url)
        domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        subdomain = extracted.subdomain
        hostname = parsed.netloc or ""
        path = parsed.path or ""

        is_typo, typo_target = cls.check_typosquatting(extracted.domain)
        is_homo = cls.detect_homograph(hostname)
        entropy = cls.calculate_entropy(hostname)
        is_ip = cls.is_ip_address(hostname)

        # Keyword matching
        keyword_hits = [kw for kw in PHISHING_KEYWORDS if kw in url.lower()]

        return {
            "url_length": len(url),
            "hostname_length": len(hostname),
            "path_length": len(path),
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_slashes": url.count("/"),
            "num_at_symbols": url.count("@"),
            "num_subdomains": len(subdomain.split(".")) if subdomain else 0,
            "has_ip_hostname": is_ip,
            "hostname_entropy": round(entropy, 3),
            "is_typosquatting": is_typo,
            "typosquat_target": typo_target,
            "is_homograph": is_homo,
            "is_suspicious_tld": extracted.suffix.lower() in SUSPICIOUS_TLDS,
            "phishing_keywords_found": keyword_hits,
            "domain": domain,
            "uses_https": parsed.scheme.lower() == "https"
        }


class URLSecurityClassifier:
    def __init__(self):
        self.extractor = URLFeatureExtractor()

    def analyze(self, url: str, intel_data: Dict[str, Any] = None) -> Dict[str, Any]:
        features = self.extractor.extract_features(url)
        risk_score = 0
        reasons = []

        # Feature rule weights
        if features["is_homograph"]:
            risk_score += 45
            reasons.append("Homograph attack detected (lookalike Unicode or Punycode domain)")

        if features["is_typosquatting"]:
            risk_score += 40
            reasons.append(f"Typosquatting target detected resembling '{features['typosquat_target']}'")

        if features["has_ip_hostname"]:
            risk_score += 35
            reasons.append("URL uses raw numeric IP address instead of registered domain name")

        if features["is_suspicious_tld"]:
            risk_score += 25
            reasons.append("High-risk top-level domain frequently associated with phishing campaigns")

        if len(features["phishing_keywords_found"]) > 0:
            kw_points = min(len(features["phishing_keywords_found"]) * 12, 36)
            risk_score += kw_points
            reasons.append(f"Suspicious security keywords found in URL: {', '.join(features['phishing_keywords_found'])}")

        if features["hostname_entropy"] > 4.2:
            risk_score += 15
            reasons.append("High domain entropy (DGA or randomized subdomain pattern)")

        if features["num_subdomains"] >= 3:
            risk_score += 15
            reasons.append("Excessive nested subdomains detected")

        if not features["uses_https"]:
            risk_score += 10
            reasons.append("Insecure plain HTTP connection (Missing SSL/TLS encryption)")

        # Factor in external Threat Intelligence if available
        if intel_data:
            if intel_data.get("is_malicious"):
                risk_score = max(risk_score, 88)
                reasons.append(f"Flagged by global threat feeds: {', '.join(intel_data.get('threat_sources', []))}")
            if intel_data.get("vt_positives", 0) > 0:
                risk_score = min(100, risk_score + (intel_data["vt_positives"] * 15))
                reasons.append(f"VirusTotal detected {intel_data['vt_positives']} security vendors flagging URL")

        # Clamp score 0 - 100
        risk_score = min(max(risk_score, 0), 100)

        # Classification
        if risk_score >= 70:
            verdict = "MALICIOUS"
            threat_level = "CRITICAL" if risk_score >= 85 else "HIGH"
        elif risk_score >= 35:
            verdict = "SUSPICIOUS"
            threat_level = "MEDIUM"
        else:
            verdict = "SAFE"
            threat_level = "LOW"

        if not reasons:
            reasons.append("Legitimate domain reputation with clean security telemetry")

        return {
            "url": url,
            "domain": features["domain"],
            "verdict": verdict,
            "risk_score": risk_score,
            "threat_level": threat_level,
            "reasons": reasons,
            "features": features,
            "is_typosquatting": features["is_typosquatting"],
            "is_homograph": features["is_homograph"],
            "ssl_valid": features["uses_https"]
        }


url_classifier = URLSecurityClassifier()
