import re
import urllib.parse
from typing import Dict, Any, List

SUSPICIOUS_DOWNLOAD_EXTS = [
    ".exe", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".hta", ".iso", ".img", ".apk"
]

HIGH_RISK_EXTENSION_PERMISSIONS = [
    "<all_urls>", "*://*/*", "webRequestBlocking", "cookies", "debugger", "management",
    "proxy", "nativeMessaging", "privacy", "declarativeNetRequestFeedback"
]

def analyze_browser_url(url: str, page_title: str = "", has_password_field: bool = False, is_https: bool = True) -> Dict[str, Any]:
    """Evaluates a webpage visited in browser for phishing, fake logins, or domain spoofing."""
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    risk_score = 0
    reasons = []
    categories = []
    
    # Insecure password submission
    if has_password_field and not is_https:
        risk_score += 75
        reasons.append("Password input detected over insecure unencrypted HTTP connection")
        categories.append("insecure_login")
        
    # Fake login heuristic: popular brands impersonation in subdomains
    trusted_brands = ["google", "microsoft", "paypal", "apple", "netflix", "amazon", "chase", "bankofamerica"]
    for brand in trusted_brands:
        if brand in domain and not domain.endswith(f".{brand}.com") and domain != f"{brand}.com":
            risk_score += 80
            reasons.append(f"Domain impersonates trusted service '{brand}' via deceptive subdomain/SLD")
            categories.append("brand_impersonation")
            categories.append("phishing")
            break
            
    # Punycode / IDN Homograph
    if domain.startswith("xn--") or "xn--" in domain:
        risk_score += 45
        reasons.append("Punycode (IDN) detected - potential internationalized homograph attack")
        categories.append("homograph_attack")
        
    # Suspicious keywords in path
    if any(k in path for k in ["login", "signin", "verify", "secure", "account", "wallet", "update"]) and risk_score > 30:
        risk_score += 15
        reasons.append("Credential harvesting keyword patterns found in URL path")
        categories.append("credential_harvesting")
        
    risk_score = min(100, risk_score)
    risk_level = "low"
    if risk_score >= 70:
        risk_level = "critical"
    elif risk_score >= 40:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "moderate"
        
    action = "allow"
    if risk_score >= 70:
        action = "block"
    elif risk_score >= 40:
        action = "warn"
        
    return {
        "url": url,
        "domain": domain,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "action": action,
        "reasons": reasons,
        "categories": categories,
        "is_phishing": "phishing" in categories or "brand_impersonation" in categories,
    }

def analyze_download_safety(filename: str, source_url: str, file_size: int = 0) -> Dict[str, Any]:
    """Evaluates whether a browser download is dangerous."""
    lower_name = filename.lower()
    risk_score = 0
    reasons = []
    
    # Check double extensions (e.g. document.pdf.exe)
    if re.search(r'\.[a-z0-9]{2,4}\.(exe|scr|bat|vbs|cmd)$', lower_name):
        risk_score += 85
        reasons.append("Deceptive double extension detected (e.g., invoice.pdf.exe)")
        
    # Check high-risk executable formats
    for ext in SUSPICIOUS_DOWNLOAD_EXTS:
        if lower_name.endswith(ext):
            risk_score += 40
            reasons.append(f"Executable/script download extension '{ext}' requires inspection")
            break
            
    # Check direct IP source
    parsed = urllib.parse.urlparse(source_url)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
        risk_score += 30
        reasons.append("Download originating directly from raw IP address rather than verified domain")
        
    risk_score = min(100, risk_score)
    return {
        "filename": filename,
        "source_url": source_url,
        "risk_score": risk_score,
        "is_dangerous": risk_score >= 60,
        "reasons": reasons,
        "action": "block" if risk_score >= 70 else ("warn" if risk_score >= 40 else "allow")
    }

def analyze_extension_permissions(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Assesses browser extension manifest for privilege escalation and spyware risks."""
    name = manifest.get("name", "Unknown Extension")
    version = manifest.get("version", "1.0")
    permissions = manifest.get("permissions", [])
    optional_permissions = manifest.get("optional_permissions", [])
    all_perms = set(permissions + optional_permissions)
    
    risk_score = 0
    reasons = []
    excessive_perms = []
    
    for perm in HIGH_RISK_EXTENSION_PERMISSIONS:
        if perm in all_perms:
            risk_score += 20
            excessive_perms.append(perm)
            reasons.append(f"Broad permission requested: '{perm}' (can inspect all web traffic/content)")
            
    if "webRequestBlocking" in all_perms and ("<all_urls>" in all_perms or "*://*/*" in all_perms):
        risk_score += 35
        reasons.append("Critical risk: Extension can intercept, modify, or block all network requests")
        
    if "cookies" in all_perms and ("<all_urls>" in all_perms or "*://*/*" in all_perms):
        risk_score += 25
        reasons.append("Session hijacking risk: Extension has full access to authentication cookies across all domains")
        
    risk_score = min(100, risk_score)
    return {
        "name": name,
        "version": version,
        "risk_score": risk_score,
        "risk_level": "critical" if risk_score >= 70 else ("high" if risk_score >= 40 else "low"),
        "excessive_permissions": excessive_perms,
        "reasons": reasons,
        "recommendation": "Review required" if risk_score >= 40 else "Safe",
    }
