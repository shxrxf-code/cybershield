from __future__ import annotations
from typing import Dict, Any, List

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.INSTALL_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW"
}

def analyze_apk_permissions(permissions: List[str]) -> Dict[str, Any]:
    features = {}
    reasons = []
    found = [p for p in permissions if p in DANGEROUS_PERMISSIONS]
    if len(found) >= 2:
        features["behavior_anomaly"] = True
        reasons.append(f"Multiple dangerous permissions ({len(found)})")
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions:
        features["behavior_anomaly"] = True
        features["malware_signatures"] = True
        reasons.append("Accessibility service permission (high risk)")
    if "android.permission.INSTALL_PACKAGES" in permissions:
        features["malware_signatures"] = True
        reasons.append("Can install packages")
    if "android.permission.SEND_SMS" in permissions and "android.permission.READ_CONTACTS" in permissions:
        features["behavior_anomaly"] = True
        reasons.append("SMS + Contacts combination suspicious")
    return {"features": features, "reasons": reasons, "dangerous": found, "suspicious": len(features) > 0}
