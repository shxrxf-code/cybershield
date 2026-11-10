from typing import Dict, Any, List

DANGEROUS_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 30,
    "android.permission.SYSTEM_ALERT_WINDOW": 25,
    "android.permission.REQUEST_INSTALL_PACKAGES": 25,
    "android.permission.SEND_SMS": 20,
    "android.permission.RECEIVE_SMS": 20,
    "android.permission.READ_SMS": 20,
    "android.permission.READ_CALL_LOG": 15,
    "android.permission.PROCESS_OUTGOING_CALLS": 15,
    "android.permission.RECORD_AUDIO": 15,
    "android.permission.CAMERA": 10,
    "android.permission.ACCESS_FINE_LOCATION": 10,
    "android.permission.READ_CONTACTS": 10,
    "android.permission.WRITE_EXTERNAL_STORAGE": 10,
    "android.permission.BIND_DEVICE_ADMIN": 30
}

KNOWN_BANKING_PACKAGE_TARGETS = [
    "com.chase.sig.android", "com.infonow.bofa", "com.wf.wellsfargomobile",
    "com.citi.citimobile", "org.usaa.mobile.android.usaa"
]


class ApkStaticAnalysisEngine:
    def __init__(self):
        pass

    def analyze_package_metadata(
        self,
        package_name: str,
        permissions: List[str],
        dangerous_apis: List[str] = None,
        embedded_urls: List[str] = None,
        native_libraries: List[str] = None,
        is_debuggable: bool = False,
        uses_accessibility: bool = False,
        uses_overlay: bool = False
    ) -> Dict[str, Any]:
        dangerous_apis = dangerous_apis or []
        embedded_urls = embedded_urls or []
        native_libraries = native_libraries or []

        risk_score = 0
        risky_perms = []
        suspicious_behaviors = []
        detected_families = []

        # 1. Analyze requested permissions
        perm_score = 0
        for perm in permissions:
            if perm in DANGEROUS_PERMISSIONS:
                weight = DANGEROUS_PERMISSIONS[perm]
                perm_score += weight
                risky_perms.append(perm)

        risk_score += min(perm_score, 45)

        # 2. Check for Banking Trojan Behavioral Combo
        # (Accessibility Service + Screen Overlay + SMS interception)
        has_sms = any("SMS" in p for p in permissions)
        if uses_accessibility and uses_overlay and has_sms:
            risk_score += 45
            detected_families.append("Banking Trojan (Overlay & Keystroke Interception Signature)")
            suspicious_behaviors.append("Severe Risk: Combination of Accessibility, Overlay, and SMS permissions observed (Typical of Anatsa/TeaBot/FluBot)")
        elif uses_accessibility and uses_overlay:
            risk_score += 30
            suspicious_behaviors.append("App requests both Accessibility Service and Overlay window (Screen Hijack risk)")

        # 3. Check for Spyware indicators
        has_audio = "android.permission.RECORD_AUDIO" in permissions
        has_loc = "android.permission.ACCESS_FINE_LOCATION" in permissions
        has_contacts = "android.permission.READ_CONTACTS" in permissions
        if has_audio and has_loc and has_contacts:
            if "android.permission.CAMERA" in permissions or has_sms:
                risk_score += 35
                detected_families.append("Spyware / Commercial Surveillance")
                suspicious_behaviors.append("Excessive background surveillance permissions (Audio, Camera, Location, Contacts)")

        # 4. Check for Ransomware indicators
        if "android.permission.BIND_DEVICE_ADMIN" in permissions and uses_overlay:
            risk_score += 35
            detected_families.append("Ransomware / ScreenLocker")
            suspicious_behaviors.append("Device Administrator binding combined with overlay capabilities (Common in ScreenLocker ransomware)")

        # 5. Native libraries and obfuscation
        suspicious_native = [lib for lib in native_libraries if any(term in lib.lower() for term in ["frida", "xposed", "payload", "dropper", "shell"])]
        if suspicious_native:
            risk_score += 30
            detected_families.append("Rootkit / Dropper")
            suspicious_behaviors.append(f"Suspicious native payload detected: {', '.join(suspicious_native)}")

        # 6. Debuggable flag in production
        if is_debuggable:
            risk_score += 15
            suspicious_behaviors.append("Application APK compiled with android:debuggable='true' (Vulnerable to memory tampering)")

        # 7. Unverified package origin heuristics
        if any(term in package_name.lower() for term in ["hack", "crack", "mod", "cheats", "fake"]):
            risk_score += 20
            detected_families.append("Trojan / Repackaged App")

        # Clamp risk score
        risk_score = min(max(risk_score, 0), 100)

        if risk_score >= 70:
            verdict = "MALICIOUS"
            threat_level = "CRITICAL" if "Banking Trojan" in str(detected_families) else "HIGH"
            recommendation = "IMMEDIATE UNINSTALLATION REQUIRED. Do not grant permissions or launch application."
        elif risk_score >= 35:
            verdict = "SUSPICIOUS"
            threat_level = "MEDIUM"
            recommendation = "Review application permissions. Revoke Accessibility and Overlay permissions."
        else:
            verdict = "SAFE"
            threat_level = "LOW"
            recommendation = "App permissions and behavioral posture align with standard Android applications."

        return {
            "package_name": package_name,
            "verdict": verdict,
            "risk_score": risk_score,
            "threat_level": threat_level,
            "detected_families": list(set(detected_families)),
            "risky_permissions": risky_perms,
            "suspicious_behaviors": suspicious_behaviors,
            "reputation_status": "FLAGGED_MALWARE" if verdict == "MALICIOUS" else "VERIFIED_CLEAN",
            "recommendation": recommendation
        }


apk_engine = ApkStaticAnalysisEngine()
