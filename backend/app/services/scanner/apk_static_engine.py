import os
import re
import tempfile
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

try:
    from loguru import logger as _loguru_logger
    _loguru_logger.disable("androguard")
except Exception:
    pass

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    ANDROGUARD_AVAILABLE = True
    ANDROGUARD_ENGINE_NAME = "androguard-4.1.4"
except Exception:
    APK = None
    DEX = None
    ANDROGUARD_AVAILABLE = False
    ANDROGUARD_ENGINE_NAME = "heuristic-fallback"

DANGEROUS_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 30,
    "android.permission.SYSTEM_ALERT_WINDOW": 20,
    "android.permission.REQUEST_INSTALL_PACKAGES": 20,
    "android.permission.SEND_SMS": 20,
    "android.permission.RECEIVE_SMS": 15,
    "android.permission.READ_SMS": 15,
    "android.permission.READ_CALL_LOG": 15,
    "android.permission.PROCESS_OUTGOING_CALLS": 15,
    "android.permission.RECORD_AUDIO": 4,
    "android.permission.CAMERA": 3,
    "android.permission.ACCESS_FINE_LOCATION": 3,
    "android.permission.READ_CONTACTS": 3,
    "android.permission.WRITE_EXTERNAL_STORAGE": 3,
    "android.permission.BIND_DEVICE_ADMIN": 30,
}

KNOWN_BANKING_PACKAGE_TARGETS = [
    "com.chase.sig.android",
    "com.infonow.bofa",
    "com.wf.wellsfargomobile",
    "com.citi.citimobile",
    "org.usaa.mobile.android.usaa",
]

# High-risk Android / Java API strings observed in DEX bytecode string pools
DANGEROUS_DEX_API_SIGNATURES: Dict[str, Tuple[str, int]] = {
    "dalvik/system/DexClassLoader": ("Dynamic DEX Code Loading (DexClassLoader)", 12),
    "dalvik/system/InMemoryDexClassLoader": ("In-Memory DEX Payload Loading", 18),
    "java/lang/Runtime;->exec": ("Shell Command Execution (Runtime.exec)", 10),
    "java/lang/ProcessBuilder": ("Process Spawning (ProcessBuilder)", 8),
    "android/telephony/SmsManager": ("Direct SMS API Usage (SmsManager)", 15),
    "android/accessibilityservice/AccessibilityService": ("Accessibility Service Implementation", 14),
    "android/media/projection/MediaProjectionManager": ("Screen Capture API (MediaProjection)", 10),
    "android/app/admin/DevicePolicyManager": ("Device Admin Policy Control", 14),
    "setComponentEnabledSetting": ("App Icon / Component Hiding API", 14),
    "/system/bin/su": ("Root Binary Probing (/system/bin/su)", 8),
    "android/webkit/WebView;->addJavascriptInterface": ("WebView JS Bridge (addJavascriptInterface)", 6),
}

URL_PATTERN = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,180}")
IGNORED_SCHEMA_DOMAINS = (
    "schemas.android.com",
    "www.w3.org",
    "xmlpull.org",
    "apache.org",
    "creativecommons.org",
    "purl.org",
    "ns.adobe.com",
    "example.com",
    "localhost",
    "127.0.0.1",
)
SUSPICIOUS_URL_TLDS = (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".icu", ".onion")
PRIVATE_IP_PREFIXES = ("10.", "127.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.")
SUSPICIOUS_NATIVE_TERMS = ("frida", "xposed", "substrate", "payload", "dropper", "shell", "jiagu", "bangcle", "secneo")
MAX_DEX_FILES_PER_APK = 25
MAX_STRINGS_PER_DEX = 150000


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
        uses_overlay: bool = False,
        uses_cleartext_traffic: bool = False,
        is_trusted_store: bool = False,
        cert_subject: Optional[str] = None,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        dangerous_apis = dangerous_apis or []
        embedded_urls = embedded_urls or []
        native_libraries = native_libraries or []
        extra_metadata = extra_metadata or {}

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
            suspicious_behaviors.append(
                "Severe Risk: Combination of Accessibility, Overlay, and SMS permissions observed (Typical of Anatsa/TeaBot/FluBot)"
            )
        elif uses_accessibility and uses_overlay:
            risk_score += 30
            suspicious_behaviors.append("App requests both Accessibility Service and Overlay window (Screen Hijack risk)")

        # 3. Check for Spyware indicators (requires mic + location + contacts + SMS/CallLog interception on untrusted origin)
        has_audio = "android.permission.RECORD_AUDIO" in permissions
        has_loc = "android.permission.ACCESS_FINE_LOCATION" in permissions
        has_contacts = "android.permission.READ_CONTACTS" in permissions
        has_comms = has_sms or ("android.permission.READ_CALL_LOG" in permissions)
        if not is_trusted_store and has_audio and has_loc and has_contacts and has_comms:
            risk_score += 40
            detected_families.append("Spyware / Commercial Surveillance")
            suspicious_behaviors.append(
                "Excessive background surveillance permissions (Audio, Location, Contacts, SMS/Call Logs)"
            )

        # 4. Check for Ransomware indicators
        if "android.permission.BIND_DEVICE_ADMIN" in permissions and uses_overlay:
            risk_score += 35
            detected_families.append("Ransomware / ScreenLocker")
            suspicious_behaviors.append(
                "Device Administrator binding combined with overlay capabilities (Common in ScreenLocker ransomware)"
            )

        # 5. Native libraries and obfuscation/packers
        suspicious_native = [
            lib
            for lib in native_libraries
            if any(term in lib.lower() for term in SUSPICIOUS_NATIVE_TERMS)
        ]
        if suspicious_native:
            risk_score += 30
            detected_families.append("Rootkit / Dropper")
            suspicious_behaviors.append(
                f"Suspicious native payload/packer detected: {', '.join(suspicious_native[:5])}"
            )

        # 6. DEX API static inspection indicators
        if dangerous_apis:
            api_weight_total = 0
            for api_label in dangerous_apis:
                matched_weight = next(
                    (w for _, (lbl, w) in DANGEROUS_DEX_API_SIGNATURES.items() if lbl == api_label),
                    6,
                )
                api_weight_total += matched_weight
            # Store-verified apps legitimately use WebView/Cipher/Dynamic loading SDKs
            effective_api_score = min(api_weight_total, 12 if is_trusted_store else 32)
            risk_score += effective_api_score
            if not is_trusted_store or api_weight_total >= 20:
                suspicious_behaviors.append(
                    f"Androguard DEX API indicators ({len(dangerous_apis)}): {', '.join(dangerous_apis[:4])}"
                )
            if any("In-Memory DEX" in a for a in dangerous_apis) and any("Icon" in a for a in dangerous_apis):
                risk_score += 25
                detected_families.append("Dropper / Stealth Loader")

        # 7. Suspicious embedded C2 / phishing URLs inside bytecode (hostname-level checks)
        suspicious_urls = []
        for u in embedded_urls:
            try:
                host = (urlparse(u).hostname or "").lower()
            except ValueError:
                continue
            if not host:
                continue
            is_bad_tld = any(host.endswith(tld) for tld in SUSPICIOUS_URL_TLDS)
            is_public_ip = (
                bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
                and not any(host.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)
            )
            if is_bad_tld or is_public_ip:
                suspicious_urls.append(u)
        if suspicious_urls:
            risk_score += 10 if is_trusted_store else 22
            suspicious_behaviors.append(
                f"Suspicious hardcoded URL/IP endpoint(s) in DEX: {', '.join(suspicious_urls[:3])}"
            )

        # 8. Manifest & Signing Certificate posture
        if is_debuggable:
            risk_score += 15
            suspicious_behaviors.append(
                "Application APK compiled with android:debuggable='true' (Vulnerable to memory tampering)"
            )

        if uses_cleartext_traffic and not is_trusted_store:
            risk_score += 8
            suspicious_behaviors.append("Manifest enables android:usesCleartextTraffic='true' (Unencrypted HTTP allowed)")

        if cert_subject and any(tag in cert_subject.lower() for tag in ("android debug", "testkey")):
            risk_score += 10
            suspicious_behaviors.append(f"Signed with development/test certificate ({cert_subject})")

        # 9. Unverified package origin heuristics
        if any(term in package_name.lower() for term in ["hack", "crack", "mod", "cheats", "fake"]):
            risk_score += 20
            detected_families.append("Trojan / Repackaged App")

        # Calibrate consumer Play Store / OEM packages unless explicit malware families triggered
        if is_trusted_store and not detected_families:
            risk_score = min(risk_score, 25)

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

        result = {
            "package_name": package_name,
            "verdict": verdict,
            "risk_score": risk_score,
            "threat_level": threat_level,
            "detected_families": sorted(set(detected_families)),
            "risky_permissions": risky_perms,
            "suspicious_behaviors": suspicious_behaviors,
            "reputation_status": "FLAGGED_MALWARE" if verdict == "MALICIOUS" else "VERIFIED_CLEAN",
            "recommendation": recommendation,
            "analysis_engine": extra_metadata.get("analysis_engine", "heuristic"),
            "app_name": extra_metadata.get("app_name"),
            "version_name": extra_metadata.get("version_name"),
            "min_sdk": extra_metadata.get("min_sdk"),
            "target_sdk": extra_metadata.get("target_sdk"),
            "dex_count": extra_metadata.get("dex_count", 0),
            "cert_sha256": extra_metadata.get("cert_sha256"),
            "cert_subject": cert_subject,
            "dangerous_apis": dangerous_apis,
            "native_libraries": native_libraries[:25],
            "embedded_urls": embedded_urls[:25],
            "exported_components": extra_metadata.get("exported_components", [])[:25],
        }
        return result

    def analyze_apk_bytes(
        self,
        apk_bytes: bytes,
        filename: str = "upload.apk",
        is_trusted_store: bool = False,
    ) -> Dict[str, Any]:
        if not ANDROGUARD_AVAILABLE:
            raise RuntimeError("Androguard library is not installed in this backend environment.")

        suffix = ".apk" if not filename.lower().endswith(".apk") else ""
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{os.path.basename(filename)}{suffix}") as tmp:
                tmp.write(apk_bytes)
                tmp_path = tmp.name
            return self.analyze_apk_file(tmp_path, is_trusted_store=is_trusted_store)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def analyze_apk_file(self, apk_path: str, is_trusted_store: bool = False) -> Dict[str, Any]:
        if not ANDROGUARD_AVAILABLE:
            raise RuntimeError("Androguard library is not installed in this backend environment.")

        try:
            apk = APK(apk_path)
        except Exception as exc:
            raise ValueError(f"Failed to parse APK via Androguard: {exc}") from exc

        package_name = apk.get_package() or "unknown.package"
        app_name = apk.get_app_name() or package_name
        permissions = apk.get_permissions() or []
        version_name = apk.get_androidversion_name()
        min_sdk = apk.get_min_sdk_version()
        target_sdk = apk.get_target_sdk_version()

        debuggable_attr = str(apk.get_attribute_value("application", "debuggable") or "").lower()
        is_debuggable = debuggable_attr == "true"

        cleartext_attr = str(apk.get_attribute_value("application", "usesCleartextTraffic") or "").lower()
        uses_cleartext = cleartext_attr == "true"

        uses_accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions
        uses_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in permissions

        # Native .so libraries inside APK archive
        native_libraries = sorted(
            {
                entry.rsplit("/", 1)[-1]
                for entry in (apk.get_files() or [])
                if entry.startswith("lib/") and entry.endswith(".so")
            }
        )

        # Signing certificate SHA-256 & subject via Androguard
        cert_sha256, cert_subject = self._extract_signing_certificate(apk)

        # Exported manifest components
        exported_components = self._extract_exported_components(apk)

        # DEX bytecode strings & API inspection
        dex_count, dangerous_apis, embedded_urls = self._scan_dex_payloads(apk)

        # Avoid counting AndroidX/framework boilerplate references unless matching permissions/services exist
        uses_device_admin = "android.permission.BIND_DEVICE_ADMIN" in permissions
        dangerous_apis = [
            api
            for api in dangerous_apis
            if not (api == "Accessibility Service Implementation" and not uses_accessibility)
            and not (api == "Device Admin Policy Control" and not uses_device_admin)
        ]

        return self.analyze_package_metadata(
            package_name=package_name,
            permissions=permissions,
            dangerous_apis=dangerous_apis,
            embedded_urls=embedded_urls,
            native_libraries=native_libraries,
            is_debuggable=is_debuggable,
            uses_accessibility=uses_accessibility,
            uses_overlay=uses_overlay,
            uses_cleartext_traffic=uses_cleartext,
            is_trusted_store=is_trusted_store,
            cert_subject=cert_subject,
            extra_metadata={
                "analysis_engine": ANDROGUARD_ENGINE_NAME,
                "app_name": app_name,
                "version_name": str(version_name) if version_name is not None else None,
                "min_sdk": str(min_sdk) if min_sdk is not None else None,
                "target_sdk": str(target_sdk) if target_sdk is not None else None,
                "dex_count": dex_count,
                "cert_sha256": cert_sha256,
                "exported_components": exported_components,
            },
        )

    def _extract_signing_certificate(self, apk: "APK") -> Tuple[Optional[str], Optional[str]]:
        try:
            certs = apk.get_certificates_v3() or apk.get_certificates_v2() or apk.get_certificates_v1() or []
            if not certs:
                return None, None
            cert = certs[0]
            sha256 = getattr(cert, "sha256_fingerprint", None)
            if isinstance(sha256, str):
                sha256 = sha256.replace(" ", "").lower()
            subject = None
            if getattr(cert, "subject", None) is not None:
                subject = cert.subject.human_friendly
            return sha256, subject
        except Exception:
            return None, None

    def _extract_exported_components(self, apk: "APK") -> List[str]:
        exported = []
        try:
            xml = apk.get_android_manifest_xml()
            if xml is None:
                return exported
            ns = "{http://schemas.android.com/apk/res/android}"
            for tag in ("activity", "service", "receiver", "provider"):
                for elem in xml.findall(f".//{tag}"):
                    name = elem.get(f"{ns}name")
                    if not name:
                        continue
                    exp_attr = elem.get(f"{ns}exported")
                    has_intent = elem.find("intent-filter") is not None
                    if exp_attr == "true" or (exp_attr is None and has_intent):
                        exported.append(f"{tag}:{name}")
        except Exception:
            pass
        return exported

    def _scan_dex_payloads(self, apk: "APK") -> Tuple[int, List[str], List[str]]:
        dex_count = 0
        detected_api_labels = set()
        urls_found = set()

        try:
            for dex_bytes in apk.get_all_dex():
                dex_count += 1
                if dex_count > MAX_DEX_FILES_PER_APK:
                    continue
                try:
                    dex = DEX(dex_bytes)
                    strings = dex.get_strings() or []
                except Exception:
                    continue

                for idx, raw_s in enumerate(strings):
                    if idx >= MAX_STRINGS_PER_DEX:
                        break
                    if not raw_s or len(raw_s) < 6:
                        continue

                    for sig, (label, _) in DANGEROUS_DEX_API_SIGNATURES.items():
                        if sig in raw_s:
                            detected_api_labels.add(label)

                    if "http://" in raw_s or "https://" in raw_s:
                        for match in URL_PATTERN.findall(raw_s):
                            lower_m = match.lower()
                            if any(dom in lower_m for dom in IGNORED_SCHEMA_DOMAINS):
                                continue
                            urls_found.add(match)
                            if len(urls_found) >= 50:
                                break
        except Exception:
            pass

        return dex_count, sorted(detected_api_labels), sorted(urls_found)


apk_engine = ApkStaticAnalysisEngine()
