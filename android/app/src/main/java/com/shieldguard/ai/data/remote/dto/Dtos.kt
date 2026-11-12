package com.shieldguard.ai.data.remote.dto

import com.google.gson.annotations.SerializedName

data class UrlScanRequestDto(
    @SerializedName("url") val url: String,
    @SerializedName("device_uuid") val deviceUuid: String?,
    @SerializedName("deep_analysis") val deepAnalysis: Boolean = true
)

data class UrlScanResponseDto(
    @SerializedName("url") val url: String,
    @SerializedName("domain") val domain: String,
    @SerializedName("verdict") val verdict: String,
    @SerializedName("risk_score") val riskScore: Int,
    @SerializedName("threat_level") val threatLevel: String,
    @SerializedName("reasons") val reasons: List<String>,
    @SerializedName("is_typosquatting") val isTyposquatting: Boolean,
    @SerializedName("is_homograph") val isHomograph: Boolean,
    @SerializedName("ssl_valid") val sslValid: Boolean,
    @SerializedName("threat_intel_matches") val threatIntelMatches: List<String>
)

data class ApkScanRequestDto(
    @SerializedName("package_name") val packageName: String,
    @SerializedName("app_name") val appName: String?,
    @SerializedName("version_code") val versionCode: Long?,
    @SerializedName("permissions") val permissions: List<String>,
    @SerializedName("dangerous_apis") val dangerousApis: List<String> = emptyList(),
    @SerializedName("embedded_urls") val embeddedUrls: List<String> = emptyList(),
    @SerializedName("native_libraries") val nativeLibraries: List<String> = emptyList(),
    @SerializedName("is_debuggable") val isDebuggable: Boolean = false,
    @SerializedName("uses_accessibility") val usesAccessibility: Boolean = false,
    @SerializedName("uses_overlay") val usesOverlay: Boolean = false
)

data class ApkScanResponseDto(
    @SerializedName("package_name") val packageName: String,
    @SerializedName("verdict") val verdict: String,
    @SerializedName("risk_score") val riskScore: Int,
    @SerializedName("threat_level") val threatLevel: String,
    @SerializedName("detected_families") val detectedFamilies: List<String>,
    @SerializedName("risky_permissions") val riskyPermissions: List<String>,
    @SerializedName("suspicious_behaviors") val suspiciousBehaviors: List<String>,
    @SerializedName("reputation_status") val reputationStatus: String,
    @SerializedName("recommendation") val recommendation: String,
    @SerializedName("analysis_engine") val analysisEngine: String = "heuristic",
    @SerializedName("app_name") val appName: String? = null,
    @SerializedName("version_name") val versionName: String? = null,
    @SerializedName("min_sdk") val minSdk: String? = null,
    @SerializedName("target_sdk") val targetSdk: String? = null,
    @SerializedName("dex_count") val dexCount: Int = 0,
    @SerializedName("cert_sha256") val certSha256: String? = null,
    @SerializedName("cert_subject") val certSubject: String? = null,
    @SerializedName("dangerous_apis") val dangerousApis: List<String> = emptyList(),
    @SerializedName("native_libraries") val nativeLibraries: List<String> = emptyList(),
    @SerializedName("embedded_urls") val embeddedUrls: List<String> = emptyList(),
    @SerializedName("exported_components") val exportedComponents: List<String> = emptyList()
)

data class DocumentScanRequestDto(
    @SerializedName("file_name") val fileName: String,
    @SerializedName("file_hash_sha256") val fileHashSha256: String,
    @SerializedName("file_size_bytes") val fileSizeBytes: Long,
    @SerializedName("file_extension") val fileExtension: String,
    @SerializedName("has_macros") val hasMacros: Boolean = false,
    @SerializedName("embedded_scripts") val embeddedScripts: List<String> = emptyList(),
    @SerializedName("embedded_urls") val embeddedUrls: List<String> = emptyList(),
    @SerializedName("suspicious_tags") val suspiciousTags: List<String> = emptyList()
)

data class DocumentScanResponseDto(
    @SerializedName("file_name") val fileName: String,
    @SerializedName("verdict") val verdict: String,
    @SerializedName("risk_score") val riskScore: Int,
    @SerializedName("threat_level") val threatLevel: String,
    @SerializedName("exploit_indicators") val exploitIndicators: List<String>,
    @SerializedName("macro_risk") val macroRisk: Boolean,
    @SerializedName("safe_to_open") val safeToOpen: Boolean,
    @SerializedName("quarantine_recommended") val quarantineRecommended: Boolean
)

data class DeviceAuditRequestDto(
    @SerializedName("device_uuid") val deviceUuid: String,
    @SerializedName("device_model") val deviceModel: String,
    @SerializedName("os_version") val osVersion: String,
    @SerializedName("is_rooted") val isRooted: Boolean,
    @SerializedName("developer_mode_enabled") val developerModeEnabled: Boolean,
    @SerializedName("usb_debugging_enabled") val usbDebuggingEnabled: Boolean,
    @SerializedName("adb_enabled") val adbEnabled: Boolean,
    @SerializedName("unknown_sources_enabled") val unknownSourcesEnabled: Boolean,
    @SerializedName("accessibility_services_count") val accessibilityServicesCount: Int,
    @SerializedName("overlay_apps_count") val overlayAppsCount: Int,
    @SerializedName("installed_apps_count") val installedAppsCount: Int
)

data class DeviceAuditResponseDto(
    @SerializedName("overall_security_score") val overallSecurityScore: Int,
    @SerializedName("security_posture") val securityPosture: String,
    @SerializedName("critical_findings") val criticalFindings: List<String>,
    @SerializedName("remediation_steps") val remediationSteps: List<String>
)
