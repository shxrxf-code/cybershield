package com.shieldguard.ai.domain.model

data class Threat(
    val id: String,
    val moduleType: ModuleType,
    val threatLevel: ThreatLevel,
    val verdict: Verdict,
    val riskScore: Int,
    val title: String,
    val description: String,
    val actionTaken: String,
    val rawPayload: String,
    val indicators: List<String>,
    val timestampMs: Long
)

data class ScanResult(
    val scanId: String,
    val scanType: String,
    val status: String,
    val riskScore: Int,
    val findingsCount: Int,
    val scannedItemsCount: Int,
    val findings: List<String>,
    val durationMs: Long,
    val timestampMs: Long
)

data class SecurityScore(
    val overallScore: Int, // 0 - 100
    val threatLevel: ThreatLevel,
    val activeThreatsCount: Int,
    val scannedAppsCount: Int,
    val scannedFilesCount: Int,
    val networkProtected: Boolean,
    val notificationShieldActive: Boolean
)

data class DeviceAudit(
    val isRooted: Boolean,
    val rootIndicators: List<String>,
    val developerModeEnabled: Boolean,
    val usbDebuggingEnabled: Boolean,
    val unknownSourcesEnabled: Boolean,
    val accessibilityAppsCount: Int,
    val overlayAppsCount: Int,
    val securityScore: Int,
    val posture: String,
    val recommendations: List<String>
)

data class AppThreatInfo(
    val packageName: String,
    val appName: String,
    val versionCode: Long,
    val isSystemApp: Boolean,
    val verdict: Verdict,
    val riskScore: Int,
    val threatLevel: ThreatLevel,
    val dangerousPermissions: List<String>,
    val malwareFamilies: List<String>,
    val behaviors: List<String>,
    val recommendation: String
)
