package com.shieldguard.ai.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.shieldguard.ai.domain.model.AppThreatInfo
import com.shieldguard.ai.domain.model.ThreatLevel
import com.shieldguard.ai.domain.model.Verdict
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ApkStaticScanner @Inject constructor(
    @ApplicationContext private val context: Context
) {

    private val dangerousPermissionsMap = mapOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to 30,
        "android.permission.SYSTEM_ALERT_WINDOW" to 25,
        "android.permission.REQUEST_INSTALL_PACKAGES" to 20,
        "android.permission.SEND_SMS" to 20,
        "android.permission.RECEIVE_SMS" to 20,
        "android.permission.READ_SMS" to 20,
        "android.permission.RECORD_AUDIO" to 15,
        "android.permission.CAMERA" to 10,
        "android.permission.ACCESS_FINE_LOCATION" to 10,
        "android.permission.READ_CONTACTS" to 10,
        "android.permission.BIND_DEVICE_ADMIN" to 30
    )

    fun scanAllInstalledApps(): List<AppThreatInfo> {
        val pm = context.packageManager
        val installed = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        val scannedApps = mutableListOf<AppThreatInfo>()

        for (pkg in installed) {
            val appInfo = pkg.applicationInfo ?: continue
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            // Focus primarily on user-installed third party apps
            if (!isSystem || pkg.packageName.contains("updater") || pkg.packageName.contains("flash")) {
                scannedApps.add(analyzePackage(pm, pkg))
            }
        }
        return scannedApps.sortedByDescending { it.riskScore }
    }

    fun analyzePackage(pm: PackageManager, pkg: PackageInfo): AppThreatInfo {
        val appInfo = pkg.applicationInfo
        val appName = appInfo?.loadLabel(pm)?.toString() ?: pkg.packageName
        val permissions = pkg.requestedPermissions?.toList() ?: emptyList()
        val isSystem = ((appInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM) != 0
        val isDebuggable = ((appInfo?.flags ?: 0) and ApplicationInfo.FLAG_DEBUGGABLE) != 0

        val riskyPerms = mutableListOf<String>()
        val families = mutableListOf<String>()
        val behaviors = mutableListOf<String>()
        var score = 0

        // 1. Permission scoring
        for (perm in permissions) {
            dangerousPermissionsMap[perm]?.let { weight ->
                score += weight
                riskyPerms.add(perm.substringAfterLast("."))
            }
        }

        // 2. Behavioral combination heuristics
        val hasAccessibility = permissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
        val hasOverlay = permissions.contains("android.permission.SYSTEM_ALERT_WINDOW")
        val hasSms = permissions.any { it.contains("SMS") }

        if (hasAccessibility && hasOverlay && hasSms) {
            score += 45
            families.add("Banking Trojan (Overlay & Keystroke Interception)")
            behaviors.add("High Risk: Combines Accessibility Service, Screen Overlay, and SMS Interception")
        } else if (hasAccessibility && hasOverlay) {
            score += 30
            behaviors.add("Suspicious: Simultaneous Accessibility Service and Screen Overlay permission")
        }

        // Spyware detection
        val hasAudio = permissions.contains("android.permission.RECORD_AUDIO")
        val hasLoc = permissions.contains("android.permission.ACCESS_FINE_LOCATION")
        val hasContacts = permissions.contains("android.permission.READ_CONTACTS")
        if (hasAudio && hasLoc && hasContacts && !isSystem) {
            score += 35
            families.add("Spyware / Commercial Surveillance")
            behaviors.add("Full sensory and identity access (Mic, Location, Contacts)")
        }

        // Ransomware detection
        if (permissions.contains("android.permission.BIND_DEVICE_ADMIN") && hasOverlay) {
            score += 40
            families.add("Ransomware / ScreenLocker")
            behaviors.add("Device Administrator binding combined with overlay capabilities")
        }

        if (isDebuggable && !isSystem) {
            score += 15
            behaviors.add("Debuggable build flag enabled in production package")
        }

        score = score.coerceIn(0, 100)

        val verdict = when {
            score >= 70 -> Verdict.MALICIOUS
            score >= 35 -> Verdict.SUSPICIOUS
            else -> Verdict.SAFE
        }

        val threatLevel = when {
            score >= 85 -> ThreatLevel.CRITICAL
            score >= 65 -> ThreatLevel.HIGH
            score >= 35 -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }

        val recommendation = when (verdict) {
            Verdict.MALICIOUS -> "IMMEDIATE UNINSTALLATION RECOMMENDED. App exhibits high-risk malware patterns."
            Verdict.SUSPICIOUS -> "Review application permissions. Consider revoking Accessibility or Overlay."
            Verdict.SAFE -> "Permissions align with standard application posture."
        }

        val versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pkg.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            pkg.versionCode.toLong()
        }

        return AppThreatInfo(
            packageName = pkg.packageName,
            appName = appName,
            versionCode = versionCode,
            isSystemApp = isSystem,
            verdict = verdict,
            riskScore = score,
            threatLevel = threatLevel,
            dangerousPermissions = riskyPerms,
            malwareFamilies = families,
            behaviors = behaviors,
            recommendation = recommendation
        )
    }
}
