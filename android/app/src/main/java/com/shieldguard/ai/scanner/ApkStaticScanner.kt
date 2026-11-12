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

    private val trustedStoreInstallers = setOf(
        "com.android.vending",           // Google Play Store
        "com.heytap.market",             // OPPO / OnePlus App Market
        "com.oppo.market",
        "com.oplus.sau",                 // Oplus System App Updater
        "com.oplus.exsystemservice",
        "com.sec.android.app.samsungapps",
        "com.xiaomi.market",
        "com.amazon.venezia"
    )

    private val trustedOemPrefixes = listOf(
        "com.coloros.",
        "com.oplus.",
        "com.oppo.",
        "com.heytap.",
        "com.nearme.",
        "com.google.android."
    )

    private val highRiskAbusePermissions = mapOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to 30,
        "android.permission.BIND_DEVICE_ADMIN" to 30,
        "android.permission.SYSTEM_ALERT_WINDOW" to 20,
        "android.permission.REQUEST_INSTALL_PACKAGES" to 20,
        "android.permission.SEND_SMS" to 20,
        "android.permission.RECEIVE_SMS" to 15,
        "android.permission.READ_SMS" to 15,
        "android.permission.READ_CALL_LOG" to 15
    )

    private val standardRuntimePermissions = mapOf(
        "android.permission.RECORD_AUDIO" to 4,
        "android.permission.CAMERA" to 3,
        "android.permission.ACCESS_FINE_LOCATION" to 3,
        "android.permission.READ_CONTACTS" to 3
    )

    fun scanAllInstalledApps(
        includeSystemApps: Boolean = false,
        onProgress: ((current: Int, total: Int, appName: String) -> Unit)? = null
    ): List<AppThreatInfo> {
        val pm = context.packageManager
        val installed = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        val scannedApps = mutableListOf<AppThreatInfo>()

        val targets = installed.filter { pkg ->
            if (pkg.packageName == context.packageName) return@filter false
            if (includeSystemApps) return@filter true
            val appInfo = pkg.applicationInfo ?: return@filter false
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val isUpdatedSystem = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            !isSystem && !isUpdatedSystem
        }

        val total = targets.size
        targets.forEachIndexed { index, pkg ->
            val info = analyzePackage(pm, pkg)
            scannedApps.add(info)
            if (onProgress != null && (index % 5 == 0 || index == total - 1)) {
                onProgress(index + 1, total, info.appName)
            }
        }
        return scannedApps.sortedByDescending { it.riskScore }
    }

    fun analyzePackage(pm: PackageManager, pkg: PackageInfo): AppThreatInfo {
        val appInfo = pkg.applicationInfo
        val appName = appInfo?.loadLabel(pm)?.toString() ?: pkg.packageName
        val permissions = pkg.requestedPermissions?.toList() ?: emptyList()
        val permissionFlags = pkg.requestedPermissionsFlags
        val isSystem = ((appInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM) != 0
        val isDebuggable = ((appInfo?.flags ?: 0) and ApplicationInfo.FLAG_DEBUGGABLE) != 0

        val installerPkg = getInstallerPackage(pm, pkg.packageName)
        val isFromTrustedStore = installerPkg in trustedStoreInstallers
        val isTrustedOemPkg = trustedOemPrefixes.any { pkg.packageName.startsWith(it) }

        val grantedPermissions = mutableSetOf<String>()
        permissions.forEachIndexed { index, perm ->
            val isGranted = if (permissionFlags != null && index < permissionFlags.size) {
                (permissionFlags[index] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            } else {
                false
            }
            if (isGranted) grantedPermissions.add(perm)
        }

        val riskyPerms = mutableListOf<String>()
        val families = mutableListOf<String>()
        val behaviors = mutableListOf<String>()
        var score = 0

        // 1. Origin / Sideload evaluation
        if (!isFromTrustedStore && !isTrustedOemPkg && !isSystem) {
            score += 20
            behaviors.add("Sideloaded app (not installed via Google Play or OEM store)")
        }

        // 2. High-risk special permissions (evaluated strictly if granted or sideloaded)
        var highRiskScore = 0
        for ((perm, weight) in highRiskAbusePermissions) {
            if (permissions.contains(perm)) {
                val isGranted = grantedPermissions.contains(perm)
                if (isGranted || !isFromTrustedStore) {
                    highRiskScore += if (isGranted) weight else (weight / 2)
                    riskyPerms.add(perm.substringAfterLast("."))
                }
            }
        }
        score += highRiskScore.coerceAtMost(45)

        // 3. Standard consumer runtime permissions (never push Play Store apps into suspicious/malicious)
        var runtimeScore = 0
        for ((perm, weight) in standardRuntimePermissions) {
            if (grantedPermissions.contains(perm)) {
                runtimeScore += weight
                riskyPerms.add(perm.substringAfterLast("."))
            }
        }
        score += runtimeScore.coerceAtMost(12)

        // 4. Severe Malware Family Combination Signatures
        val hasAccessibility = permissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE") &&
            (grantedPermissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE") || !isFromTrustedStore)
        val hasOverlay = grantedPermissions.contains("android.permission.SYSTEM_ALERT_WINDOW") ||
            (!isFromTrustedStore && permissions.contains("android.permission.SYSTEM_ALERT_WINDOW"))
        val hasSms = permissions.any {
            it == "android.permission.SEND_SMS" || it == "android.permission.RECEIVE_SMS" || it == "android.permission.READ_SMS"
        } && (grantedPermissions.any { it.contains("SMS") } || !isFromTrustedStore)

        // Banking Trojan: Accessibility + Overlay + SMS
        if (hasAccessibility && hasOverlay && hasSms && !isTrustedOemPkg) {
            score += 45
            families.add("Banking Trojan (Overlay & Keystroke Interception)")
            behaviors.add("Combines Accessibility Service, Screen Overlay, and SMS Interception")
        }

        // Spyware: Sideloaded app with granted mic + location + contacts + (SMS or Call Log)
        val hasAudio = grantedPermissions.contains("android.permission.RECORD_AUDIO")
        val hasLoc = grantedPermissions.contains("android.permission.ACCESS_FINE_LOCATION")
        val hasContacts = grantedPermissions.contains("android.permission.READ_CONTACTS")
        val hasSensitiveComms = grantedPermissions.contains("android.permission.READ_SMS") ||
            grantedPermissions.contains("android.permission.READ_CALL_LOG")

        if (!isFromTrustedStore && !isTrustedOemPkg && hasAudio && hasLoc && hasContacts && hasSensitiveComms) {
            score += 40
            families.add("Spyware / Commercial Surveillance")
            behaviors.add("Sideloaded app granted extensive microphone, location, contacts, and message/call access")
        }

        // Ransomware: Device Admin + Screen Overlay
        val hasDeviceAdmin = permissions.contains("android.permission.BIND_DEVICE_ADMIN")
        if (hasDeviceAdmin && hasOverlay && !isTrustedOemPkg) {
            score += 45
            families.add("Ransomware / ScreenLocker")
            behaviors.add("Device Administrator binding combined with overlay capabilities")
        }

        // Debuggable build on non-system package
        if (isDebuggable && !isSystem && !isFromTrustedStore) {
            score += 20
            behaviors.add("Debuggable flag enabled in sideloaded package")
        }

        // Known suspicious package naming patterns (only for untrusted installs)
        if (!isFromTrustedStore && !isTrustedOemPkg &&
            listOf("hack", "crack", "modapk", "cheat", "spy", "stealer").any { pkg.packageName.lowercase().contains(it) }
        ) {
            score += 30
            families.add("Trojan / Repackaged Mod")
            behaviors.add("Package identifier matches high-risk trojan/mod pattern")
        }

        // Apply Play Store / Trusted OEM calibration cap unless an explicit malware family was triggered
        if ((isFromTrustedStore || isTrustedOemPkg) && families.isEmpty()) {
            score = score.coerceAtMost(25)
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
            Verdict.SUSPICIOUS -> "Review application origin and sensitive permissions."
            Verdict.SAFE -> if (isFromTrustedStore) "Verified store installation ($installerPkg). Clean posture." else "No active malware indicators found."
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
            dangerousPermissions = riskyPerms.distinct(),
            malwareFamilies = families.distinct(),
            behaviors = behaviors,
            recommendation = recommendation,
            apkPath = appInfo?.publicSourceDir ?: appInfo?.sourceDir,
            isTrustedStore = isFromTrustedStore || isTrustedOemPkg
        )
    }

    private fun getInstallerPackage(pm: PackageManager, packageName: String): String? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (e: Exception) {
            null
        }
    }
}
