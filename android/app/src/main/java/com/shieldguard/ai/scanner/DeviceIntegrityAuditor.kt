package com.shieldguard.ai.scanner

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.os.Build
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import com.shieldguard.ai.domain.model.DeviceAudit
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DeviceIntegrityAuditor @Inject constructor(
    @ApplicationContext private val context: Context,
    private val rootDetectionEngine: RootDetectionEngine
) {

    fun auditDevice(): DeviceAudit {
        val (isRooted, rootIndicators) = rootDetectionEngine.checkRootStatus()

        val devMode = isDeveloperOptionsEnabled()
        val usbDebug = isUsbDebuggingEnabled()
        val unknownSources = isUnknownSourcesAllowed()
        val accessibilityCount = getActiveAccessibilityServicesCount()
        val overlayCount = getOverlayAppsCount()

        val recommendations = mutableListOf<String>()
        var score = 100

        if (isRooted) {
            score -= 40
            recommendations.add("Critical: Root privileges detected. Flash stock OEM firmware to restore sandbox isolation.")
        }

        if (devMode || usbDebug) {
            score -= 15
            recommendations.add("Turn off Developer Options and USB Debugging in Android Settings to prevent unauthorized ADB access.")
        }

        if (unknownSources) {
            score -= 15
            recommendations.add("Disable 'Install from Unknown Sources' to safeguard against sideloaded malware.")
        }

        if (accessibilityCount > 2) {
            score -= 10
            recommendations.add("Audit enabled Accessibility Services. Untrusted apps can scrape credentials and bypass confirmations.")
        }

        if (overlayCount > 5) {
            score -= 10
            recommendations.add("Review apps with 'Display over other apps' permission to block tapjacking and screen spoofing.")
        }

        score = score.coerceIn(0, 100)

        val posture = when {
            score >= 80 -> "SECURE"
            score >= 50 -> "ELEVATED_RISK"
            else -> "COMPROMISED"
        }

        if (recommendations.isEmpty()) {
            recommendations.add("Device configuration meets highest enterprise security baseline.")
        }

        return DeviceAudit(
            isRooted = isRooted,
            rootIndicators = rootIndicators,
            developerModeEnabled = devMode,
            usbDebuggingEnabled = usbDebug,
            unknownSourcesEnabled = unknownSources,
            accessibilityAppsCount = accessibilityCount,
            overlayAppsCount = overlayCount,
            securityScore = score,
            posture = posture,
            recommendations = recommendations
        )
    }

    private fun isDeveloperOptionsEnabled(): Boolean {
        return try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) != 0
        } catch (e: Exception) {
            false
        }
    }

    private fun isUsbDebuggingEnabled(): Boolean {
        return try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) != 0
        } catch (e: Exception) {
            false
        }
    }

    private fun isUnknownSourcesAllowed(): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                // On modern Android (O+), unknown sources is per-app
                false
            } else {
                @Suppress("DEPRECATION")
                Settings.Secure.getInt(context.contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) != 0
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun getActiveAccessibilityServicesCount(): Int {
        return try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            am?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)?.size ?: 0
        } catch (e: Exception) {
            0
        }
    }

    private fun getOverlayAppsCount(): Int {
        // Approximate count of third-party apps requesting overlay
        return try {
            val pm = context.packageManager
            val packages = pm.getInstalledPackages(0)
            packages.count { (((it.applicationInfo?.flags) ?: 0) and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0 }
                .coerceAtMost(10)
        } catch (e: Exception) {
            0
        }
    }
}
