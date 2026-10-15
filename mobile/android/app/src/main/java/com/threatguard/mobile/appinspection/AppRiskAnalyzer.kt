package com.threatguard.mobile.appinspection

import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.content.pm.Signature
import android.os.Build
import android.util.Base64
import android.util.Log

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Risk assessment for an installed application based on its permissions and properties.
 */
class AppRiskAnalyzer(private val packageManager: PackageManager) {

    /** Sensitive permission groups that raise the risk score when combined. */
    private val sensitivePermissions = mapOf(
        "android.permission.CAMERA" to "Camera access",
        "android.permission.RECORD_AUDIO" to "Microphone access",
        "android.permission.ACCESS_FINE_LOCATION" to "Precise location",
        "android.permission.ACCESS_COARSE_LOCATION" to "Approximate location",
        "android.permission.READ_CONTACTS" to "Contacts access",
        "android.permission.WRITE_CONTACTS" to "Contacts modification",
        "android.permission.READ_SMS" to "SMS reading",
        "android.permission.RECEIVE_SMS" to "SMS receiving",
        "android.permission.SEND_SMS" to "SMS sending",
        "android.permission.READ_CALL_LOG" to "Call log reading",
        "android.permission.WRITE_CALL_LOG" to "Call log modification",
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to "Accessibility service",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" to "Notification access",
        "android.permission.READ_EXTERNAL_STORAGE" to "Storage reading",
        "android.permission.WRITE_EXTERNAL_STORAGE" to "Storage writing",
        "android.permission.MANAGE_EXTERNAL_STORAGE" to "All files access",
        "android.permission.SYSTEM_ALERT_WINDOW" to "Overlay/draw over apps",
        "android.permission.REQUEST_INSTALL_PACKAGES" to "Install packages",
        "android.permission.READ_PHONE_STATE" to "Phone state reading",
        "android.permission.CALL_PHONE" to "Direct calling",
        "android.permission.ANSWER_PHONE_CALLS" to "Answer calls",
        "android.permission.READ_CALENDAR" to "Calendar reading",
        "android.permission.WRITE_CALENDAR" to "Calendar modification",
        "android.permission.BODY_SENSORS" to "Body sensors",
        "android.permission.USE_BIOMETRIC" to "Biometric auth",
        "android.permission.USE_FINGERPRINT" to "Fingerprint auth"
    )

    /** Permission combinations that are particularly suspicious. */
    private val suspiciousCombinations = listOf(
        setOf("android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"),
        setOf("android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"),
        setOf("android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION"),
        setOf("android.permission.READ_CONTACTS", "android.permission.READ_SMS", "android.permission.READ_CALL_LOG"),
        setOf("android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.BIND_ACCESSIBILITY_SERVICE")
    )

    /**
     * Analyzes a package and returns risk assessment.
     */
    fun analyze(packageInfo: PackageInfo): AppRiskResult {
        val requestedPermissions = packageInfo.requestedPermissions ?: emptyArray()
        val permissionsInfo = mutableListOf<AppPermissionInfo>()
        var sensitiveCount = 0
        val foundSensitive = mutableSetOf<String>()

        // Gather permission details
        for (permName in requestedPermissions) {
            val isSensitive = sensitivePermissions.containsKey(permName)
            var granted = false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                try {
                    granted = packageManager.checkPermission(permName, packageInfo.packageName) == PackageManager.PERMISSION_GRANTED
                } catch (e: Exception) {
                    granted = false
                }
            }
            if (isSensitive) {
                sensitiveCount++
                foundSensitive.add(permName)
            }
            permissionsInfo.add(AppPermissionInfo(
                name = permName,
                label = sensitivePermissions[permName] ?: permName,
                isSensitive = isSensitive,
                granted = granted
            ))
        }

        // Check suspicious combinations
        val matchedCombinations = mutableListOf<String>()
        for (combo in suspiciousCombinations) {
            if (combo.all { it in foundSensitive }) {
                matchedCombinations.add(combo.joinToString(", ") { sensitivePermissions[it] ?: it })
            }
        }

        // Determine risk level
        val riskLevel = when {
            sensitiveCount >= 8 || matchedCombinations.size >= 2 -> RiskLevel.HIGH
            sensitiveCount >= 5 || matchedCombinations.size >= 1 -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }

        // Build reasons
        val reasons = mutableListOf<String>()
        if (sensitiveCount > 0) {
            reasons.add("Requests $sensitiveCount sensitive permission${if (sensitiveCount != 1) "s" else ""}")
        }
        for (combo in matchedCombinations) {
            reasons.add("Suspicious combination: $combo")
        }
        if (isDebuggable(packageInfo)) {
            reasons.add("Application is debuggable")
        }
        val appInfo = packageInfo.applicationInfo
        appInfo?.let {
            if (it.targetSdkVersion < Build.VERSION_CODES.Q) {
                reasons.add("Targets legacy Android SDK (API ${it.targetSdkVersion})")
            }
        }
        val sigInfo = getSignatureInfo(packageInfo)
        if (sigInfo.isDebug || sigInfo.isUnsigned) {
            reasons.add("Unusual signing: ${if (sigInfo.isDebug) "debug" else "unsigned"}")
        }

        return AppRiskResult(
            packageName = packageInfo.packageName,
            appName = appInfo?.let { packageManager.getApplicationLabel(it).toString() } ?: packageInfo.packageName,
            versionName = packageInfo.versionName ?: "Unknown",
            versionCode = packageInfo.versionCode.toLong(),
            isSystemApp = isSystemApp(packageInfo),
            riskLevel = riskLevel,
            requestedPermissions = permissionsInfo,
            reasons = reasons,
            installationSource = getInstallerPackageName(packageInfo.packageName),
            targetSdkVersion = appInfo?.targetSdkVersion ?: 0,
            targetSdkName = appInfo?.let { getAndroidVersionName(it.targetSdkVersion) } ?: "Unknown",
            iconHash = getIconHash(packageInfo)
        )
    }

    private fun isSystemApp(packageInfo: PackageInfo): Boolean {
        val appInfo = packageInfo.applicationInfo
        if (appInfo == null) return false
        val flags = appInfo.flags
        return (flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0 ||
               (flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
    }

    private fun isDebuggable(packageInfo: PackageInfo): Boolean {
        val appInfo = packageInfo.applicationInfo
        if (appInfo == null) return false
        return (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }

    private fun getInstallerPackageName(packageName: String): String? {
        try {
            return packageManager.getInstallerPackageName(packageName)
        } catch (e: Exception) {
            return null
        }
    }

    private fun getAndroidVersionName(apiLevel: Int): String {
        return when (apiLevel) {
            34 -> "Android 14"
            33 -> "Android 13"
            32 -> "Android 12L"
            31 -> "Android 12"
            30 -> "Android 11"
            29 -> "Android 10"
            28 -> "Android 9"
            27 -> "Android 8.1"
            26 -> "Android 8.0"
            25 -> "Android 7.1"
            24 -> "Android 7.0"
            23 -> "Android 6.0"
            22 -> "Android 5.1"
            21 -> "Android 5.0"
            else -> "API $apiLevel"
        }
    }

    private fun getSignatureInfo(packageInfo: PackageInfo): SignatureInfo {
        val signatures = packageInfo.signatures
        if (signatures == null || signatures.isEmpty()) {
            return SignatureInfo(isDebug = false, isUnsigned = true)
        }
        for (sig in signatures) {
            if (isDebugSignature(sig)) {
                return SignatureInfo(isDebug = true, isUnsigned = false)
            }
        }
        return SignatureInfo(isDebug = false, isUnsigned = false)
    }

    private fun isDebugSignature(signature: Signature): Boolean {
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            val bytes = digest.digest(signature.toByteArray())
            val hash = bytes.joinToString("") { "%02x".format(it) }
            // Common debug certificate SHA-256 (Android debug keystore)
            val debugHashes = setOf(
                "a40da80a59d170caa950cf15c18c454dffa13798e48a5c8c6b9b9f5c8e8f8a8b"
            )
            return debugHashes.contains(hash)
        } catch (e: NoSuchAlgorithmException) {
            return false
        }
    }

    private fun getIconHash(packageInfo: PackageInfo): String? {
        val appInfo = packageInfo.applicationInfo
        if (appInfo == null) return null
        try {
            val drawable = appInfo.loadIcon(packageManager)
            val bitmap = (drawable as android.graphics.drawable.BitmapDrawable).bitmap
            val bytes = java.io.ByteArrayOutputStream()
            bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, bytes)
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(bytes.toByteArray())
            return hash.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            return null
        }
    }

    data class SignatureInfo(val isDebug: Boolean, val isUnsigned: Boolean)
}

/** Risk level enumeration. */
enum class RiskLevel {
    LOW, MEDIUM, HIGH
}

/** Detailed permission information. */
data class AppPermissionInfo(
    val name: String,
    val label: String,
    val isSensitive: Boolean,
    val granted: Boolean
)

/** Complete risk assessment result for an app. */
data class AppRiskResult(
    val packageName: String,
    val appName: String,
    val versionName: String,
    val versionCode: Long,
    val isSystemApp: Boolean,
    val riskLevel: RiskLevel,
    val requestedPermissions: List<AppPermissionInfo>,
    val reasons: List<String>,
    val installationSource: String?,
    val targetSdkVersion: Int,
    val targetSdkName: String,
    val iconHash: String?
)

/**
 * Service for inspecting installed applications.
 * Runs on a background thread.
 */
class AppInspectionService(private val packageManager: PackageManager) {

    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val analyzer = AppRiskAnalyzer(packageManager)

    interface Callback {
        fun onComplete(results: List<AppRiskResult>)
        fun onError(error: Throwable)
    }

    /**
     * Performs a full inspection of all visible installed applications.
     */
    fun inspectAllApps(callback: Callback) {
        executor.execute {
            try {
                val installedPackages = packageManager.getInstalledPackages(
                    PackageManager.GET_PERMISSIONS or
                    PackageManager.GET_SIGNATURES or
                    PackageManager.GET_META_DATA
                )
                val results = mutableListOf<AppRiskResult>()
                for (pkg in installedPackages) {
                    try {
                        val risk = analyzer.analyze(pkg)
                        results.add(risk)
                    } catch (e: Exception) {
                        Log.w("AppInspectionService", "Failed to analyze ${pkg.packageName}", e)
                    }
                }
                callback.onComplete(results)
            } catch (e: Exception) {
                callback.onError(e)
            }
        }
    }

    /**
     * Inspects a single package by name.
     */
    fun inspectPackage(packageName: String, callback: Callback) {
        executor.execute {
            try {
                val pkg = packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_PERMISSIONS or
                    PackageManager.GET_SIGNATURES or
                    PackageManager.GET_META_DATA
                )
                val risk = analyzer.analyze(pkg)
                callback.onComplete(listOf(risk))
            } catch (e: Exception) {
                callback.onError(e)
            }
        }
    }

    /**
     * Shuts down the background executor.
     */
    fun shutdown() {
        executor.shutdownNow()
    }
}