package com.shieldguard.ai.data.local

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import dagger.hilt.android.qualifiers.ApplicationContext
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class EncryptedPreferencesManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

    private val sharedPreferences: SharedPreferences = runCatching {
        EncryptedSharedPreferences.create(
            "shieldguard_secure_prefs",
            masterKeyAlias,
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }.getOrElse {
        context.getSharedPreferences("shieldguard_prefs_fallback", Context.MODE_PRIVATE)
    }

    companion object {
        private const val KEY_DEVICE_UUID = "key_device_uuid"
        private const val KEY_AUTH_TOKEN = "key_auth_token"
        private const val KEY_VPN_ACTIVE = "key_vpn_active"
        private const val KEY_NOTIF_MONITOR_ACTIVE = "key_notif_monitor_active"
        private const val KEY_AUTO_QUARANTINE = "key_auto_quarantine"
        private const val KEY_SECURITY_SCORE = "key_security_score"
        private const val KEY_SCANNED_APPS_COUNT = "key_scanned_apps_count"
        private const val KEY_SCANNED_FILES_COUNT = "key_scanned_files_count"
    }

    fun getDeviceUuid(): String {
        var uuid = sharedPreferences.getString(KEY_DEVICE_UUID, null)
        if (uuid == null) {
            uuid = UUID.randomUUID().toString()
            sharedPreferences.edit().putString(KEY_DEVICE_UUID, uuid).apply()
        }
        return uuid
    }

    fun getAuthToken(): String {
        return sharedPreferences.getString(KEY_AUTH_TOKEN, "sg_live_mobile_client_default") ?: "sg_live_mobile_client_default"
    }

    fun setAuthToken(token: String) {
        sharedPreferences.edit().putString(KEY_AUTH_TOKEN, token).apply()
    }

    fun isVpnProtectionEnabled(): Boolean {
        return sharedPreferences.getBoolean(KEY_VPN_ACTIVE, false)
    }

    fun setVpnProtectionEnabled(enabled: Boolean) {
        sharedPreferences.edit().putBoolean(KEY_VPN_ACTIVE, enabled).apply()
    }

    fun isNotificationMonitorEnabled(): Boolean {
        return sharedPreferences.getBoolean(KEY_NOTIF_MONITOR_ACTIVE, true)
    }

    fun setNotificationMonitorEnabled(enabled: Boolean) {
        sharedPreferences.edit().putBoolean(KEY_NOTIF_MONITOR_ACTIVE, enabled).apply()
    }

    fun isAutoQuarantineEnabled(): Boolean {
        return sharedPreferences.getBoolean(KEY_AUTO_QUARANTINE, true)
    }

    fun setAutoQuarantineEnabled(enabled: Boolean) {
        sharedPreferences.edit().putBoolean(KEY_AUTO_QUARANTINE, enabled).apply()
    }

    fun getCachedSecurityScore(): Int {
        return sharedPreferences.getInt(KEY_SECURITY_SCORE, 95)
    }

    fun setCachedSecurityScore(score: Int) {
        sharedPreferences.edit().putInt(KEY_SECURITY_SCORE, score).apply()
    }

    fun getScannedAppsCount(): Int {
        return sharedPreferences.getInt(KEY_SCANNED_APPS_COUNT, 0)
    }

    fun setScannedAppsCount(count: Int) {
        sharedPreferences.edit().putInt(KEY_SCANNED_APPS_COUNT, count).apply()
    }

    fun getScannedFilesCount(): Int {
        return sharedPreferences.getInt(KEY_SCANNED_FILES_COUNT, 0)
    }

    fun setScannedFilesCount(count: Int) {
        sharedPreferences.edit().putInt(KEY_SCANNED_FILES_COUNT, count).apply()
    }
}
