package com.shieldguard.ai.data.local;

@javax.inject.Singleton()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\f\b\u0007\u0018\u0000 \u001f2\u00020\u0001:\u0001\u001fB\u0011\b\u0007\u0012\b\b\u0001\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0002\u0010\u0004J\u0006\u0010\t\u001a\u00020\u0006J\u0006\u0010\n\u001a\u00020\u000bJ\u0006\u0010\f\u001a\u00020\u0006J\u0006\u0010\r\u001a\u00020\u000bJ\u0006\u0010\u000e\u001a\u00020\u000bJ\u0006\u0010\u000f\u001a\u00020\u0010J\u0006\u0010\u0011\u001a\u00020\u0010J\u0006\u0010\u0012\u001a\u00020\u0010J\u000e\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\u0006J\u000e\u0010\u0016\u001a\u00020\u00142\u0006\u0010\u0017\u001a\u00020\u0010J\u000e\u0010\u0018\u001a\u00020\u00142\u0006\u0010\u0019\u001a\u00020\u000bJ\u000e\u0010\u001a\u001a\u00020\u00142\u0006\u0010\u0017\u001a\u00020\u0010J\u000e\u0010\u001b\u001a\u00020\u00142\u0006\u0010\u001c\u001a\u00020\u000bJ\u000e\u0010\u001d\u001a\u00020\u00142\u0006\u0010\u001c\u001a\u00020\u000bJ\u000e\u0010\u001e\u001a\u00020\u00142\u0006\u0010\u0017\u001a\u00020\u0010R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0006X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\bX\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006 "}, d2 = {"Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;", "", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "masterKeyAlias", "", "sharedPreferences", "Landroid/content/SharedPreferences;", "getAuthToken", "getCachedSecurityScore", "", "getDeviceUuid", "getScannedAppsCount", "getScannedFilesCount", "isAutoQuarantineEnabled", "", "isNotificationMonitorEnabled", "isVpnProtectionEnabled", "setAuthToken", "", "token", "setAutoQuarantineEnabled", "enabled", "setCachedSecurityScore", "score", "setNotificationMonitorEnabled", "setScannedAppsCount", "count", "setScannedFilesCount", "setVpnProtectionEnabled", "Companion", "app_debug"})
public final class EncryptedPreferencesManager {
    @org.jetbrains.annotations.NotNull()
    private final android.content.Context context = null;
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String masterKeyAlias = null;
    @org.jetbrains.annotations.NotNull()
    private final android.content.SharedPreferences sharedPreferences = null;
    @org.jetbrains.annotations.NotNull()
    private static final java.lang.String KEY_DEVICE_UUID = "key_device_uuid";
    @org.jetbrains.annotations.NotNull()
    private static final java.lang.String KEY_AUTH_TOKEN = "key_auth_token";
    @org.jetbrains.annotations.NotNull()
    private static final java.lang.String KEY_VPN_ACTIVE = "key_vpn_active";
    @org.jetbrains.annotations.NotNull()
    private static final java.lang.String KEY_NOTIF_MONITOR_ACTIVE = "key_notif_monitor_active";
    @org.jetbrains.annotations.NotNull()
    private static final java.lang.String KEY_AUTO_QUARANTINE = "key_auto_quarantine";
    @org.jetbrains.annotations.NotNull()
    private static final java.lang.String KEY_SECURITY_SCORE = "key_security_score";
    @org.jetbrains.annotations.NotNull()
    private static final java.lang.String KEY_SCANNED_APPS_COUNT = "key_scanned_apps_count";
    @org.jetbrains.annotations.NotNull()
    private static final java.lang.String KEY_SCANNED_FILES_COUNT = "key_scanned_files_count";
    @org.jetbrains.annotations.NotNull()
    public static final com.shieldguard.ai.data.local.EncryptedPreferencesManager.Companion Companion = null;
    
    @javax.inject.Inject()
    public EncryptedPreferencesManager(@dagger.hilt.android.qualifiers.ApplicationContext()
    @org.jetbrains.annotations.NotNull()
    android.content.Context context) {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getDeviceUuid() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getAuthToken() {
        return null;
    }
    
    public final void setAuthToken(@org.jetbrains.annotations.NotNull()
    java.lang.String token) {
    }
    
    public final boolean isVpnProtectionEnabled() {
        return false;
    }
    
    public final void setVpnProtectionEnabled(boolean enabled) {
    }
    
    public final boolean isNotificationMonitorEnabled() {
        return false;
    }
    
    public final void setNotificationMonitorEnabled(boolean enabled) {
    }
    
    public final boolean isAutoQuarantineEnabled() {
        return false;
    }
    
    public final void setAutoQuarantineEnabled(boolean enabled) {
    }
    
    public final int getCachedSecurityScore() {
        return 0;
    }
    
    public final void setCachedSecurityScore(int score) {
    }
    
    public final int getScannedAppsCount() {
        return 0;
    }
    
    public final void setScannedAppsCount(int count) {
    }
    
    public final int getScannedFilesCount() {
        return 0;
    }
    
    public final void setScannedFilesCount(int count) {
    }
    
    @kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\b\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002\u00a2\u0006\u0002\u0010\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u000b\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000\u00a8\u0006\f"}, d2 = {"Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager$Companion;", "", "()V", "KEY_AUTH_TOKEN", "", "KEY_AUTO_QUARANTINE", "KEY_DEVICE_UUID", "KEY_NOTIF_MONITOR_ACTIVE", "KEY_SCANNED_APPS_COUNT", "KEY_SCANNED_FILES_COUNT", "KEY_SECURITY_SCORE", "KEY_VPN_ACTIVE", "app_debug"})
    public static final class Companion {
        
        private Companion() {
            super();
        }
    }
}