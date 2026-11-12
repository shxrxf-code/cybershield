package com.shieldguard.ai.scanner;

@javax.inject.Singleton()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0003\b\u0007\u0018\u00002\u00020\u0001B\u0019\b\u0007\u0012\b\b\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0002\u0010\u0006J\u0006\u0010\u0007\u001a\u00020\bJ\b\u0010\t\u001a\u00020\nH\u0002J\b\u0010\u000b\u001a\u00020\nH\u0002J\b\u0010\f\u001a\u00020\rH\u0002J\b\u0010\u000e\u001a\u00020\rH\u0002J\b\u0010\u000f\u001a\u00020\rH\u0002R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u0010"}, d2 = {"Lcom/shieldguard/ai/scanner/DeviceIntegrityAuditor;", "", "context", "Landroid/content/Context;", "rootDetectionEngine", "Lcom/shieldguard/ai/scanner/RootDetectionEngine;", "(Landroid/content/Context;Lcom/shieldguard/ai/scanner/RootDetectionEngine;)V", "auditDevice", "Lcom/shieldguard/ai/domain/model/DeviceAudit;", "getActiveAccessibilityServicesCount", "", "getOverlayAppsCount", "isDeveloperOptionsEnabled", "", "isUnknownSourcesAllowed", "isUsbDebuggingEnabled", "app_debug"})
public final class DeviceIntegrityAuditor {
    @org.jetbrains.annotations.NotNull()
    private final android.content.Context context = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.scanner.RootDetectionEngine rootDetectionEngine = null;
    
    @javax.inject.Inject()
    public DeviceIntegrityAuditor(@dagger.hilt.android.qualifiers.ApplicationContext()
    @org.jetbrains.annotations.NotNull()
    android.content.Context context, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.scanner.RootDetectionEngine rootDetectionEngine) {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.DeviceAudit auditDevice() {
        return null;
    }
    
    private final boolean isDeveloperOptionsEnabled() {
        return false;
    }
    
    private final boolean isUsbDebuggingEnabled() {
        return false;
    }
    
    private final boolean isUnknownSourcesAllowed() {
        return false;
    }
    
    private final int getActiveAccessibilityServicesCount() {
        return 0;
    }
    
    private final int getOverlayAppsCount() {
        return 0;
    }
}