package com.shieldguard.ai.ui.dashboard;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0007\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b!\n\u0002\u0010\b\n\u0002\b\u0002\b\u0086\b\u0018\u00002\u00020\u0001B}\u0012\b\b\u0002\u0010\u0002\u001a\u00020\u0003\u0012\b\b\u0002\u0010\u0004\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0006\u001a\u00020\u0007\u0012\b\b\u0002\u0010\b\u001a\u00020\u0007\u0012\n\b\u0002\u0010\t\u001a\u0004\u0018\u00010\u0007\u0012\b\b\u0002\u0010\n\u001a\u00020\u0003\u0012\b\b\u0002\u0010\u000b\u001a\u00020\u0003\u0012\b\b\u0002\u0010\f\u001a\u00020\r\u0012\b\b\u0002\u0010\u000e\u001a\u00020\u000f\u0012\n\b\u0002\u0010\u0010\u001a\u0004\u0018\u00010\u0011\u0012\u000e\b\u0002\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00140\u0013\u00a2\u0006\u0002\u0010\u0015J\t\u0010\'\u001a\u00020\u0003H\u00c6\u0003J\u000b\u0010(\u001a\u0004\u0018\u00010\u0011H\u00c6\u0003J\u000f\u0010)\u001a\b\u0012\u0004\u0012\u00020\u00140\u0013H\u00c6\u0003J\t\u0010*\u001a\u00020\u0005H\u00c6\u0003J\t\u0010+\u001a\u00020\u0007H\u00c6\u0003J\t\u0010,\u001a\u00020\u0007H\u00c6\u0003J\u000b\u0010-\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003J\t\u0010.\u001a\u00020\u0003H\u00c6\u0003J\t\u0010/\u001a\u00020\u0003H\u00c6\u0003J\t\u00100\u001a\u00020\rH\u00c6\u0003J\t\u00101\u001a\u00020\u000fH\u00c6\u0003J\u0081\u0001\u00102\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00052\b\b\u0002\u0010\u0006\u001a\u00020\u00072\b\b\u0002\u0010\b\u001a\u00020\u00072\n\b\u0002\u0010\t\u001a\u0004\u0018\u00010\u00072\b\b\u0002\u0010\n\u001a\u00020\u00032\b\b\u0002\u0010\u000b\u001a\u00020\u00032\b\b\u0002\u0010\f\u001a\u00020\r2\b\b\u0002\u0010\u000e\u001a\u00020\u000f2\n\b\u0002\u0010\u0010\u001a\u0004\u0018\u00010\u00112\u000e\b\u0002\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00140\u0013H\u00c6\u0001J\u0013\u00103\u001a\u00020\u00032\b\u00104\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u00105\u001a\u000206H\u00d6\u0001J\t\u00107\u001a\u00020\u0007H\u00d6\u0001R\u0013\u0010\u0010\u001a\u0004\u0018\u00010\u0011\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0016\u0010\u0017R\u0011\u0010\n\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0018\u0010\u0019R\u0011\u0010\u000b\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001a\u0010\u0019R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0002\u0010\u0019R\u0013\u0010\t\u001a\u0004\u0018\u00010\u0007\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001b\u0010\u001cR\u0011\u0010\b\u001a\u00020\u0007\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001d\u0010\u001cR\u0011\u0010\f\u001a\u00020\r\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001e\u0010\u001fR\u0017\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00140\u0013\u00a2\u0006\b\n\u0000\u001a\u0004\b \u0010!R\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\b\n\u0000\u001a\u0004\b\"\u0010#R\u0011\u0010\u0006\u001a\u00020\u0007\u00a2\u0006\b\n\u0000\u001a\u0004\b$\u0010\u001cR\u0011\u0010\u000e\u001a\u00020\u000f\u00a2\u0006\b\n\u0000\u001a\u0004\b%\u0010&\u00a8\u00068"}, d2 = {"Lcom/shieldguard/ai/ui/dashboard/DashboardUiState;", "", "isScanning", "", "scanProgress", "", "scanStatusMessage", "", "liveCurrentItem", "lastScanSummary", "hasAllFilesAccess", "hasNotificationAccess", "notificationMonitorState", "Lcom/shieldguard/ai/service/NotificationMonitorState;", "securityScore", "Lcom/shieldguard/ai/domain/model/SecurityScore;", "deviceAudit", "Lcom/shieldguard/ai/domain/model/DeviceAudit;", "recentThreats", "", "Lcom/shieldguard/ai/domain/model/Threat;", "(ZFLjava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLcom/shieldguard/ai/service/NotificationMonitorState;Lcom/shieldguard/ai/domain/model/SecurityScore;Lcom/shieldguard/ai/domain/model/DeviceAudit;Ljava/util/List;)V", "getDeviceAudit", "()Lcom/shieldguard/ai/domain/model/DeviceAudit;", "getHasAllFilesAccess", "()Z", "getHasNotificationAccess", "getLastScanSummary", "()Ljava/lang/String;", "getLiveCurrentItem", "getNotificationMonitorState", "()Lcom/shieldguard/ai/service/NotificationMonitorState;", "getRecentThreats", "()Ljava/util/List;", "getScanProgress", "()F", "getScanStatusMessage", "getSecurityScore", "()Lcom/shieldguard/ai/domain/model/SecurityScore;", "component1", "component10", "component11", "component2", "component3", "component4", "component5", "component6", "component7", "component8", "component9", "copy", "equals", "other", "hashCode", "", "toString", "app_debug"})
public final class DashboardUiState {
    private final boolean isScanning = false;
    private final float scanProgress = 0.0F;
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String scanStatusMessage = null;
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String liveCurrentItem = null;
    @org.jetbrains.annotations.Nullable()
    private final java.lang.String lastScanSummary = null;
    private final boolean hasAllFilesAccess = false;
    private final boolean hasNotificationAccess = false;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.service.NotificationMonitorState notificationMonitorState = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.model.SecurityScore securityScore = null;
    @org.jetbrains.annotations.Nullable()
    private final com.shieldguard.ai.domain.model.DeviceAudit deviceAudit = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<com.shieldguard.ai.domain.model.Threat> recentThreats = null;
    
    public DashboardUiState(boolean isScanning, float scanProgress, @org.jetbrains.annotations.NotNull()
    java.lang.String scanStatusMessage, @org.jetbrains.annotations.NotNull()
    java.lang.String liveCurrentItem, @org.jetbrains.annotations.Nullable()
    java.lang.String lastScanSummary, boolean hasAllFilesAccess, boolean hasNotificationAccess, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.service.NotificationMonitorState notificationMonitorState, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.SecurityScore securityScore, @org.jetbrains.annotations.Nullable()
    com.shieldguard.ai.domain.model.DeviceAudit deviceAudit, @org.jetbrains.annotations.NotNull()
    java.util.List<com.shieldguard.ai.domain.model.Threat> recentThreats) {
        super();
    }
    
    public final boolean isScanning() {
        return false;
    }
    
    public final float getScanProgress() {
        return 0.0F;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getScanStatusMessage() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getLiveCurrentItem() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String getLastScanSummary() {
        return null;
    }
    
    public final boolean getHasAllFilesAccess() {
        return false;
    }
    
    public final boolean getHasNotificationAccess() {
        return false;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.service.NotificationMonitorState getNotificationMonitorState() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.SecurityScore getSecurityScore() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final com.shieldguard.ai.domain.model.DeviceAudit getDeviceAudit() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<com.shieldguard.ai.domain.model.Threat> getRecentThreats() {
        return null;
    }
    
    public DashboardUiState() {
        super();
    }
    
    public final boolean component1() {
        return false;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final com.shieldguard.ai.domain.model.DeviceAudit component10() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<com.shieldguard.ai.domain.model.Threat> component11() {
        return null;
    }
    
    public final float component2() {
        return 0.0F;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component3() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component4() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String component5() {
        return null;
    }
    
    public final boolean component6() {
        return false;
    }
    
    public final boolean component7() {
        return false;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.service.NotificationMonitorState component8() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.SecurityScore component9() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.ui.dashboard.DashboardUiState copy(boolean isScanning, float scanProgress, @org.jetbrains.annotations.NotNull()
    java.lang.String scanStatusMessage, @org.jetbrains.annotations.NotNull()
    java.lang.String liveCurrentItem, @org.jetbrains.annotations.Nullable()
    java.lang.String lastScanSummary, boolean hasAllFilesAccess, boolean hasNotificationAccess, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.service.NotificationMonitorState notificationMonitorState, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.SecurityScore securityScore, @org.jetbrains.annotations.Nullable()
    com.shieldguard.ai.domain.model.DeviceAudit deviceAudit, @org.jetbrains.annotations.NotNull()
    java.util.List<com.shieldguard.ai.domain.model.Threat> recentThreats) {
        return null;
    }
    
    @java.lang.Override()
    public boolean equals(@org.jetbrains.annotations.Nullable()
    java.lang.Object other) {
        return false;
    }
    
    @java.lang.Override()
    public int hashCode() {
        return 0;
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.NotNull()
    public java.lang.String toString() {
        return null;
    }
}