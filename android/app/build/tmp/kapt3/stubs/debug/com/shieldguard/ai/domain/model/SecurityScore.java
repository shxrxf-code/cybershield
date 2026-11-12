package com.shieldguard.ai.domain.model;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0018\n\u0002\u0010\u000e\n\u0000\b\u0086\b\u0018\u00002\u00020\u0001B=\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0003\u0012\u0006\u0010\u0007\u001a\u00020\u0003\u0012\u0006\u0010\b\u001a\u00020\u0003\u0012\u0006\u0010\t\u001a\u00020\n\u0012\u0006\u0010\u000b\u001a\u00020\n\u00a2\u0006\u0002\u0010\fJ\t\u0010\u0017\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0018\u001a\u00020\u0005H\u00c6\u0003J\t\u0010\u0019\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001a\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001b\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001c\u001a\u00020\nH\u00c6\u0003J\t\u0010\u001d\u001a\u00020\nH\u00c6\u0003JO\u0010\u001e\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00052\b\b\u0002\u0010\u0006\u001a\u00020\u00032\b\b\u0002\u0010\u0007\u001a\u00020\u00032\b\b\u0002\u0010\b\u001a\u00020\u00032\b\b\u0002\u0010\t\u001a\u00020\n2\b\b\u0002\u0010\u000b\u001a\u00020\nH\u00c6\u0001J\u0013\u0010\u001f\u001a\u00020\n2\b\u0010 \u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010!\u001a\u00020\u0003H\u00d6\u0001J\t\u0010\"\u001a\u00020#H\u00d6\u0001R\u0011\u0010\u0006\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b\r\u0010\u000eR\u0011\u0010\t\u001a\u00020\n\u00a2\u0006\b\n\u0000\u001a\u0004\b\u000f\u0010\u0010R\u0011\u0010\u000b\u001a\u00020\n\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0011\u0010\u0010R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0012\u0010\u000eR\u0011\u0010\u0007\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0013\u0010\u000eR\u0011\u0010\b\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0014\u0010\u000eR\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0015\u0010\u0016\u00a8\u0006$"}, d2 = {"Lcom/shieldguard/ai/domain/model/SecurityScore;", "", "overallScore", "", "threatLevel", "Lcom/shieldguard/ai/domain/model/ThreatLevel;", "activeThreatsCount", "scannedAppsCount", "scannedFilesCount", "networkProtected", "", "notificationShieldActive", "(ILcom/shieldguard/ai/domain/model/ThreatLevel;IIIZZ)V", "getActiveThreatsCount", "()I", "getNetworkProtected", "()Z", "getNotificationShieldActive", "getOverallScore", "getScannedAppsCount", "getScannedFilesCount", "getThreatLevel", "()Lcom/shieldguard/ai/domain/model/ThreatLevel;", "component1", "component2", "component3", "component4", "component5", "component6", "component7", "copy", "equals", "other", "hashCode", "toString", "", "app_debug"})
public final class SecurityScore {
    private final int overallScore = 0;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.model.ThreatLevel threatLevel = null;
    private final int activeThreatsCount = 0;
    private final int scannedAppsCount = 0;
    private final int scannedFilesCount = 0;
    private final boolean networkProtected = false;
    private final boolean notificationShieldActive = false;
    
    public SecurityScore(int overallScore, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.ThreatLevel threatLevel, int activeThreatsCount, int scannedAppsCount, int scannedFilesCount, boolean networkProtected, boolean notificationShieldActive) {
        super();
    }
    
    public final int getOverallScore() {
        return 0;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.ThreatLevel getThreatLevel() {
        return null;
    }
    
    public final int getActiveThreatsCount() {
        return 0;
    }
    
    public final int getScannedAppsCount() {
        return 0;
    }
    
    public final int getScannedFilesCount() {
        return 0;
    }
    
    public final boolean getNetworkProtected() {
        return false;
    }
    
    public final boolean getNotificationShieldActive() {
        return false;
    }
    
    public final int component1() {
        return 0;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.ThreatLevel component2() {
        return null;
    }
    
    public final int component3() {
        return 0;
    }
    
    public final int component4() {
        return 0;
    }
    
    public final int component5() {
        return 0;
    }
    
    public final boolean component6() {
        return false;
    }
    
    public final boolean component7() {
        return false;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.SecurityScore copy(int overallScore, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.ThreatLevel threatLevel, int activeThreatsCount, int scannedAppsCount, int scannedFilesCount, boolean networkProtected, boolean notificationShieldActive) {
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