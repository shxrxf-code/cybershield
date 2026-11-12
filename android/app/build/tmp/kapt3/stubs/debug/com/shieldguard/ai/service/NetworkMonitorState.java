package com.shieldguard.ai.service;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\"\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0019\b\u0086\b\u0018\u00002\u00020\u0001BY\u0012\b\b\u0002\u0010\u0002\u001a\u00020\u0003\u0012\b\b\u0002\u0010\u0004\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0006\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0007\u001a\u00020\u0005\u0012\n\b\u0002\u0010\b\u001a\u0004\u0018\u00010\t\u0012\u000e\b\u0002\u0010\n\u001a\b\u0012\u0004\u0012\u00020\t0\u000b\u0012\u000e\b\u0002\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000e0\r\u00a2\u0006\u0002\u0010\u000fJ\t\u0010\u001b\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001c\u001a\u00020\u0005H\u00c6\u0003J\t\u0010\u001d\u001a\u00020\u0005H\u00c6\u0003J\t\u0010\u001e\u001a\u00020\u0005H\u00c6\u0003J\u000b\u0010\u001f\u001a\u0004\u0018\u00010\tH\u00c6\u0003J\u000f\u0010 \u001a\b\u0012\u0004\u0012\u00020\t0\u000bH\u00c6\u0003J\u000f\u0010!\u001a\b\u0012\u0004\u0012\u00020\u000e0\rH\u00c6\u0003J]\u0010\"\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00052\b\b\u0002\u0010\u0006\u001a\u00020\u00052\b\b\u0002\u0010\u0007\u001a\u00020\u00052\n\b\u0002\u0010\b\u001a\u0004\u0018\u00010\t2\u000e\b\u0002\u0010\n\u001a\b\u0012\u0004\u0012\u00020\t0\u000b2\u000e\b\u0002\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000e0\rH\u00c6\u0001J\u0013\u0010#\u001a\u00020\u00032\b\u0010$\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010%\u001a\u00020\u0005H\u00d6\u0001J\t\u0010&\u001a\u00020\tH\u00d6\u0001R\u0011\u0010\u0007\u001a\u00020\u0005\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0010\u0010\u0011R\u0011\u0010\u0006\u001a\u00020\u0005\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0012\u0010\u0011R\u0017\u0010\n\u001a\b\u0012\u0004\u0012\u00020\t0\u000b\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0013\u0010\u0014R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0002\u0010\u0015R\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0016\u0010\u0011R\u0017\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000e0\r\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0017\u0010\u0018R\u0013\u0010\b\u001a\u0004\u0018\u00010\t\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0019\u0010\u001a\u00a8\u0006\'"}, d2 = {"Lcom/shieldguard/ai/service/NetworkMonitorState;", "", "isVpnRunning", "", "packetsScanned", "", "blockedCount", "allowedCount", "suspiciousNetworkWarning", "", "blockedHosts", "", "recentEvents", "", "Lcom/shieldguard/ai/service/NetworkTrafficEvent;", "(ZIIILjava/lang/String;Ljava/util/Set;Ljava/util/List;)V", "getAllowedCount", "()I", "getBlockedCount", "getBlockedHosts", "()Ljava/util/Set;", "()Z", "getPacketsScanned", "getRecentEvents", "()Ljava/util/List;", "getSuspiciousNetworkWarning", "()Ljava/lang/String;", "component1", "component2", "component3", "component4", "component5", "component6", "component7", "copy", "equals", "other", "hashCode", "toString", "app_debug"})
public final class NetworkMonitorState {
    private final boolean isVpnRunning = false;
    private final int packetsScanned = 0;
    private final int blockedCount = 0;
    private final int allowedCount = 0;
    @org.jetbrains.annotations.Nullable()
    private final java.lang.String suspiciousNetworkWarning = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.Set<java.lang.String> blockedHosts = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<com.shieldguard.ai.service.NetworkTrafficEvent> recentEvents = null;
    
    public NetworkMonitorState(boolean isVpnRunning, int packetsScanned, int blockedCount, int allowedCount, @org.jetbrains.annotations.Nullable()
    java.lang.String suspiciousNetworkWarning, @org.jetbrains.annotations.NotNull()
    java.util.Set<java.lang.String> blockedHosts, @org.jetbrains.annotations.NotNull()
    java.util.List<com.shieldguard.ai.service.NetworkTrafficEvent> recentEvents) {
        super();
    }
    
    public final boolean isVpnRunning() {
        return false;
    }
    
    public final int getPacketsScanned() {
        return 0;
    }
    
    public final int getBlockedCount() {
        return 0;
    }
    
    public final int getAllowedCount() {
        return 0;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String getSuspiciousNetworkWarning() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.Set<java.lang.String> getBlockedHosts() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<com.shieldguard.ai.service.NetworkTrafficEvent> getRecentEvents() {
        return null;
    }
    
    public NetworkMonitorState() {
        super();
    }
    
    public final boolean component1() {
        return false;
    }
    
    public final int component2() {
        return 0;
    }
    
    public final int component3() {
        return 0;
    }
    
    public final int component4() {
        return 0;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String component5() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.Set<java.lang.String> component6() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<com.shieldguard.ai.service.NetworkTrafficEvent> component7() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.service.NetworkMonitorState copy(boolean isVpnRunning, int packetsScanned, int blockedCount, int allowedCount, @org.jetbrains.annotations.Nullable()
    java.lang.String suspiciousNetworkWarning, @org.jetbrains.annotations.NotNull()
    java.util.Set<java.lang.String> blockedHosts, @org.jetbrains.annotations.NotNull()
    java.util.List<com.shieldguard.ai.service.NetworkTrafficEvent> recentEvents) {
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