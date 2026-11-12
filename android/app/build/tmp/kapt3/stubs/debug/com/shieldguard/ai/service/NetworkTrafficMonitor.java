package com.shieldguard.ai.service;

@javax.inject.Singleton()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010#\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\"\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010 \n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\b\u0007\u0018\u00002\u00020\u0001B\u0007\b\u0007\u00a2\u0006\u0002\u0010\u0002J\u000e\u0010\u0014\u001a\u00020\u00152\u0006\u0010\u0016\u001a\u00020\bJ\u001a\u0010\u0017\u001a\u000e\u0012\u0004\u0012\u00020\u0019\u0012\u0004\u0012\u00020\b0\u00182\u0006\u0010\u001a\u001a\u00020\bJ\f\u0010\u001b\u001a\b\u0012\u0004\u0012\u00020\b0\u000bJ\u000e\u0010\u001c\u001a\u00020\u00152\u0006\u0010\u001d\u001a\u00020\u001eJ\u000e\u0010\u001f\u001a\u00020\u00152\u0006\u0010\u0016\u001a\u00020\bJ\u0010\u0010 \u001a\u00020\u00152\b\u0010!\u001a\u0004\u0018\u00010\bJ\u000e\u0010\"\u001a\u00020\u00152\u0006\u0010#\u001a\u00020\u0019R\u0014\u0010\u0003\u001a\b\u0012\u0004\u0012\u00020\u00050\u0004X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\b0\u0007X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\t\u001a\b\u0012\u0004\u0012\u00020\b0\u0007X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\n\u001a\b\u0012\u0004\u0012\u00020\b0\u000bX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\f\u001a\b\u0012\u0004\u0012\u00020\b0\u000bX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\r\u001a\b\u0012\u0004\u0012\u00020\b0\u000bX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0017\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\u00050\u000f\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0010\u0010\u0011R\u0014\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\b0\u0013X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006$"}, d2 = {"Lcom/shieldguard/ai/service/NetworkTrafficMonitor;", "", "()V", "_state", "Lkotlinx/coroutines/flow/MutableStateFlow;", "Lcom/shieldguard/ai/service/NetworkMonitorState;", "customBlockedHosts", "", "", "customBlockedIps", "defaultUnauthorizedDomains", "", "defaultUnauthorizedIps", "highRiskTlds", "state", "Lkotlinx/coroutines/flow/StateFlow;", "getState", "()Lkotlinx/coroutines/flow/StateFlow;", "suspiciousKeywords", "", "addBlockedRule", "", "hostOrIp", "evaluateDomain", "Lkotlin/Pair;", "", "domain", "getAllBlockedIps", "recordEvent", "event", "Lcom/shieldguard/ai/service/NetworkTrafficEvent;", "removeBlockedRule", "setNetworkWarning", "warning", "setVpnRunning", "running", "app_debug"})
public final class NetworkTrafficMonitor {
    @org.jetbrains.annotations.NotNull()
    private final java.util.Set<java.lang.String> defaultUnauthorizedDomains = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.Set<java.lang.String> highRiskTlds = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> suspiciousKeywords = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.Set<java.lang.String> defaultUnauthorizedIps = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.Set<java.lang.String> customBlockedHosts = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.Set<java.lang.String> customBlockedIps = null;
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.flow.MutableStateFlow<com.shieldguard.ai.service.NetworkMonitorState> _state = null;
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.flow.StateFlow<com.shieldguard.ai.service.NetworkMonitorState> state = null;
    
    @javax.inject.Inject()
    public NetworkTrafficMonitor() {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final kotlinx.coroutines.flow.StateFlow<com.shieldguard.ai.service.NetworkMonitorState> getState() {
        return null;
    }
    
    public final void setVpnRunning(boolean running) {
    }
    
    public final void setNetworkWarning(@org.jetbrains.annotations.Nullable()
    java.lang.String warning) {
    }
    
    public final void addBlockedRule(@org.jetbrains.annotations.NotNull()
    java.lang.String hostOrIp) {
    }
    
    public final void removeBlockedRule(@org.jetbrains.annotations.NotNull()
    java.lang.String hostOrIp) {
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.Set<java.lang.String> getAllBlockedIps() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final kotlin.Pair<java.lang.Boolean, java.lang.String> evaluateDomain(@org.jetbrains.annotations.NotNull()
    java.lang.String domain) {
        return null;
    }
    
    public final void recordEvent(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.service.NetworkTrafficEvent event) {
    }
}