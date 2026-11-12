package com.shieldguard.ai.service;

@dagger.hilt.android.AndroidEntryPoint()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000r\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\"\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0012\n\u0002\b\f\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\u000b\b\u0007\u0018\u0000 N2\u00020\u0001:\u0001NB\u0005\u00a2\u0006\u0002\u0010\u0002J\"\u0010!\u001a\u0004\u0018\u00010\"2\u0006\u0010#\u001a\u00020\"2\u0006\u0010$\u001a\u00020\u00072\u0006\u0010%\u001a\u00020\u0007H\u0002J \u0010&\u001a\u00020\"2\u0006\u0010\'\u001a\u00020\"2\u0006\u0010(\u001a\u00020\u00072\u0006\u0010)\u001a\u00020\"H\u0002J \u0010*\u001a\u00020\u00072\u0006\u0010+\u001a\u00020\"2\u0006\u0010,\u001a\u00020\u00072\u0006\u0010-\u001a\u00020\u0007H\u0002J\b\u0010.\u001a\u00020/H\u0002J \u00100\u001a\u0002012\u0006\u0010#\u001a\u00020\"2\u0006\u0010$\u001a\u00020\u00072\u0006\u0010%\u001a\u00020\u0007H\u0002J\u001a\u00102\u001a\u0004\u0018\u00010\"2\u0006\u00103\u001a\u00020\"2\u0006\u00104\u001a\u000201H\u0002J \u00105\u001a\u0002062\u0006\u0010#\u001a\u00020\"2\u0006\u0010-\u001a\u00020\u00072\u0006\u00107\u001a\u000208H\u0002J\b\u00109\u001a\u000206H\u0002J\b\u0010:\u001a\u000206H\u0002J(\u0010;\u001a\u0002062\u0006\u0010<\u001a\u0002012\u0006\u0010=\u001a\u0002012\u0006\u0010>\u001a\u0002012\u0006\u0010?\u001a\u000201H\u0002J\b\u0010@\u001a\u000206H\u0016J\b\u0010A\u001a\u000206H\u0016J\"\u0010B\u001a\u00020\u00072\b\u0010C\u001a\u0004\u0018\u00010D2\u0006\u0010E\u001a\u00020\u00072\u0006\u0010F\u001a\u00020\u0007H\u0016J>\u0010G\u001a\u0002062\u0006\u0010\'\u001a\u00020\"2\u0006\u0010(\u001a\u00020\u00072\u0006\u0010$\u001a\u00020\u00072\u0006\u0010%\u001a\u00020\u00072\u0006\u0010H\u001a\u0002012\u0006\u00107\u001a\u000208H\u0082@\u00a2\u0006\u0002\u0010IJ\b\u0010J\u001a\u000206H\u0002J\b\u0010K\u001a\u000206H\u0002J\b\u0010L\u001a\u000206H\u0002J\b\u0010M\u001a\u000206H\u0002R\u0010\u0010\u0003\u001a\u0004\u0018\u00010\u0004X\u0082\u000e\u00a2\u0006\u0002\n\u0000R\u0014\u0010\u0005\u001a\b\u0012\u0004\u0012\u00020\u00070\u0006X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\tX\u0082\u000e\u00a2\u0006\u0002\n\u0000R\u001e\u0010\n\u001a\u00020\u000b8\u0006@\u0006X\u0087.\u00a2\u0006\u000e\n\u0000\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000fR\u001e\u0010\u0010\u001a\u00020\u00118\u0006@\u0006X\u0087.\u00a2\u0006\u000e\n\u0000\u001a\u0004\b\u0012\u0010\u0013\"\u0004\b\u0014\u0010\u0015R\u001e\u0010\u0016\u001a\u00020\u00178\u0006@\u0006X\u0087.\u00a2\u0006\u000e\n\u0000\u001a\u0004\b\u0018\u0010\u0019\"\u0004\b\u001a\u0010\u001bR\u0010\u0010\u001c\u001a\u0004\u0018\u00010\u0004X\u0082\u000e\u00a2\u0006\u0002\n\u0000R\u0010\u0010\u001d\u001a\u0004\u0018\u00010\u001eX\u0082\u000e\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u001f\u001a\u00020 X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006O"}, d2 = {"Lcom/shieldguard/ai/service/ShieldGuardVpnService;", "Landroid/net/VpnService;", "()V", "auditJob", "Lkotlinx/coroutines/Job;", "highRiskPorts", "", "", "isRunning", "", "networkTrafficMonitor", "Lcom/shieldguard/ai/service/NetworkTrafficMonitor;", "getNetworkTrafficMonitor", "()Lcom/shieldguard/ai/service/NetworkTrafficMonitor;", "setNetworkTrafficMonitor", "(Lcom/shieldguard/ai/service/NetworkTrafficMonitor;)V", "preferencesManager", "Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;", "getPreferencesManager", "()Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;", "setPreferencesManager", "(Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;)V", "threatRepository", "Lcom/shieldguard/ai/domain/repository/ThreatRepository;", "getThreatRepository", "()Lcom/shieldguard/ai/domain/repository/ThreatRepository;", "setThreatRepository", "(Lcom/shieldguard/ai/domain/repository/ThreatRepository;)V", "tunnelJob", "vpnInterface", "Landroid/os/ParcelFileDescriptor;", "vpnScope", "Lkotlinx/coroutines/CoroutineScope;", "buildDnsNxDomainResponse", "", "packet", "dnsOffset", "dnsLength", "buildUdpIpResponse", "requestPacket", "ihl", "dnsPayload", "computeChecksum", "buf", "offset", "length", "createStatusNotification", "Landroid/app/Notification;", "extractDnsDomainName", "", "forwardDnsOverProtectedSocket", "query", "dnsServer", "handleOutboundIpPacket", "", "outStream", "Ljava/io/FileOutputStream;", "inspectActiveNetworkPosture", "inspectActiveSockets", "logAndRecordBlock", "destination", "direction", "protocol", "reason", "onDestroy", "onRevoke", "onStartCommand", "intent", "Landroid/content/Intent;", "flags", "startId", "processDnsQuery", "domain", "([BIIILjava/lang/String;Ljava/io/FileOutputStream;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "restartTunnel", "startNetworkAuditor", "startVpnTunnel", "stopVpn", "Companion", "app_debug"})
public final class ShieldGuardVpnService extends android.net.VpnService {
    @javax.inject.Inject()
    public com.shieldguard.ai.service.NetworkTrafficMonitor networkTrafficMonitor;
    @javax.inject.Inject()
    public com.shieldguard.ai.domain.repository.ThreatRepository threatRepository;
    @javax.inject.Inject()
    public com.shieldguard.ai.data.local.EncryptedPreferencesManager preferencesManager;
    @org.jetbrains.annotations.Nullable()
    private android.os.ParcelFileDescriptor vpnInterface;
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.CoroutineScope vpnScope = null;
    @org.jetbrains.annotations.Nullable()
    private kotlinx.coroutines.Job tunnelJob;
    @org.jetbrains.annotations.Nullable()
    private kotlinx.coroutines.Job auditJob;
    @kotlin.jvm.Volatile()
    private volatile boolean isRunning = false;
    @org.jetbrains.annotations.NotNull()
    private final java.util.Set<java.lang.Integer> highRiskPorts = null;
    @org.jetbrains.annotations.NotNull()
    public static final java.lang.String ACTION_START = "com.shieldguard.ai.VPN_START";
    @org.jetbrains.annotations.NotNull()
    public static final java.lang.String ACTION_STOP = "com.shieldguard.ai.VPN_STOP";
    @org.jetbrains.annotations.NotNull()
    public static final java.lang.String ACTION_RELOAD = "com.shieldguard.ai.VPN_RELOAD";
    @org.jetbrains.annotations.NotNull()
    private static final java.lang.String VPN_ADDRESS = "10.10.0.2";
    @org.jetbrains.annotations.NotNull()
    private static final java.lang.String VPN_DNS_LOCAL = "10.10.0.1";
    @org.jetbrains.annotations.NotNull()
    private static final java.lang.String UPSTREAM_DNS_PRIMARY = "1.1.1.2";
    @org.jetbrains.annotations.NotNull()
    private static final java.lang.String UPSTREAM_DNS_SECONDARY = "9.9.9.9";
    @org.jetbrains.annotations.NotNull()
    public static final com.shieldguard.ai.service.ShieldGuardVpnService.Companion Companion = null;
    
    public ShieldGuardVpnService() {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.service.NetworkTrafficMonitor getNetworkTrafficMonitor() {
        return null;
    }
    
    public final void setNetworkTrafficMonitor(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.service.NetworkTrafficMonitor p0) {
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.repository.ThreatRepository getThreatRepository() {
        return null;
    }
    
    public final void setThreatRepository(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.repository.ThreatRepository p0) {
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.data.local.EncryptedPreferencesManager getPreferencesManager() {
        return null;
    }
    
    public final void setPreferencesManager(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.local.EncryptedPreferencesManager p0) {
    }
    
    @java.lang.Override()
    public int onStartCommand(@org.jetbrains.annotations.Nullable()
    android.content.Intent intent, int flags, int startId) {
        return 0;
    }
    
    private final void restartTunnel() {
    }
    
    private final void startVpnTunnel() {
    }
    
    private final void handleOutboundIpPacket(byte[] packet, int length, java.io.FileOutputStream outStream) {
    }
    
    private final java.lang.Object processDnsQuery(byte[] requestPacket, int ihl, int dnsOffset, int dnsLength, java.lang.String domain, java.io.FileOutputStream outStream, kotlin.coroutines.Continuation<? super kotlin.Unit> $completion) {
        return null;
    }
    
    private final byte[] forwardDnsOverProtectedSocket(byte[] query, java.lang.String dnsServer) {
        return null;
    }
    
    private final void startNetworkAuditor() {
    }
    
    private final void inspectActiveNetworkPosture() {
    }
    
    private final void inspectActiveSockets() {
    }
    
    private final void logAndRecordBlock(java.lang.String destination, java.lang.String direction, java.lang.String protocol, java.lang.String reason) {
    }
    
    private final java.lang.String extractDnsDomainName(byte[] packet, int dnsOffset, int dnsLength) {
        return null;
    }
    
    private final byte[] buildDnsNxDomainResponse(byte[] packet, int dnsOffset, int dnsLength) {
        return null;
    }
    
    private final byte[] buildUdpIpResponse(byte[] requestPacket, int ihl, byte[] dnsPayload) {
        return null;
    }
    
    private final int computeChecksum(byte[] buf, int offset, int length) {
        return 0;
    }
    
    private final android.app.Notification createStatusNotification() {
        return null;
    }
    
    private final void stopVpn() {
    }
    
    @java.lang.Override()
    public void onRevoke() {
    }
    
    @java.lang.Override()
    public void onDestroy() {
    }
    
    @kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002\u00a2\u0006\u0002\u0010\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0086T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0004X\u0086T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0004X\u0086T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u000b"}, d2 = {"Lcom/shieldguard/ai/service/ShieldGuardVpnService$Companion;", "", "()V", "ACTION_RELOAD", "", "ACTION_START", "ACTION_STOP", "UPSTREAM_DNS_PRIMARY", "UPSTREAM_DNS_SECONDARY", "VPN_ADDRESS", "VPN_DNS_LOCAL", "app_debug"})
    public static final class Companion {
        
        private Companion() {
            super();
        }
    }
}