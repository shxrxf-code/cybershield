package com.shieldguard.ai.data.repository;

@javax.inject.Singleton()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000H\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\b\b\u0007\u0018\u00002\u00020\u0001B\u001f\b\u0007\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u00a2\u0006\u0002\u0010\bJ\u000e\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000e0\rH\u0016J\u000e\u0010\u000f\u001a\u00020\u0010H\u0096@\u00a2\u0006\u0002\u0010\u0011J\u001e\u0010\u0012\u001a\u00020\u00132\u0006\u0010\u0014\u001a\u00020\u00152\u0006\u0010\u0016\u001a\u00020\u0015H\u0096@\u00a2\u0006\u0002\u0010\u0017J&\u0010\u0018\u001a\u00020\u00132\u0006\u0010\u0019\u001a\u00020\u000b2\u0006\u0010\u001a\u001a\u00020\u000b2\u0006\u0010\u001b\u001a\u00020\u000bH\u0096@\u00a2\u0006\u0002\u0010\u001cR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\t\u001a\b\u0012\u0004\u0012\u00020\u000b0\nX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u001d"}, d2 = {"Lcom/shieldguard/ai/data/repository/DeviceSecurityRepositoryImpl;", "Lcom/shieldguard/ai/domain/repository/DeviceSecurityRepository;", "auditor", "Lcom/shieldguard/ai/scanner/DeviceIntegrityAuditor;", "threatDao", "Lcom/shieldguard/ai/data/local/dao/ThreatDao;", "preferencesManager", "Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;", "(Lcom/shieldguard/ai/scanner/DeviceIntegrityAuditor;Lcom/shieldguard/ai/data/local/dao/ThreatDao;Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;)V", "refreshTrigger", "Lkotlinx/coroutines/flow/MutableStateFlow;", "", "getSecurityScore", "Lkotlinx/coroutines/flow/Flow;", "Lcom/shieldguard/ai/domain/model/SecurityScore;", "performDeviceAudit", "Lcom/shieldguard/ai/domain/model/DeviceAudit;", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "updateProtectionStatus", "", "vpnEnabled", "", "notifEnabled", "(ZZLkotlin/coroutines/Continuation;)Ljava/lang/Object;", "updateScanMetrics", "appsCount", "filesCount", "securityScore", "(IIILkotlin/coroutines/Continuation;)Ljava/lang/Object;", "app_debug"})
public final class DeviceSecurityRepositoryImpl implements com.shieldguard.ai.domain.repository.DeviceSecurityRepository {
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.scanner.DeviceIntegrityAuditor auditor = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.data.local.dao.ThreatDao threatDao = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.data.local.EncryptedPreferencesManager preferencesManager = null;
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.flow.MutableStateFlow<java.lang.Integer> refreshTrigger = null;
    
    @javax.inject.Inject()
    public DeviceSecurityRepositoryImpl(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.scanner.DeviceIntegrityAuditor auditor, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.local.dao.ThreatDao threatDao, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.local.EncryptedPreferencesManager preferencesManager) {
        super();
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.Nullable()
    public java.lang.Object performDeviceAudit(@org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super com.shieldguard.ai.domain.model.DeviceAudit> $completion) {
        return null;
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.NotNull()
    public kotlinx.coroutines.flow.Flow<com.shieldguard.ai.domain.model.SecurityScore> getSecurityScore() {
        return null;
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.Nullable()
    public java.lang.Object updateProtectionStatus(boolean vpnEnabled, boolean notifEnabled, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion) {
        return null;
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.Nullable()
    public java.lang.Object updateScanMetrics(int appsCount, int filesCount, int securityScore, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion) {
        return null;
    }
}