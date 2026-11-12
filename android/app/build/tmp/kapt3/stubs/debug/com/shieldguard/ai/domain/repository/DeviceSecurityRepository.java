package com.shieldguard.ai.domain.repository;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0004\bf\u0018\u00002\u00020\u0001J\u000e\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003H&J\u000e\u0010\u0005\u001a\u00020\u0006H\u00a6@\u00a2\u0006\u0002\u0010\u0007J\u001e\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\u000bH\u00a6@\u00a2\u0006\u0002\u0010\rJ&\u0010\u000e\u001a\u00020\t2\u0006\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0012\u001a\u00020\u0010H\u00a6@\u00a2\u0006\u0002\u0010\u0013\u00a8\u0006\u0014"}, d2 = {"Lcom/shieldguard/ai/domain/repository/DeviceSecurityRepository;", "", "getSecurityScore", "Lkotlinx/coroutines/flow/Flow;", "Lcom/shieldguard/ai/domain/model/SecurityScore;", "performDeviceAudit", "Lcom/shieldguard/ai/domain/model/DeviceAudit;", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "updateProtectionStatus", "", "vpnEnabled", "", "notifEnabled", "(ZZLkotlin/coroutines/Continuation;)Ljava/lang/Object;", "updateScanMetrics", "appsCount", "", "filesCount", "securityScore", "(IIILkotlin/coroutines/Continuation;)Ljava/lang/Object;", "app_debug"})
public abstract interface DeviceSecurityRepository {
    
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object performDeviceAudit(@org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super com.shieldguard.ai.domain.model.DeviceAudit> $completion);
    
    @org.jetbrains.annotations.NotNull()
    public abstract kotlinx.coroutines.flow.Flow<com.shieldguard.ai.domain.model.SecurityScore> getSecurityScore();
    
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object updateProtectionStatus(boolean vpnEnabled, boolean notifEnabled, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion);
    
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object updateScanMetrics(int appsCount, int filesCount, int securityScore, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion);
}