package com.shieldguard.ai.domain.repository;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0002\b\u0002\bf\u0018\u00002\u00020\u0001J\u000e\u0010\u0002\u001a\u00020\u0003H\u00a6@\u00a2\u0006\u0002\u0010\u0004J\u0016\u0010\u0005\u001a\u00020\u00032\u0006\u0010\u0006\u001a\u00020\u0007H\u00a6@\u00a2\u0006\u0002\u0010\bJ\u0014\u0010\t\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\f0\u000b0\nH&J\u001e\u0010\r\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\f0\u000b0\n2\b\b\u0002\u0010\u000e\u001a\u00020\u000fH&J\u0016\u0010\u0010\u001a\u00020\u00032\u0006\u0010\u0011\u001a\u00020\fH\u00a6@\u00a2\u0006\u0002\u0010\u0012J\u0016\u0010\u0013\u001a\u00020\u00032\u0006\u0010\u0014\u001a\u00020\u0015H\u00a6@\u00a2\u0006\u0002\u0010\u0016\u00a8\u0006\u0017"}, d2 = {"Lcom/shieldguard/ai/domain/repository/ThreatRepository;", "", "clearThreats", "", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "clearThreatsByModule", "moduleType", "Lcom/shieldguard/ai/domain/model/ModuleType;", "(Lcom/shieldguard/ai/domain/model/ModuleType;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "getAllThreats", "Lkotlinx/coroutines/flow/Flow;", "", "Lcom/shieldguard/ai/domain/model/Threat;", "getRecentThreats", "limit", "", "recordThreat", "threat", "(Lcom/shieldguard/ai/domain/model/Threat;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "resolveThreat", "threatId", "", "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "app_debug"})
public abstract interface ThreatRepository {
    
    @org.jetbrains.annotations.NotNull()
    public abstract kotlinx.coroutines.flow.Flow<java.util.List<com.shieldguard.ai.domain.model.Threat>> getAllThreats();
    
    @org.jetbrains.annotations.NotNull()
    public abstract kotlinx.coroutines.flow.Flow<java.util.List<com.shieldguard.ai.domain.model.Threat>> getRecentThreats(int limit);
    
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object recordThreat(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.Threat threat, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion);
    
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object resolveThreat(@org.jetbrains.annotations.NotNull()
    java.lang.String threatId, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion);
    
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object clearThreatsByModule(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.ModuleType moduleType, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion);
    
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object clearThreats(@org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion);
    
    @kotlin.Metadata(mv = {1, 9, 0}, k = 3, xi = 48)
    public static final class DefaultImpls {
    }
}