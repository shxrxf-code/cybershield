package com.shieldguard.ai.data.repository;

@javax.inject.Singleton()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000B\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0007\u0018\u00002\u00020\u0001B\u000f\b\u0007\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0002\u0010\u0004J\u000e\u0010\u0005\u001a\u00020\u0006H\u0096@\u00a2\u0006\u0002\u0010\u0007J\u0016\u0010\b\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\nH\u0096@\u00a2\u0006\u0002\u0010\u000bJ\u0014\u0010\f\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u000f0\u000e0\rH\u0016J\u001c\u0010\u0010\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u000f0\u000e0\r2\u0006\u0010\u0011\u001a\u00020\u0012H\u0016J\u0016\u0010\u0013\u001a\u00020\u00062\u0006\u0010\u0014\u001a\u00020\u000fH\u0096@\u00a2\u0006\u0002\u0010\u0015J\u0016\u0010\u0016\u001a\u00020\u00062\u0006\u0010\u0017\u001a\u00020\u0018H\u0096@\u00a2\u0006\u0002\u0010\u0019R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u001a"}, d2 = {"Lcom/shieldguard/ai/data/repository/ThreatRepositoryImpl;", "Lcom/shieldguard/ai/domain/repository/ThreatRepository;", "threatDao", "Lcom/shieldguard/ai/data/local/dao/ThreatDao;", "(Lcom/shieldguard/ai/data/local/dao/ThreatDao;)V", "clearThreats", "", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "clearThreatsByModule", "moduleType", "Lcom/shieldguard/ai/domain/model/ModuleType;", "(Lcom/shieldguard/ai/domain/model/ModuleType;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "getAllThreats", "Lkotlinx/coroutines/flow/Flow;", "", "Lcom/shieldguard/ai/domain/model/Threat;", "getRecentThreats", "limit", "", "recordThreat", "threat", "(Lcom/shieldguard/ai/domain/model/Threat;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "resolveThreat", "threatId", "", "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "app_debug"})
public final class ThreatRepositoryImpl implements com.shieldguard.ai.domain.repository.ThreatRepository {
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.data.local.dao.ThreatDao threatDao = null;
    
    @javax.inject.Inject()
    public ThreatRepositoryImpl(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.local.dao.ThreatDao threatDao) {
        super();
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.NotNull()
    public kotlinx.coroutines.flow.Flow<java.util.List<com.shieldguard.ai.domain.model.Threat>> getAllThreats() {
        return null;
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.NotNull()
    public kotlinx.coroutines.flow.Flow<java.util.List<com.shieldguard.ai.domain.model.Threat>> getRecentThreats(int limit) {
        return null;
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.Nullable()
    public java.lang.Object recordThreat(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.Threat threat, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion) {
        return null;
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.Nullable()
    public java.lang.Object resolveThreat(@org.jetbrains.annotations.NotNull()
    java.lang.String threatId, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion) {
        return null;
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.Nullable()
    public java.lang.Object clearThreatsByModule(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.ModuleType moduleType, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion) {
        return null;
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.Nullable()
    public java.lang.Object clearThreats(@org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion) {
        return null;
    }
}