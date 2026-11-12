package com.shieldguard.ai.domain.usecase;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\u0017\b\u0007\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0002\u0010\u0006J\u0012\u0010\u0007\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\n0\t0\bJ\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\f0\bR\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\r"}, d2 = {"Lcom/shieldguard/ai/domain/usecase/GetDashboardSummaryUseCase;", "", "threatRepository", "Lcom/shieldguard/ai/domain/repository/ThreatRepository;", "deviceSecurityRepository", "Lcom/shieldguard/ai/domain/repository/DeviceSecurityRepository;", "(Lcom/shieldguard/ai/domain/repository/ThreatRepository;Lcom/shieldguard/ai/domain/repository/DeviceSecurityRepository;)V", "getRecentThreats", "Lkotlinx/coroutines/flow/Flow;", "", "Lcom/shieldguard/ai/domain/model/Threat;", "getSecurityScore", "Lcom/shieldguard/ai/domain/model/SecurityScore;", "app_debug"})
public final class GetDashboardSummaryUseCase {
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.repository.ThreatRepository threatRepository = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.repository.DeviceSecurityRepository deviceSecurityRepository = null;
    
    @javax.inject.Inject()
    public GetDashboardSummaryUseCase(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.repository.ThreatRepository threatRepository, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.repository.DeviceSecurityRepository deviceSecurityRepository) {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final kotlinx.coroutines.flow.Flow<com.shieldguard.ai.domain.model.SecurityScore> getSecurityScore() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final kotlinx.coroutines.flow.Flow<java.util.List<com.shieldguard.ai.domain.model.Threat>> getRecentThreats() {
        return null;
    }
}