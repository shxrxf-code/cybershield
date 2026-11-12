package com.shieldguard.ai.domain.usecase;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\u0018\u00002\u00020\u0001B\u0017\b\u0007\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0002\u0010\u0006J$\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\t0\b2\u0006\u0010\n\u001a\u00020\u000bH\u0086B\u00f8\u0001\u0000\u00f8\u0001\u0001\u00a2\u0006\u0004\b\f\u0010\rR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u0082\u0002\u000b\n\u0002\b!\n\u0005\b\u00a1\u001e0\u0001\u00a8\u0006\u000e"}, d2 = {"Lcom/shieldguard/ai/domain/usecase/ScanUrlUseCase;", "", "scannerRepository", "Lcom/shieldguard/ai/domain/repository/ScannerRepository;", "threatRepository", "Lcom/shieldguard/ai/domain/repository/ThreatRepository;", "(Lcom/shieldguard/ai/domain/repository/ScannerRepository;Lcom/shieldguard/ai/domain/repository/ThreatRepository;)V", "invoke", "Lkotlin/Result;", "Lcom/shieldguard/ai/domain/model/Threat;", "url", "", "invoke-gIAlu-s", "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "app_debug"})
public final class ScanUrlUseCase {
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.repository.ScannerRepository scannerRepository = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.repository.ThreatRepository threatRepository = null;
    
    @javax.inject.Inject()
    public ScanUrlUseCase(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.repository.ScannerRepository scannerRepository, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.repository.ThreatRepository threatRepository) {
        super();
    }
}