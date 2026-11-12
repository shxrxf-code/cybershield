package com.shieldguard.ai.domain.usecase;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\'\b\u0007\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u0012\u0006\u0010\b\u001a\u00020\t\u00a2\u0006\u0002\u0010\nJ0\u0010\u000b\u001a\u0004\u0018\u00010\f2\u0006\u0010\r\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\u0010\u001a\u00020\u000e2\u0006\u0010\u0011\u001a\u00020\u000eH\u0086B\u00a2\u0006\u0002\u0010\u0012R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\tX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u0013"}, d2 = {"Lcom/shieldguard/ai/domain/usecase/ProcessNotificationUseCase;", "", "threatRepository", "Lcom/shieldguard/ai/domain/repository/ThreatRepository;", "scanUrlUseCase", "Lcom/shieldguard/ai/domain/usecase/ScanUrlUseCase;", "localUrlThreatAnalyzer", "Lcom/shieldguard/ai/scanner/LocalUrlThreatAnalyzer;", "notificationMonitorHub", "Lcom/shieldguard/ai/service/NotificationMonitorHub;", "(Lcom/shieldguard/ai/domain/repository/ThreatRepository;Lcom/shieldguard/ai/domain/usecase/ScanUrlUseCase;Lcom/shieldguard/ai/scanner/LocalUrlThreatAnalyzer;Lcom/shieldguard/ai/service/NotificationMonitorHub;)V", "invoke", "Lcom/shieldguard/ai/domain/model/Threat;", "packageName", "", "appLabel", "title", "text", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "app_debug"})
public final class ProcessNotificationUseCase {
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.repository.ThreatRepository threatRepository = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.usecase.ScanUrlUseCase scanUrlUseCase = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.scanner.LocalUrlThreatAnalyzer localUrlThreatAnalyzer = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.service.NotificationMonitorHub notificationMonitorHub = null;
    
    @javax.inject.Inject()
    public ProcessNotificationUseCase(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.repository.ThreatRepository threatRepository, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.usecase.ScanUrlUseCase scanUrlUseCase, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.scanner.LocalUrlThreatAnalyzer localUrlThreatAnalyzer, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.service.NotificationMonitorHub notificationMonitorHub) {
        super();
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.Object invoke(@org.jetbrains.annotations.NotNull()
    java.lang.String packageName, @org.jetbrains.annotations.NotNull()
    java.lang.String appLabel, @org.jetbrains.annotations.NotNull()
    java.lang.String title, @org.jetbrains.annotations.NotNull()
    java.lang.String text, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super com.shieldguard.ai.domain.model.Threat> $completion) {
        return null;
    }
}