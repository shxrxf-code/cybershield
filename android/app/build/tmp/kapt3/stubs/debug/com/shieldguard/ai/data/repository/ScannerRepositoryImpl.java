package com.shieldguard.ai.data.repository;

@javax.inject.Singleton()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\u0003\b\u0007\u0018\u00002\u00020\u0001B/\b\u0007\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u0012\u0006\u0010\b\u001a\u00020\t\u0012\u0006\u0010\n\u001a\u00020\u000b\u00a2\u0006\u0002\u0010\fJ\u0014\u0010\r\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00100\u000f0\u000eH\u0016J\u0016\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u0010H\u0096@\u00a2\u0006\u0002\u0010\u0014J$\u0010\u0015\u001a\b\u0012\u0004\u0012\u00020\u00170\u00162\u0006\u0010\u0018\u001a\u00020\u0017H\u0096@\u00f8\u0001\u0000\u00f8\u0001\u0001\u00a2\u0006\u0004\b\u0019\u0010\u001aJ$\u0010\u001b\u001a\b\u0012\u0004\u0012\u00020\u001c0\u00162\u0006\u0010\u001d\u001a\u00020\u001eH\u0096@\u00f8\u0001\u0000\u00f8\u0001\u0001\u00a2\u0006\u0004\b\u001f\u0010 J,\u0010!\u001a\b\u0012\u0004\u0012\u00020\u001c0\u00162\u0006\u0010\"\u001a\u00020\u001e2\u0006\u0010#\u001a\u00020$H\u0096@\u00f8\u0001\u0000\u00f8\u0001\u0001\u00a2\u0006\u0004\b%\u0010&R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u000bX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\tX\u0082\u0004\u00a2\u0006\u0002\n\u0000\u0082\u0002\u000b\n\u0002\b!\n\u0005\b\u00a1\u001e0\u0001\u00a8\u0006\'"}, d2 = {"Lcom/shieldguard/ai/data/repository/ScannerRepositoryImpl;", "Lcom/shieldguard/ai/domain/repository/ScannerRepository;", "apiService", "Lcom/shieldguard/ai/data/remote/api/ShieldGuardApiService;", "documentSecurityScanner", "Lcom/shieldguard/ai/scanner/DocumentSecurityScanner;", "localUrlThreatAnalyzer", "Lcom/shieldguard/ai/scanner/LocalUrlThreatAnalyzer;", "scanHistoryDao", "Lcom/shieldguard/ai/data/local/dao/ScanHistoryDao;", "preferencesManager", "Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;", "(Lcom/shieldguard/ai/data/remote/api/ShieldGuardApiService;Lcom/shieldguard/ai/scanner/DocumentSecurityScanner;Lcom/shieldguard/ai/scanner/LocalUrlThreatAnalyzer;Lcom/shieldguard/ai/data/local/dao/ScanHistoryDao;Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;)V", "getScanHistory", "Lkotlinx/coroutines/flow/Flow;", "", "Lcom/shieldguard/ai/domain/model/ScanResult;", "recordScanResult", "", "scanResult", "(Lcom/shieldguard/ai/domain/model/ScanResult;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "scanApk", "Lkotlin/Result;", "Lcom/shieldguard/ai/domain/model/AppThreatInfo;", "packageInfo", "scanApk-gIAlu-s", "(Lcom/shieldguard/ai/domain/model/AppThreatInfo;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "scanDocument", "Lcom/shieldguard/ai/domain/model/Threat;", "filePath", "", "scanDocument-gIAlu-s", "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "scanUrl", "url", "deepAnalysis", "", "scanUrl-0E7RQCE", "(Ljava/lang/String;ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;", "app_debug"})
public final class ScannerRepositoryImpl implements com.shieldguard.ai.domain.repository.ScannerRepository {
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.data.remote.api.ShieldGuardApiService apiService = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.scanner.DocumentSecurityScanner documentSecurityScanner = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.scanner.LocalUrlThreatAnalyzer localUrlThreatAnalyzer = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.data.local.dao.ScanHistoryDao scanHistoryDao = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.data.local.EncryptedPreferencesManager preferencesManager = null;
    
    @javax.inject.Inject()
    public ScannerRepositoryImpl(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.remote.api.ShieldGuardApiService apiService, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.scanner.DocumentSecurityScanner documentSecurityScanner, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.scanner.LocalUrlThreatAnalyzer localUrlThreatAnalyzer, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.local.dao.ScanHistoryDao scanHistoryDao, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.local.EncryptedPreferencesManager preferencesManager) {
        super();
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.Nullable()
    public java.lang.Object recordScanResult(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.ScanResult scanResult, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion) {
        return null;
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.NotNull()
    public kotlinx.coroutines.flow.Flow<java.util.List<com.shieldguard.ai.domain.model.ScanResult>> getScanHistory() {
        return null;
    }
}