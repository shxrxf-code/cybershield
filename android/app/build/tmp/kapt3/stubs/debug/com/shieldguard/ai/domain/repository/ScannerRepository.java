package com.shieldguard.ai.domain.repository;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000B\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001J\u0014\u0010\u0002\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00050\u00040\u0003H&J\u0016\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u0005H\u00a6@\u00a2\u0006\u0002\u0010\tJ$\u0010\n\u001a\b\u0012\u0004\u0012\u00020\f0\u000b2\u0006\u0010\r\u001a\u00020\fH\u00a6@\u00f8\u0001\u0000\u00f8\u0001\u0001\u00a2\u0006\u0004\b\u000e\u0010\u000fJ$\u0010\u0010\u001a\b\u0012\u0004\u0012\u00020\u00110\u000b2\u0006\u0010\u0012\u001a\u00020\u0013H\u00a6@\u00f8\u0001\u0000\u00f8\u0001\u0001\u00a2\u0006\u0004\b\u0014\u0010\u0015J.\u0010\u0016\u001a\b\u0012\u0004\u0012\u00020\u00110\u000b2\u0006\u0010\u0017\u001a\u00020\u00132\b\b\u0002\u0010\u0018\u001a\u00020\u0019H\u00a6@\u00f8\u0001\u0000\u00f8\u0001\u0001\u00a2\u0006\u0004\b\u001a\u0010\u001b\u0082\u0002\u000b\n\u0002\b!\n\u0005\b\u00a1\u001e0\u0001\u00a8\u0006\u001c"}, d2 = {"Lcom/shieldguard/ai/domain/repository/ScannerRepository;", "", "getScanHistory", "Lkotlinx/coroutines/flow/Flow;", "", "Lcom/shieldguard/ai/domain/model/ScanResult;", "recordScanResult", "", "scanResult", "(Lcom/shieldguard/ai/domain/model/ScanResult;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "scanApk", "Lkotlin/Result;", "Lcom/shieldguard/ai/domain/model/AppThreatInfo;", "packageInfo", "scanApk-gIAlu-s", "(Lcom/shieldguard/ai/domain/model/AppThreatInfo;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "scanDocument", "Lcom/shieldguard/ai/domain/model/Threat;", "filePath", "", "scanDocument-gIAlu-s", "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "scanUrl", "url", "deepAnalysis", "", "scanUrl-0E7RQCE", "(Ljava/lang/String;ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;", "app_debug"})
public abstract interface ScannerRepository {
    
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object recordScanResult(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.ScanResult scanResult, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion);
    
    @org.jetbrains.annotations.NotNull()
    public abstract kotlinx.coroutines.flow.Flow<java.util.List<com.shieldguard.ai.domain.model.ScanResult>> getScanHistory();
    
    @kotlin.Metadata(mv = {1, 9, 0}, k = 3, xi = 48)
    public static final class DefaultImpls {
    }
}