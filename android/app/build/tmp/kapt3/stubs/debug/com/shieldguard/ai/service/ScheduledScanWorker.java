package com.shieldguard.ai.service;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0007\u0018\u00002\u00020\u0001B;\b\u0007\u0012\b\b\u0001\u0010\u0002\u001a\u00020\u0003\u0012\b\b\u0001\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u0012\u0006\u0010\b\u001a\u00020\t\u0012\u0006\u0010\n\u001a\u00020\u000b\u0012\u0006\u0010\f\u001a\u00020\r\u00a2\u0006\u0002\u0010\u000eJ\u000e\u0010\u000f\u001a\u00020\u0010H\u0096@\u00a2\u0006\u0002\u0010\u0011R\u000e\u0010\b\u001a\u00020\tX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\f\u001a\u00020\rX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u000bX\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u0012"}, d2 = {"Lcom/shieldguard/ai/service/ScheduledScanWorker;", "Landroidx/work/CoroutineWorker;", "appContext", "Landroid/content/Context;", "workerParams", "Landroidx/work/WorkerParameters;", "deviceIntegrityAuditor", "Lcom/shieldguard/ai/scanner/DeviceIntegrityAuditor;", "apkStaticScanner", "Lcom/shieldguard/ai/scanner/ApkStaticScanner;", "scannerRepository", "Lcom/shieldguard/ai/domain/repository/ScannerRepository;", "preferencesManager", "Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;", "(Landroid/content/Context;Landroidx/work/WorkerParameters;Lcom/shieldguard/ai/scanner/DeviceIntegrityAuditor;Lcom/shieldguard/ai/scanner/ApkStaticScanner;Lcom/shieldguard/ai/domain/repository/ScannerRepository;Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;)V", "doWork", "Landroidx/work/ListenableWorker$Result;", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "app_debug"})
@androidx.hilt.work.HiltWorker()
public final class ScheduledScanWorker extends androidx.work.CoroutineWorker {
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.scanner.DeviceIntegrityAuditor deviceIntegrityAuditor = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.scanner.ApkStaticScanner apkStaticScanner = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.repository.ScannerRepository scannerRepository = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.data.local.EncryptedPreferencesManager preferencesManager = null;
    
    @dagger.assisted.AssistedInject()
    public ScheduledScanWorker(@dagger.assisted.Assisted()
    @org.jetbrains.annotations.NotNull()
    android.content.Context appContext, @dagger.assisted.Assisted()
    @org.jetbrains.annotations.NotNull()
    androidx.work.WorkerParameters workerParams, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.scanner.DeviceIntegrityAuditor deviceIntegrityAuditor, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.scanner.ApkStaticScanner apkStaticScanner, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.repository.ScannerRepository scannerRepository, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.local.EncryptedPreferencesManager preferencesManager) {
        super(null, null);
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.Nullable()
    public java.lang.Object doWork(@org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super androidx.work.ListenableWorker.Result> $completion) {
        return null;
    }
}