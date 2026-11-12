package com.shieldguard.ai.scanner;

@javax.inject.Singleton()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000b\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\"\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\b\u0007\u0018\u00002\u00020\u0001B\u0019\b\u0007\u0012\b\b\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0002\u0010\u0006J\u0006\u0010\n\u001a\u00020\u000bJS\u0010\f\u001a\u00020\r2K\u0010\u000e\u001aG\u0012\u0013\u0012\u00110\u0010\u00a2\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(\u0013\u0012\u0013\u0012\u00110\u0010\u00a2\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(\u0014\u0012\u0013\u0012\u00110\t\u00a2\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(\u0015\u0012\u0004\u0012\u00020\u00160\u000fJf\u0010\u0017\u001a\u00020\u00162\u0016\u0010\u0018\u001a\u0012\u0012\u0004\u0012\u00020\t0\u0019j\b\u0012\u0004\u0012\u00020\t`\u001a2\f\u0010\u001b\u001a\b\u0012\u0004\u0012\u00020\u001d0\u001c26\u0010\u001e\u001a2\u0012\u0013\u0012\u00110\u0010\u00a2\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b( \u0012\u0013\u0012\u00110\t\u00a2\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(!\u0012\u0004\u0012\u00020\u00160\u001fH\u0002R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\t0\bX\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\""}, d2 = {"Lcom/shieldguard/ai/scanner/FullDeviceFileScanner;", "", "context", "Landroid/content/Context;", "documentSecurityScanner", "Lcom/shieldguard/ai/scanner/DocumentSecurityScanner;", "(Landroid/content/Context;Lcom/shieldguard/ai/scanner/DocumentSecurityScanner;)V", "inspectableExtensions", "", "", "hasAllFilesAccess", "", "scanEntireDeviceStorage", "Lcom/shieldguard/ai/scanner/FullFileScanSummary;", "onProgress", "Lkotlin/Function3;", "", "Lkotlin/ParameterName;", "name", "filesScanned", "threatsFound", "currentPath", "", "scanViaMediaStore", "visitedPaths", "Ljava/util/HashSet;", "Lkotlin/collections/HashSet;", "threats", "", "Lcom/shieldguard/ai/domain/model/Threat;", "onBatchProgress", "Lkotlin/Function2;", "addedCount", "lastName", "app_debug"})
public final class FullDeviceFileScanner {
    @org.jetbrains.annotations.NotNull()
    private final android.content.Context context = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.scanner.DocumentSecurityScanner documentSecurityScanner = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.Set<java.lang.String> inspectableExtensions = null;
    
    @javax.inject.Inject()
    public FullDeviceFileScanner(@dagger.hilt.android.qualifiers.ApplicationContext()
    @org.jetbrains.annotations.NotNull()
    android.content.Context context, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.scanner.DocumentSecurityScanner documentSecurityScanner) {
        super();
    }
    
    public final boolean hasAllFilesAccess() {
        return false;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.scanner.FullFileScanSummary scanEntireDeviceStorage(@org.jetbrains.annotations.NotNull()
    kotlin.jvm.functions.Function3<? super java.lang.Integer, ? super java.lang.Integer, ? super java.lang.String, kotlin.Unit> onProgress) {
        return null;
    }
    
    private final void scanViaMediaStore(java.util.HashSet<java.lang.String> visitedPaths, java.util.List<com.shieldguard.ai.domain.model.Threat> threats, kotlin.jvm.functions.Function2<? super java.lang.Integer, ? super java.lang.String, kotlin.Unit> onBatchProgress) {
    }
}