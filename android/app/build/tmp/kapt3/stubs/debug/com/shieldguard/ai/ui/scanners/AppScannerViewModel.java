package com.shieldguard.ai.ui.scanners;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\u001f\b\u0007\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u00a2\u0006\u0002\u0010\bJ\u0006\u0010\u0010\u001a\u00020\u0011J\u0006\u0010\u0012\u001a\u00020\u0011J\u000e\u0010\u0013\u001a\u00020\u00112\u0006\u0010\u0014\u001a\u00020\u0015R\u0014\u0010\t\u001a\b\u0012\u0004\u0012\u00020\u000b0\nX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0017\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000b0\r\u00a2\u0006\b\n\u0000\u001a\u0004\b\u000e\u0010\u000f\u00a8\u0006\u0016"}, d2 = {"Lcom/shieldguard/ai/ui/scanners/AppScannerViewModel;", "Landroidx/lifecycle/ViewModel;", "apkStaticScanner", "Lcom/shieldguard/ai/scanner/ApkStaticScanner;", "scanApkUseCase", "Lcom/shieldguard/ai/domain/usecase/ScanApkUseCase;", "threatRepository", "Lcom/shieldguard/ai/domain/repository/ThreatRepository;", "(Lcom/shieldguard/ai/scanner/ApkStaticScanner;Lcom/shieldguard/ai/domain/usecase/ScanApkUseCase;Lcom/shieldguard/ai/domain/repository/ThreatRepository;)V", "_uiState", "Lkotlinx/coroutines/flow/MutableStateFlow;", "Lcom/shieldguard/ai/ui/scanners/AppScannerUiState;", "uiState", "Lkotlinx/coroutines/flow/StateFlow;", "getUiState", "()Lkotlinx/coroutines/flow/StateFlow;", "scanAllWithAndroguard", "", "scanInstalledApplications", "scanSingleAppWithAndroguard", "packageName", "", "app_debug"})
@dagger.hilt.android.lifecycle.HiltViewModel()
public final class AppScannerViewModel extends androidx.lifecycle.ViewModel {
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.scanner.ApkStaticScanner apkStaticScanner = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.usecase.ScanApkUseCase scanApkUseCase = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.repository.ThreatRepository threatRepository = null;
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.flow.MutableStateFlow<com.shieldguard.ai.ui.scanners.AppScannerUiState> _uiState = null;
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.flow.StateFlow<com.shieldguard.ai.ui.scanners.AppScannerUiState> uiState = null;
    
    @javax.inject.Inject()
    public AppScannerViewModel(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.scanner.ApkStaticScanner apkStaticScanner, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.usecase.ScanApkUseCase scanApkUseCase, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.repository.ThreatRepository threatRepository) {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final kotlinx.coroutines.flow.StateFlow<com.shieldguard.ai.ui.scanners.AppScannerUiState> getUiState() {
        return null;
    }
    
    public final void scanInstalledApplications() {
    }
    
    public final void scanAllWithAndroguard() {
    }
    
    public final void scanSingleAppWithAndroguard(@org.jetbrains.annotations.NotNull()
    java.lang.String packageName) {
    }
}