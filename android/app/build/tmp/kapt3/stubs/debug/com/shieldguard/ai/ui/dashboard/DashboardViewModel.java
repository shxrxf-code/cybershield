package com.shieldguard.ai.ui.dashboard;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\n\n\u0002\u0010\u000b\n\u0000\b\u0007\u0018\u00002\u00020\u0001BQ\b\u0007\u0012\b\b\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u0012\u0006\u0010\b\u001a\u00020\t\u0012\u0006\u0010\n\u001a\u00020\u000b\u0012\u0006\u0010\f\u001a\u00020\r\u0012\u0006\u0010\u000e\u001a\u00020\u000f\u0012\u0006\u0010\u0010\u001a\u00020\u0011\u0012\u0006\u0010\u0012\u001a\u00020\u0013\u00a2\u0006\u0002\u0010\u0014J\b\u0010\u001c\u001a\u00020\u001dH\u0002J\b\u0010\u001e\u001a\u00020\u001dH\u0002J\b\u0010\u001f\u001a\u00020\u001dH\u0002J\u0006\u0010 \u001a\u00020\u001dJ\u0006\u0010!\u001a\u00020\u001dJ\u0006\u0010\"\u001a\u00020\u001dJ\u000e\u0010#\u001a\u00020\u001d2\u0006\u0010$\u001a\u00020\u0003J\u000e\u0010%\u001a\u00020\u001d2\u0006\u0010$\u001a\u00020\u0003J\u000e\u0010&\u001a\u00020\u001d2\u0006\u0010\'\u001a\u00020(R\u0014\u0010\u0015\u001a\b\u0012\u0004\u0012\u00020\u00170\u0016X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\f\u001a\u00020\rX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u000bX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u000e\u001a\u00020\u000fX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0010\u001a\u00020\u0011X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0012\u001a\u00020\u0013X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\tX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0017\u0010\u0018\u001a\b\u0012\u0004\u0012\u00020\u00170\u0019\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001a\u0010\u001b\u00a8\u0006)"}, d2 = {"Lcom/shieldguard/ai/ui/dashboard/DashboardViewModel;", "Landroidx/lifecycle/ViewModel;", "appContext", "Landroid/content/Context;", "deviceSecurityRepository", "Lcom/shieldguard/ai/domain/repository/DeviceSecurityRepository;", "threatRepository", "Lcom/shieldguard/ai/domain/repository/ThreatRepository;", "scannerRepository", "Lcom/shieldguard/ai/domain/repository/ScannerRepository;", "auditDeviceSecurityUseCase", "Lcom/shieldguard/ai/domain/usecase/AuditDeviceSecurityUseCase;", "apkStaticScanner", "Lcom/shieldguard/ai/scanner/ApkStaticScanner;", "fullDeviceFileScanner", "Lcom/shieldguard/ai/scanner/FullDeviceFileScanner;", "networkTrafficMonitor", "Lcom/shieldguard/ai/service/NetworkTrafficMonitor;", "notificationMonitorHub", "Lcom/shieldguard/ai/service/NotificationMonitorHub;", "(Landroid/content/Context;Lcom/shieldguard/ai/domain/repository/DeviceSecurityRepository;Lcom/shieldguard/ai/domain/repository/ThreatRepository;Lcom/shieldguard/ai/domain/repository/ScannerRepository;Lcom/shieldguard/ai/domain/usecase/AuditDeviceSecurityUseCase;Lcom/shieldguard/ai/scanner/ApkStaticScanner;Lcom/shieldguard/ai/scanner/FullDeviceFileScanner;Lcom/shieldguard/ai/service/NetworkTrafficMonitor;Lcom/shieldguard/ai/service/NotificationMonitorHub;)V", "_uiState", "Lkotlinx/coroutines/flow/MutableStateFlow;", "Lcom/shieldguard/ai/ui/dashboard/DashboardUiState;", "uiState", "Lkotlinx/coroutines/flow/StateFlow;", "getUiState", "()Lkotlinx/coroutines/flow/StateFlow;", "observeNotificationMonitor", "", "observeRecentThreats", "observeSecurityScore", "performFullDeepScan", "performInitialAudit", "refreshStoragePermission", "startVpnFirewall", "context", "stopVpnFirewall", "toggleNotificationShield", "enabled", "", "app_debug"})
@dagger.hilt.android.lifecycle.HiltViewModel()
public final class DashboardViewModel extends androidx.lifecycle.ViewModel {
    @org.jetbrains.annotations.NotNull()
    private final android.content.Context appContext = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.repository.DeviceSecurityRepository deviceSecurityRepository = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.repository.ThreatRepository threatRepository = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.repository.ScannerRepository scannerRepository = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.usecase.AuditDeviceSecurityUseCase auditDeviceSecurityUseCase = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.scanner.ApkStaticScanner apkStaticScanner = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.scanner.FullDeviceFileScanner fullDeviceFileScanner = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.service.NetworkTrafficMonitor networkTrafficMonitor = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.service.NotificationMonitorHub notificationMonitorHub = null;
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.flow.MutableStateFlow<com.shieldguard.ai.ui.dashboard.DashboardUiState> _uiState = null;
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.flow.StateFlow<com.shieldguard.ai.ui.dashboard.DashboardUiState> uiState = null;
    
    @javax.inject.Inject()
    public DashboardViewModel(@dagger.hilt.android.qualifiers.ApplicationContext()
    @org.jetbrains.annotations.NotNull()
    android.content.Context appContext, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.repository.DeviceSecurityRepository deviceSecurityRepository, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.repository.ThreatRepository threatRepository, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.repository.ScannerRepository scannerRepository, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.usecase.AuditDeviceSecurityUseCase auditDeviceSecurityUseCase, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.scanner.ApkStaticScanner apkStaticScanner, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.scanner.FullDeviceFileScanner fullDeviceFileScanner, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.service.NetworkTrafficMonitor networkTrafficMonitor, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.service.NotificationMonitorHub notificationMonitorHub) {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final kotlinx.coroutines.flow.StateFlow<com.shieldguard.ai.ui.dashboard.DashboardUiState> getUiState() {
        return null;
    }
    
    public final void refreshStoragePermission() {
    }
    
    private final void observeNotificationMonitor() {
    }
    
    private final void observeSecurityScore() {
    }
    
    private final void observeRecentThreats() {
    }
    
    public final void performInitialAudit() {
    }
    
    public final void performFullDeepScan() {
    }
    
    public final void startVpnFirewall(@org.jetbrains.annotations.NotNull()
    android.content.Context context) {
    }
    
    public final void stopVpnFirewall(@org.jetbrains.annotations.NotNull()
    android.content.Context context) {
    }
    
    public final void toggleNotificationShield(boolean enabled) {
    }
}