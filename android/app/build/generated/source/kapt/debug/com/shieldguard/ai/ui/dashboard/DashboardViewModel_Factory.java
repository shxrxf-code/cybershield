package com.shieldguard.ai.ui.dashboard;

import android.content.Context;
import com.shieldguard.ai.domain.repository.DeviceSecurityRepository;
import com.shieldguard.ai.domain.repository.ScannerRepository;
import com.shieldguard.ai.domain.repository.ThreatRepository;
import com.shieldguard.ai.domain.usecase.AuditDeviceSecurityUseCase;
import com.shieldguard.ai.scanner.ApkStaticScanner;
import com.shieldguard.ai.scanner.FullDeviceFileScanner;
import com.shieldguard.ai.service.NetworkTrafficMonitor;
import com.shieldguard.ai.service.NotificationMonitorHub;
import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
import dagger.internal.QualifierMetadata;
import dagger.internal.ScopeMetadata;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

@ScopeMetadata
@QualifierMetadata("dagger.hilt.android.qualifiers.ApplicationContext")
@DaggerGenerated
@Generated(
    value = "dagger.internal.codegen.ComponentProcessor",
    comments = "https://dagger.dev"
)
@SuppressWarnings({
    "unchecked",
    "rawtypes",
    "KotlinInternal",
    "KotlinInternalInJava",
    "cast"
})
public final class DashboardViewModel_Factory implements Factory<DashboardViewModel> {
  private final Provider<Context> appContextProvider;

  private final Provider<DeviceSecurityRepository> deviceSecurityRepositoryProvider;

  private final Provider<ThreatRepository> threatRepositoryProvider;

  private final Provider<ScannerRepository> scannerRepositoryProvider;

  private final Provider<AuditDeviceSecurityUseCase> auditDeviceSecurityUseCaseProvider;

  private final Provider<ApkStaticScanner> apkStaticScannerProvider;

  private final Provider<FullDeviceFileScanner> fullDeviceFileScannerProvider;

  private final Provider<NetworkTrafficMonitor> networkTrafficMonitorProvider;

  private final Provider<NotificationMonitorHub> notificationMonitorHubProvider;

  public DashboardViewModel_Factory(Provider<Context> appContextProvider,
      Provider<DeviceSecurityRepository> deviceSecurityRepositoryProvider,
      Provider<ThreatRepository> threatRepositoryProvider,
      Provider<ScannerRepository> scannerRepositoryProvider,
      Provider<AuditDeviceSecurityUseCase> auditDeviceSecurityUseCaseProvider,
      Provider<ApkStaticScanner> apkStaticScannerProvider,
      Provider<FullDeviceFileScanner> fullDeviceFileScannerProvider,
      Provider<NetworkTrafficMonitor> networkTrafficMonitorProvider,
      Provider<NotificationMonitorHub> notificationMonitorHubProvider) {
    this.appContextProvider = appContextProvider;
    this.deviceSecurityRepositoryProvider = deviceSecurityRepositoryProvider;
    this.threatRepositoryProvider = threatRepositoryProvider;
    this.scannerRepositoryProvider = scannerRepositoryProvider;
    this.auditDeviceSecurityUseCaseProvider = auditDeviceSecurityUseCaseProvider;
    this.apkStaticScannerProvider = apkStaticScannerProvider;
    this.fullDeviceFileScannerProvider = fullDeviceFileScannerProvider;
    this.networkTrafficMonitorProvider = networkTrafficMonitorProvider;
    this.notificationMonitorHubProvider = notificationMonitorHubProvider;
  }

  @Override
  public DashboardViewModel get() {
    return newInstance(appContextProvider.get(), deviceSecurityRepositoryProvider.get(), threatRepositoryProvider.get(), scannerRepositoryProvider.get(), auditDeviceSecurityUseCaseProvider.get(), apkStaticScannerProvider.get(), fullDeviceFileScannerProvider.get(), networkTrafficMonitorProvider.get(), notificationMonitorHubProvider.get());
  }

  public static DashboardViewModel_Factory create(Provider<Context> appContextProvider,
      Provider<DeviceSecurityRepository> deviceSecurityRepositoryProvider,
      Provider<ThreatRepository> threatRepositoryProvider,
      Provider<ScannerRepository> scannerRepositoryProvider,
      Provider<AuditDeviceSecurityUseCase> auditDeviceSecurityUseCaseProvider,
      Provider<ApkStaticScanner> apkStaticScannerProvider,
      Provider<FullDeviceFileScanner> fullDeviceFileScannerProvider,
      Provider<NetworkTrafficMonitor> networkTrafficMonitorProvider,
      Provider<NotificationMonitorHub> notificationMonitorHubProvider) {
    return new DashboardViewModel_Factory(appContextProvider, deviceSecurityRepositoryProvider, threatRepositoryProvider, scannerRepositoryProvider, auditDeviceSecurityUseCaseProvider, apkStaticScannerProvider, fullDeviceFileScannerProvider, networkTrafficMonitorProvider, notificationMonitorHubProvider);
  }

  public static DashboardViewModel newInstance(Context appContext,
      DeviceSecurityRepository deviceSecurityRepository, ThreatRepository threatRepository,
      ScannerRepository scannerRepository, AuditDeviceSecurityUseCase auditDeviceSecurityUseCase,
      ApkStaticScanner apkStaticScanner, FullDeviceFileScanner fullDeviceFileScanner,
      NetworkTrafficMonitor networkTrafficMonitor, NotificationMonitorHub notificationMonitorHub) {
    return new DashboardViewModel(appContext, deviceSecurityRepository, threatRepository, scannerRepository, auditDeviceSecurityUseCase, apkStaticScanner, fullDeviceFileScanner, networkTrafficMonitor, notificationMonitorHub);
  }
}
