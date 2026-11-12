package com.shieldguard.ai.domain.usecase;

import com.shieldguard.ai.domain.repository.ThreatRepository;
import com.shieldguard.ai.scanner.LocalUrlThreatAnalyzer;
import com.shieldguard.ai.service.NotificationMonitorHub;
import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
import dagger.internal.QualifierMetadata;
import dagger.internal.ScopeMetadata;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

@ScopeMetadata
@QualifierMetadata
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
public final class ProcessNotificationUseCase_Factory implements Factory<ProcessNotificationUseCase> {
  private final Provider<ThreatRepository> threatRepositoryProvider;

  private final Provider<ScanUrlUseCase> scanUrlUseCaseProvider;

  private final Provider<LocalUrlThreatAnalyzer> localUrlThreatAnalyzerProvider;

  private final Provider<NotificationMonitorHub> notificationMonitorHubProvider;

  public ProcessNotificationUseCase_Factory(Provider<ThreatRepository> threatRepositoryProvider,
      Provider<ScanUrlUseCase> scanUrlUseCaseProvider,
      Provider<LocalUrlThreatAnalyzer> localUrlThreatAnalyzerProvider,
      Provider<NotificationMonitorHub> notificationMonitorHubProvider) {
    this.threatRepositoryProvider = threatRepositoryProvider;
    this.scanUrlUseCaseProvider = scanUrlUseCaseProvider;
    this.localUrlThreatAnalyzerProvider = localUrlThreatAnalyzerProvider;
    this.notificationMonitorHubProvider = notificationMonitorHubProvider;
  }

  @Override
  public ProcessNotificationUseCase get() {
    return newInstance(threatRepositoryProvider.get(), scanUrlUseCaseProvider.get(), localUrlThreatAnalyzerProvider.get(), notificationMonitorHubProvider.get());
  }

  public static ProcessNotificationUseCase_Factory create(
      Provider<ThreatRepository> threatRepositoryProvider,
      Provider<ScanUrlUseCase> scanUrlUseCaseProvider,
      Provider<LocalUrlThreatAnalyzer> localUrlThreatAnalyzerProvider,
      Provider<NotificationMonitorHub> notificationMonitorHubProvider) {
    return new ProcessNotificationUseCase_Factory(threatRepositoryProvider, scanUrlUseCaseProvider, localUrlThreatAnalyzerProvider, notificationMonitorHubProvider);
  }

  public static ProcessNotificationUseCase newInstance(ThreatRepository threatRepository,
      ScanUrlUseCase scanUrlUseCase, LocalUrlThreatAnalyzer localUrlThreatAnalyzer,
      NotificationMonitorHub notificationMonitorHub) {
    return new ProcessNotificationUseCase(threatRepository, scanUrlUseCase, localUrlThreatAnalyzer, notificationMonitorHub);
  }
}
