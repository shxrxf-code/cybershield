package com.shieldguard.ai.domain.usecase;

import com.shieldguard.ai.domain.repository.DeviceSecurityRepository;
import com.shieldguard.ai.domain.repository.ThreatRepository;
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
public final class GetDashboardSummaryUseCase_Factory implements Factory<GetDashboardSummaryUseCase> {
  private final Provider<ThreatRepository> threatRepositoryProvider;

  private final Provider<DeviceSecurityRepository> deviceSecurityRepositoryProvider;

  public GetDashboardSummaryUseCase_Factory(Provider<ThreatRepository> threatRepositoryProvider,
      Provider<DeviceSecurityRepository> deviceSecurityRepositoryProvider) {
    this.threatRepositoryProvider = threatRepositoryProvider;
    this.deviceSecurityRepositoryProvider = deviceSecurityRepositoryProvider;
  }

  @Override
  public GetDashboardSummaryUseCase get() {
    return newInstance(threatRepositoryProvider.get(), deviceSecurityRepositoryProvider.get());
  }

  public static GetDashboardSummaryUseCase_Factory create(
      Provider<ThreatRepository> threatRepositoryProvider,
      Provider<DeviceSecurityRepository> deviceSecurityRepositoryProvider) {
    return new GetDashboardSummaryUseCase_Factory(threatRepositoryProvider, deviceSecurityRepositoryProvider);
  }

  public static GetDashboardSummaryUseCase newInstance(ThreatRepository threatRepository,
      DeviceSecurityRepository deviceSecurityRepository) {
    return new GetDashboardSummaryUseCase(threatRepository, deviceSecurityRepository);
  }
}
