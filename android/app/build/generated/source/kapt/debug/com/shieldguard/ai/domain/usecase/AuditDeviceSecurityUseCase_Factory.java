package com.shieldguard.ai.domain.usecase;

import com.shieldguard.ai.domain.repository.DeviceSecurityRepository;
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
public final class AuditDeviceSecurityUseCase_Factory implements Factory<AuditDeviceSecurityUseCase> {
  private final Provider<DeviceSecurityRepository> deviceRepositoryProvider;

  public AuditDeviceSecurityUseCase_Factory(
      Provider<DeviceSecurityRepository> deviceRepositoryProvider) {
    this.deviceRepositoryProvider = deviceRepositoryProvider;
  }

  @Override
  public AuditDeviceSecurityUseCase get() {
    return newInstance(deviceRepositoryProvider.get());
  }

  public static AuditDeviceSecurityUseCase_Factory create(
      Provider<DeviceSecurityRepository> deviceRepositoryProvider) {
    return new AuditDeviceSecurityUseCase_Factory(deviceRepositoryProvider);
  }

  public static AuditDeviceSecurityUseCase newInstance(DeviceSecurityRepository deviceRepository) {
    return new AuditDeviceSecurityUseCase(deviceRepository);
  }
}
