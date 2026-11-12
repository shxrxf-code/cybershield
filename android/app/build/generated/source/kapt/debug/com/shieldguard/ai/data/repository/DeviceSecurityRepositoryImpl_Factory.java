package com.shieldguard.ai.data.repository;

import com.shieldguard.ai.data.local.EncryptedPreferencesManager;
import com.shieldguard.ai.data.local.dao.ThreatDao;
import com.shieldguard.ai.scanner.DeviceIntegrityAuditor;
import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
import dagger.internal.QualifierMetadata;
import dagger.internal.ScopeMetadata;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

@ScopeMetadata("javax.inject.Singleton")
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
public final class DeviceSecurityRepositoryImpl_Factory implements Factory<DeviceSecurityRepositoryImpl> {
  private final Provider<DeviceIntegrityAuditor> auditorProvider;

  private final Provider<ThreatDao> threatDaoProvider;

  private final Provider<EncryptedPreferencesManager> preferencesManagerProvider;

  public DeviceSecurityRepositoryImpl_Factory(Provider<DeviceIntegrityAuditor> auditorProvider,
      Provider<ThreatDao> threatDaoProvider,
      Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    this.auditorProvider = auditorProvider;
    this.threatDaoProvider = threatDaoProvider;
    this.preferencesManagerProvider = preferencesManagerProvider;
  }

  @Override
  public DeviceSecurityRepositoryImpl get() {
    return newInstance(auditorProvider.get(), threatDaoProvider.get(), preferencesManagerProvider.get());
  }

  public static DeviceSecurityRepositoryImpl_Factory create(
      Provider<DeviceIntegrityAuditor> auditorProvider, Provider<ThreatDao> threatDaoProvider,
      Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    return new DeviceSecurityRepositoryImpl_Factory(auditorProvider, threatDaoProvider, preferencesManagerProvider);
  }

  public static DeviceSecurityRepositoryImpl newInstance(DeviceIntegrityAuditor auditor,
      ThreatDao threatDao, EncryptedPreferencesManager preferencesManager) {
    return new DeviceSecurityRepositoryImpl(auditor, threatDao, preferencesManager);
  }
}
