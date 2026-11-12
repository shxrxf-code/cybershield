package com.shieldguard.ai.service;

import com.shieldguard.ai.data.local.EncryptedPreferencesManager;
import com.shieldguard.ai.domain.repository.ThreatRepository;
import dagger.MembersInjector;
import dagger.internal.DaggerGenerated;
import dagger.internal.InjectedFieldSignature;
import dagger.internal.QualifierMetadata;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

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
public final class ShieldGuardVpnService_MembersInjector implements MembersInjector<ShieldGuardVpnService> {
  private final Provider<NetworkTrafficMonitor> networkTrafficMonitorProvider;

  private final Provider<ThreatRepository> threatRepositoryProvider;

  private final Provider<EncryptedPreferencesManager> preferencesManagerProvider;

  public ShieldGuardVpnService_MembersInjector(
      Provider<NetworkTrafficMonitor> networkTrafficMonitorProvider,
      Provider<ThreatRepository> threatRepositoryProvider,
      Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    this.networkTrafficMonitorProvider = networkTrafficMonitorProvider;
    this.threatRepositoryProvider = threatRepositoryProvider;
    this.preferencesManagerProvider = preferencesManagerProvider;
  }

  public static MembersInjector<ShieldGuardVpnService> create(
      Provider<NetworkTrafficMonitor> networkTrafficMonitorProvider,
      Provider<ThreatRepository> threatRepositoryProvider,
      Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    return new ShieldGuardVpnService_MembersInjector(networkTrafficMonitorProvider, threatRepositoryProvider, preferencesManagerProvider);
  }

  @Override
  public void injectMembers(ShieldGuardVpnService instance) {
    injectNetworkTrafficMonitor(instance, networkTrafficMonitorProvider.get());
    injectThreatRepository(instance, threatRepositoryProvider.get());
    injectPreferencesManager(instance, preferencesManagerProvider.get());
  }

  @InjectedFieldSignature("com.shieldguard.ai.service.ShieldGuardVpnService.networkTrafficMonitor")
  public static void injectNetworkTrafficMonitor(ShieldGuardVpnService instance,
      NetworkTrafficMonitor networkTrafficMonitor) {
    instance.networkTrafficMonitor = networkTrafficMonitor;
  }

  @InjectedFieldSignature("com.shieldguard.ai.service.ShieldGuardVpnService.threatRepository")
  public static void injectThreatRepository(ShieldGuardVpnService instance,
      ThreatRepository threatRepository) {
    instance.threatRepository = threatRepository;
  }

  @InjectedFieldSignature("com.shieldguard.ai.service.ShieldGuardVpnService.preferencesManager")
  public static void injectPreferencesManager(ShieldGuardVpnService instance,
      EncryptedPreferencesManager preferencesManager) {
    instance.preferencesManager = preferencesManager;
  }
}
