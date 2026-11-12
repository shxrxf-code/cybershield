package com.shieldguard.ai.ui.network;

import com.shieldguard.ai.data.local.EncryptedPreferencesManager;
import com.shieldguard.ai.service.NetworkTrafficMonitor;
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
public final class NetworkViewModel_Factory implements Factory<NetworkViewModel> {
  private final Provider<NetworkTrafficMonitor> networkTrafficMonitorProvider;

  private final Provider<EncryptedPreferencesManager> preferencesManagerProvider;

  public NetworkViewModel_Factory(Provider<NetworkTrafficMonitor> networkTrafficMonitorProvider,
      Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    this.networkTrafficMonitorProvider = networkTrafficMonitorProvider;
    this.preferencesManagerProvider = preferencesManagerProvider;
  }

  @Override
  public NetworkViewModel get() {
    return newInstance(networkTrafficMonitorProvider.get(), preferencesManagerProvider.get());
  }

  public static NetworkViewModel_Factory create(
      Provider<NetworkTrafficMonitor> networkTrafficMonitorProvider,
      Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    return new NetworkViewModel_Factory(networkTrafficMonitorProvider, preferencesManagerProvider);
  }

  public static NetworkViewModel newInstance(NetworkTrafficMonitor networkTrafficMonitor,
      EncryptedPreferencesManager preferencesManager) {
    return new NetworkViewModel(networkTrafficMonitor, preferencesManager);
  }
}
