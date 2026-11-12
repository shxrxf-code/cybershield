package com.shieldguard.ai.scanner;

import com.shieldguard.ai.service.NetworkTrafficMonitor;
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
public final class LocalUrlThreatAnalyzer_Factory implements Factory<LocalUrlThreatAnalyzer> {
  private final Provider<NetworkTrafficMonitor> networkTrafficMonitorProvider;

  public LocalUrlThreatAnalyzer_Factory(
      Provider<NetworkTrafficMonitor> networkTrafficMonitorProvider) {
    this.networkTrafficMonitorProvider = networkTrafficMonitorProvider;
  }

  @Override
  public LocalUrlThreatAnalyzer get() {
    return newInstance(networkTrafficMonitorProvider.get());
  }

  public static LocalUrlThreatAnalyzer_Factory create(
      Provider<NetworkTrafficMonitor> networkTrafficMonitorProvider) {
    return new LocalUrlThreatAnalyzer_Factory(networkTrafficMonitorProvider);
  }

  public static LocalUrlThreatAnalyzer newInstance(NetworkTrafficMonitor networkTrafficMonitor) {
    return new LocalUrlThreatAnalyzer(networkTrafficMonitor);
  }
}
