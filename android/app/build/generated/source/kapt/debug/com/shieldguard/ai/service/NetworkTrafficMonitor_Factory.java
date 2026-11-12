package com.shieldguard.ai.service;

import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
import dagger.internal.QualifierMetadata;
import dagger.internal.ScopeMetadata;
import javax.annotation.processing.Generated;

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
public final class NetworkTrafficMonitor_Factory implements Factory<NetworkTrafficMonitor> {
  @Override
  public NetworkTrafficMonitor get() {
    return newInstance();
  }

  public static NetworkTrafficMonitor_Factory create() {
    return InstanceHolder.INSTANCE;
  }

  public static NetworkTrafficMonitor newInstance() {
    return new NetworkTrafficMonitor();
  }

  private static final class InstanceHolder {
    private static final NetworkTrafficMonitor_Factory INSTANCE = new NetworkTrafficMonitor_Factory();
  }
}
