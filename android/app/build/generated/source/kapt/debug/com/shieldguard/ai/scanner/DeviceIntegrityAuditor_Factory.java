package com.shieldguard.ai.scanner;

import android.content.Context;
import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
import dagger.internal.QualifierMetadata;
import dagger.internal.ScopeMetadata;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

@ScopeMetadata("javax.inject.Singleton")
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
public final class DeviceIntegrityAuditor_Factory implements Factory<DeviceIntegrityAuditor> {
  private final Provider<Context> contextProvider;

  private final Provider<RootDetectionEngine> rootDetectionEngineProvider;

  public DeviceIntegrityAuditor_Factory(Provider<Context> contextProvider,
      Provider<RootDetectionEngine> rootDetectionEngineProvider) {
    this.contextProvider = contextProvider;
    this.rootDetectionEngineProvider = rootDetectionEngineProvider;
  }

  @Override
  public DeviceIntegrityAuditor get() {
    return newInstance(contextProvider.get(), rootDetectionEngineProvider.get());
  }

  public static DeviceIntegrityAuditor_Factory create(Provider<Context> contextProvider,
      Provider<RootDetectionEngine> rootDetectionEngineProvider) {
    return new DeviceIntegrityAuditor_Factory(contextProvider, rootDetectionEngineProvider);
  }

  public static DeviceIntegrityAuditor newInstance(Context context,
      RootDetectionEngine rootDetectionEngine) {
    return new DeviceIntegrityAuditor(context, rootDetectionEngine);
  }
}
