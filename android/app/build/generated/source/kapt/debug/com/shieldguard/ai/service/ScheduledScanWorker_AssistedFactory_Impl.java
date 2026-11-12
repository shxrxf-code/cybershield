package com.shieldguard.ai.service;

import android.content.Context;
import androidx.work.WorkerParameters;
import dagger.internal.DaggerGenerated;
import dagger.internal.InstanceFactory;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

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
public final class ScheduledScanWorker_AssistedFactory_Impl implements ScheduledScanWorker_AssistedFactory {
  private final ScheduledScanWorker_Factory delegateFactory;

  ScheduledScanWorker_AssistedFactory_Impl(ScheduledScanWorker_Factory delegateFactory) {
    this.delegateFactory = delegateFactory;
  }

  @Override
  public ScheduledScanWorker create(Context arg0, WorkerParameters arg1) {
    return delegateFactory.get(arg0, arg1);
  }

  public static Provider<ScheduledScanWorker_AssistedFactory> create(
      ScheduledScanWorker_Factory delegateFactory) {
    return InstanceFactory.create(new ScheduledScanWorker_AssistedFactory_Impl(delegateFactory));
  }

  public static dagger.internal.Provider<ScheduledScanWorker_AssistedFactory> createFactoryProvider(
      ScheduledScanWorker_Factory delegateFactory) {
    return InstanceFactory.create(new ScheduledScanWorker_AssistedFactory_Impl(delegateFactory));
  }
}
