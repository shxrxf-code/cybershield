package com.shieldguard.ai;

import androidx.hilt.work.HiltWorkerFactory;
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
public final class ShieldGuardApp_MembersInjector implements MembersInjector<ShieldGuardApp> {
  private final Provider<HiltWorkerFactory> workerFactoryProvider;

  public ShieldGuardApp_MembersInjector(Provider<HiltWorkerFactory> workerFactoryProvider) {
    this.workerFactoryProvider = workerFactoryProvider;
  }

  public static MembersInjector<ShieldGuardApp> create(
      Provider<HiltWorkerFactory> workerFactoryProvider) {
    return new ShieldGuardApp_MembersInjector(workerFactoryProvider);
  }

  @Override
  public void injectMembers(ShieldGuardApp instance) {
    injectWorkerFactory(instance, workerFactoryProvider.get());
  }

  @InjectedFieldSignature("com.shieldguard.ai.ShieldGuardApp.workerFactory")
  public static void injectWorkerFactory(ShieldGuardApp instance, HiltWorkerFactory workerFactory) {
    instance.workerFactory = workerFactory;
  }
}
