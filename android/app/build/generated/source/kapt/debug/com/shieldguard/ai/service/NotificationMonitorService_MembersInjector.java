package com.shieldguard.ai.service;

import com.shieldguard.ai.data.local.EncryptedPreferencesManager;
import com.shieldguard.ai.domain.usecase.ProcessNotificationUseCase;
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
public final class NotificationMonitorService_MembersInjector implements MembersInjector<NotificationMonitorService> {
  private final Provider<ProcessNotificationUseCase> processNotificationUseCaseProvider;

  private final Provider<EncryptedPreferencesManager> preferencesManagerProvider;

  public NotificationMonitorService_MembersInjector(
      Provider<ProcessNotificationUseCase> processNotificationUseCaseProvider,
      Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    this.processNotificationUseCaseProvider = processNotificationUseCaseProvider;
    this.preferencesManagerProvider = preferencesManagerProvider;
  }

  public static MembersInjector<NotificationMonitorService> create(
      Provider<ProcessNotificationUseCase> processNotificationUseCaseProvider,
      Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    return new NotificationMonitorService_MembersInjector(processNotificationUseCaseProvider, preferencesManagerProvider);
  }

  @Override
  public void injectMembers(NotificationMonitorService instance) {
    injectProcessNotificationUseCase(instance, processNotificationUseCaseProvider.get());
    injectPreferencesManager(instance, preferencesManagerProvider.get());
  }

  @InjectedFieldSignature("com.shieldguard.ai.service.NotificationMonitorService.processNotificationUseCase")
  public static void injectProcessNotificationUseCase(NotificationMonitorService instance,
      ProcessNotificationUseCase processNotificationUseCase) {
    instance.processNotificationUseCase = processNotificationUseCase;
  }

  @InjectedFieldSignature("com.shieldguard.ai.service.NotificationMonitorService.preferencesManager")
  public static void injectPreferencesManager(NotificationMonitorService instance,
      EncryptedPreferencesManager preferencesManager) {
    instance.preferencesManager = preferencesManager;
  }
}
