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
public final class NotificationMonitorHub_Factory implements Factory<NotificationMonitorHub> {
  @Override
  public NotificationMonitorHub get() {
    return newInstance();
  }

  public static NotificationMonitorHub_Factory create() {
    return InstanceHolder.INSTANCE;
  }

  public static NotificationMonitorHub newInstance() {
    return new NotificationMonitorHub();
  }

  private static final class InstanceHolder {
    private static final NotificationMonitorHub_Factory INSTANCE = new NotificationMonitorHub_Factory();
  }
}
