package com.shieldguard.ai.data.local;

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
public final class EncryptedPreferencesManager_Factory implements Factory<EncryptedPreferencesManager> {
  private final Provider<Context> contextProvider;

  public EncryptedPreferencesManager_Factory(Provider<Context> contextProvider) {
    this.contextProvider = contextProvider;
  }

  @Override
  public EncryptedPreferencesManager get() {
    return newInstance(contextProvider.get());
  }

  public static EncryptedPreferencesManager_Factory create(Provider<Context> contextProvider) {
    return new EncryptedPreferencesManager_Factory(contextProvider);
  }

  public static EncryptedPreferencesManager newInstance(Context context) {
    return new EncryptedPreferencesManager(context);
  }
}
