package com.shieldguard.ai.data.remote;

import com.shieldguard.ai.data.local.EncryptedPreferencesManager;
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
public final class AuthInterceptor_Factory implements Factory<AuthInterceptor> {
  private final Provider<EncryptedPreferencesManager> preferencesManagerProvider;

  public AuthInterceptor_Factory(Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    this.preferencesManagerProvider = preferencesManagerProvider;
  }

  @Override
  public AuthInterceptor get() {
    return newInstance(preferencesManagerProvider.get());
  }

  public static AuthInterceptor_Factory create(
      Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    return new AuthInterceptor_Factory(preferencesManagerProvider);
  }

  public static AuthInterceptor newInstance(EncryptedPreferencesManager preferencesManager) {
    return new AuthInterceptor(preferencesManager);
  }
}
