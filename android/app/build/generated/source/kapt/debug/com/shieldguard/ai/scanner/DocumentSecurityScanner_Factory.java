package com.shieldguard.ai.scanner;

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
public final class DocumentSecurityScanner_Factory implements Factory<DocumentSecurityScanner> {
  @Override
  public DocumentSecurityScanner get() {
    return newInstance();
  }

  public static DocumentSecurityScanner_Factory create() {
    return InstanceHolder.INSTANCE;
  }

  public static DocumentSecurityScanner newInstance() {
    return new DocumentSecurityScanner();
  }

  private static final class InstanceHolder {
    private static final DocumentSecurityScanner_Factory INSTANCE = new DocumentSecurityScanner_Factory();
  }
}
