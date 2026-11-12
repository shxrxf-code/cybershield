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
public final class FullDeviceFileScanner_Factory implements Factory<FullDeviceFileScanner> {
  private final Provider<Context> contextProvider;

  private final Provider<DocumentSecurityScanner> documentSecurityScannerProvider;

  public FullDeviceFileScanner_Factory(Provider<Context> contextProvider,
      Provider<DocumentSecurityScanner> documentSecurityScannerProvider) {
    this.contextProvider = contextProvider;
    this.documentSecurityScannerProvider = documentSecurityScannerProvider;
  }

  @Override
  public FullDeviceFileScanner get() {
    return newInstance(contextProvider.get(), documentSecurityScannerProvider.get());
  }

  public static FullDeviceFileScanner_Factory create(Provider<Context> contextProvider,
      Provider<DocumentSecurityScanner> documentSecurityScannerProvider) {
    return new FullDeviceFileScanner_Factory(contextProvider, documentSecurityScannerProvider);
  }

  public static FullDeviceFileScanner newInstance(Context context,
      DocumentSecurityScanner documentSecurityScanner) {
    return new FullDeviceFileScanner(context, documentSecurityScanner);
  }
}
