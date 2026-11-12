package com.shieldguard.ai.ui.scanners;

import com.shieldguard.ai.domain.usecase.ScanUrlUseCase;
import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
import dagger.internal.QualifierMetadata;
import dagger.internal.ScopeMetadata;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

@ScopeMetadata
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
public final class UrlScannerViewModel_Factory implements Factory<UrlScannerViewModel> {
  private final Provider<ScanUrlUseCase> scanUrlUseCaseProvider;

  public UrlScannerViewModel_Factory(Provider<ScanUrlUseCase> scanUrlUseCaseProvider) {
    this.scanUrlUseCaseProvider = scanUrlUseCaseProvider;
  }

  @Override
  public UrlScannerViewModel get() {
    return newInstance(scanUrlUseCaseProvider.get());
  }

  public static UrlScannerViewModel_Factory create(
      Provider<ScanUrlUseCase> scanUrlUseCaseProvider) {
    return new UrlScannerViewModel_Factory(scanUrlUseCaseProvider);
  }

  public static UrlScannerViewModel newInstance(ScanUrlUseCase scanUrlUseCase) {
    return new UrlScannerViewModel(scanUrlUseCase);
  }
}
