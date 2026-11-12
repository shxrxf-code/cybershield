package com.shieldguard.ai.ui.scanners;

import com.shieldguard.ai.domain.repository.ThreatRepository;
import com.shieldguard.ai.domain.usecase.ScanApkUseCase;
import com.shieldguard.ai.scanner.ApkStaticScanner;
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
public final class AppScannerViewModel_Factory implements Factory<AppScannerViewModel> {
  private final Provider<ApkStaticScanner> apkStaticScannerProvider;

  private final Provider<ScanApkUseCase> scanApkUseCaseProvider;

  private final Provider<ThreatRepository> threatRepositoryProvider;

  public AppScannerViewModel_Factory(Provider<ApkStaticScanner> apkStaticScannerProvider,
      Provider<ScanApkUseCase> scanApkUseCaseProvider,
      Provider<ThreatRepository> threatRepositoryProvider) {
    this.apkStaticScannerProvider = apkStaticScannerProvider;
    this.scanApkUseCaseProvider = scanApkUseCaseProvider;
    this.threatRepositoryProvider = threatRepositoryProvider;
  }

  @Override
  public AppScannerViewModel get() {
    return newInstance(apkStaticScannerProvider.get(), scanApkUseCaseProvider.get(), threatRepositoryProvider.get());
  }

  public static AppScannerViewModel_Factory create(
      Provider<ApkStaticScanner> apkStaticScannerProvider,
      Provider<ScanApkUseCase> scanApkUseCaseProvider,
      Provider<ThreatRepository> threatRepositoryProvider) {
    return new AppScannerViewModel_Factory(apkStaticScannerProvider, scanApkUseCaseProvider, threatRepositoryProvider);
  }

  public static AppScannerViewModel newInstance(ApkStaticScanner apkStaticScanner,
      ScanApkUseCase scanApkUseCase, ThreatRepository threatRepository) {
    return new AppScannerViewModel(apkStaticScanner, scanApkUseCase, threatRepository);
  }
}
