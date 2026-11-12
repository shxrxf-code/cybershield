package com.shieldguard.ai.domain.usecase;

import com.shieldguard.ai.domain.repository.ScannerRepository;
import com.shieldguard.ai.domain.repository.ThreatRepository;
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
public final class ScanUrlUseCase_Factory implements Factory<ScanUrlUseCase> {
  private final Provider<ScannerRepository> scannerRepositoryProvider;

  private final Provider<ThreatRepository> threatRepositoryProvider;

  public ScanUrlUseCase_Factory(Provider<ScannerRepository> scannerRepositoryProvider,
      Provider<ThreatRepository> threatRepositoryProvider) {
    this.scannerRepositoryProvider = scannerRepositoryProvider;
    this.threatRepositoryProvider = threatRepositoryProvider;
  }

  @Override
  public ScanUrlUseCase get() {
    return newInstance(scannerRepositoryProvider.get(), threatRepositoryProvider.get());
  }

  public static ScanUrlUseCase_Factory create(Provider<ScannerRepository> scannerRepositoryProvider,
      Provider<ThreatRepository> threatRepositoryProvider) {
    return new ScanUrlUseCase_Factory(scannerRepositoryProvider, threatRepositoryProvider);
  }

  public static ScanUrlUseCase newInstance(ScannerRepository scannerRepository,
      ThreatRepository threatRepository) {
    return new ScanUrlUseCase(scannerRepository, threatRepository);
  }
}
