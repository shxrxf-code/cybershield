package com.shieldguard.ai.data.repository;

import com.shieldguard.ai.data.local.EncryptedPreferencesManager;
import com.shieldguard.ai.data.local.dao.ScanHistoryDao;
import com.shieldguard.ai.data.remote.api.ShieldGuardApiService;
import com.shieldguard.ai.scanner.DocumentSecurityScanner;
import com.shieldguard.ai.scanner.LocalUrlThreatAnalyzer;
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
public final class ScannerRepositoryImpl_Factory implements Factory<ScannerRepositoryImpl> {
  private final Provider<ShieldGuardApiService> apiServiceProvider;

  private final Provider<DocumentSecurityScanner> documentSecurityScannerProvider;

  private final Provider<LocalUrlThreatAnalyzer> localUrlThreatAnalyzerProvider;

  private final Provider<ScanHistoryDao> scanHistoryDaoProvider;

  private final Provider<EncryptedPreferencesManager> preferencesManagerProvider;

  public ScannerRepositoryImpl_Factory(Provider<ShieldGuardApiService> apiServiceProvider,
      Provider<DocumentSecurityScanner> documentSecurityScannerProvider,
      Provider<LocalUrlThreatAnalyzer> localUrlThreatAnalyzerProvider,
      Provider<ScanHistoryDao> scanHistoryDaoProvider,
      Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    this.apiServiceProvider = apiServiceProvider;
    this.documentSecurityScannerProvider = documentSecurityScannerProvider;
    this.localUrlThreatAnalyzerProvider = localUrlThreatAnalyzerProvider;
    this.scanHistoryDaoProvider = scanHistoryDaoProvider;
    this.preferencesManagerProvider = preferencesManagerProvider;
  }

  @Override
  public ScannerRepositoryImpl get() {
    return newInstance(apiServiceProvider.get(), documentSecurityScannerProvider.get(), localUrlThreatAnalyzerProvider.get(), scanHistoryDaoProvider.get(), preferencesManagerProvider.get());
  }

  public static ScannerRepositoryImpl_Factory create(
      Provider<ShieldGuardApiService> apiServiceProvider,
      Provider<DocumentSecurityScanner> documentSecurityScannerProvider,
      Provider<LocalUrlThreatAnalyzer> localUrlThreatAnalyzerProvider,
      Provider<ScanHistoryDao> scanHistoryDaoProvider,
      Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    return new ScannerRepositoryImpl_Factory(apiServiceProvider, documentSecurityScannerProvider, localUrlThreatAnalyzerProvider, scanHistoryDaoProvider, preferencesManagerProvider);
  }

  public static ScannerRepositoryImpl newInstance(ShieldGuardApiService apiService,
      DocumentSecurityScanner documentSecurityScanner,
      LocalUrlThreatAnalyzer localUrlThreatAnalyzer, ScanHistoryDao scanHistoryDao,
      EncryptedPreferencesManager preferencesManager) {
    return new ScannerRepositoryImpl(apiService, documentSecurityScanner, localUrlThreatAnalyzer, scanHistoryDao, preferencesManager);
  }
}
