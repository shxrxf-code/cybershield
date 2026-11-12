package com.shieldguard.ai.service;

import android.content.Context;
import androidx.work.WorkerParameters;
import com.shieldguard.ai.data.local.EncryptedPreferencesManager;
import com.shieldguard.ai.domain.repository.ScannerRepository;
import com.shieldguard.ai.scanner.ApkStaticScanner;
import com.shieldguard.ai.scanner.DeviceIntegrityAuditor;
import dagger.internal.DaggerGenerated;
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
public final class ScheduledScanWorker_Factory {
  private final Provider<DeviceIntegrityAuditor> deviceIntegrityAuditorProvider;

  private final Provider<ApkStaticScanner> apkStaticScannerProvider;

  private final Provider<ScannerRepository> scannerRepositoryProvider;

  private final Provider<EncryptedPreferencesManager> preferencesManagerProvider;

  public ScheduledScanWorker_Factory(
      Provider<DeviceIntegrityAuditor> deviceIntegrityAuditorProvider,
      Provider<ApkStaticScanner> apkStaticScannerProvider,
      Provider<ScannerRepository> scannerRepositoryProvider,
      Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    this.deviceIntegrityAuditorProvider = deviceIntegrityAuditorProvider;
    this.apkStaticScannerProvider = apkStaticScannerProvider;
    this.scannerRepositoryProvider = scannerRepositoryProvider;
    this.preferencesManagerProvider = preferencesManagerProvider;
  }

  public ScheduledScanWorker get(Context appContext, WorkerParameters workerParams) {
    return newInstance(appContext, workerParams, deviceIntegrityAuditorProvider.get(), apkStaticScannerProvider.get(), scannerRepositoryProvider.get(), preferencesManagerProvider.get());
  }

  public static ScheduledScanWorker_Factory create(
      Provider<DeviceIntegrityAuditor> deviceIntegrityAuditorProvider,
      Provider<ApkStaticScanner> apkStaticScannerProvider,
      Provider<ScannerRepository> scannerRepositoryProvider,
      Provider<EncryptedPreferencesManager> preferencesManagerProvider) {
    return new ScheduledScanWorker_Factory(deviceIntegrityAuditorProvider, apkStaticScannerProvider, scannerRepositoryProvider, preferencesManagerProvider);
  }

  public static ScheduledScanWorker newInstance(Context appContext, WorkerParameters workerParams,
      DeviceIntegrityAuditor deviceIntegrityAuditor, ApkStaticScanner apkStaticScanner,
      ScannerRepository scannerRepository, EncryptedPreferencesManager preferencesManager) {
    return new ScheduledScanWorker(appContext, workerParams, deviceIntegrityAuditor, apkStaticScanner, scannerRepository, preferencesManager);
  }
}
