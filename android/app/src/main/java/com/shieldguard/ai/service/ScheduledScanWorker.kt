package com.shieldguard.ai.service

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.shieldguard.ai.data.local.EncryptedPreferencesManager
import com.shieldguard.ai.domain.model.ScanResult
import com.shieldguard.ai.domain.repository.ScannerRepository
import com.shieldguard.ai.scanner.ApkStaticScanner
import com.shieldguard.ai.scanner.DeviceIntegrityAuditor
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.UUID

@HiltWorker
class ScheduledScanWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val deviceIntegrityAuditor: DeviceIntegrityAuditor,
    private val apkStaticScanner: ApkStaticScanner,
    private val scannerRepository: ScannerRepository,
    private val preferencesManager: EncryptedPreferencesManager
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val startTime = System.currentTimeMillis()

        // 1. Audit Device Integrity
        val audit = deviceIntegrityAuditor.auditDevice()

        // 2. Scan installed apps
        val apps = apkStaticScanner.scanAllInstalledApps()
        val maliciousCount = apps.count { it.verdict == com.shieldguard.ai.domain.model.Verdict.MALICIOUS }

        val duration = System.currentTimeMillis() - startTime

        // Update cached security score
        val finalScore = (audit.securityScore - (maliciousCount * 20)).coerceIn(0, 100)
        preferencesManager.setCachedSecurityScore(finalScore)

        scannerRepository.recordScanResult(
            ScanResult(
                scanId = UUID.randomUUID().toString(),
                scanType = "PERIODIC_DEVICE_SCAN",
                status = "COMPLETED",
                riskScore = 100 - finalScore,
                findingsCount = maliciousCount + (if (audit.isRooted) 1 else 0),
                scannedItemsCount = apps.size,
                findings = audit.recommendations,
                durationMs = duration,
                timestampMs = System.currentTimeMillis()
            )
        )

        return Result.success()
    }
}
