package com.shieldguard.ai.domain.usecase

import com.shieldguard.ai.domain.model.AppThreatInfo
import com.shieldguard.ai.domain.model.DeviceAudit
import com.shieldguard.ai.domain.model.ModuleType
import com.shieldguard.ai.domain.model.SecurityScore
import com.shieldguard.ai.domain.model.Threat
import com.shieldguard.ai.domain.model.ThreatLevel
import com.shieldguard.ai.domain.model.Verdict
import com.shieldguard.ai.domain.repository.DeviceSecurityRepository
import com.shieldguard.ai.domain.repository.ScannerRepository
import com.shieldguard.ai.domain.repository.ThreatRepository
import kotlinx.coroutines.flow.Flow
import java.util.UUID
import javax.inject.Inject

class ScanUrlUseCase @Inject constructor(
    private val scannerRepository: ScannerRepository,
    private val threatRepository: ThreatRepository
) {
    suspend operator fun invoke(url: String): Result<Threat> {
        val result = scannerRepository.scanUrl(url)
        result.onSuccess { threat ->
            if (threat.verdict != Verdict.SAFE) {
                threatRepository.recordThreat(threat)
            }
        }
        return result
    }
}

class ScanApkUseCase @Inject constructor(
    private val scannerRepository: ScannerRepository,
    private val threatRepository: ThreatRepository
) {
    suspend operator fun invoke(appInfo: AppThreatInfo): Result<AppThreatInfo> {
        val result = scannerRepository.scanApk(appInfo)
        result.onSuccess { scanned ->
            if (scanned.verdict != Verdict.SAFE) {
                threatRepository.recordThreat(
                    Threat(
                        id = UUID.randomUUID().toString(),
                        moduleType = ModuleType.APK,
                        threatLevel = scanned.threatLevel,
                        verdict = scanned.verdict,
                        riskScore = scanned.riskScore,
                        title = "Suspicious App: ${scanned.appName}",
                        description = scanned.recommendation,
                        actionTaken = if (scanned.verdict == Verdict.MALICIOUS) "UNINSTALL_RECOMMENDED" else "WARNED",
                        rawPayload = scanned.packageName,
                        indicators = scanned.dangerousPermissions + scanned.malwareFamilies,
                        timestampMs = System.currentTimeMillis()
                    )
                )
            }
        }
        return result
    }
}

class ScanDocumentUseCase @Inject constructor(
    private val scannerRepository: ScannerRepository,
    private val threatRepository: ThreatRepository
) {
    suspend operator fun invoke(filePath: String): Result<Threat> {
        val result = scannerRepository.scanDocument(filePath)
        result.onSuccess { threat ->
            if (threat.verdict != Verdict.SAFE) {
                threatRepository.recordThreat(threat)
            }
        }
        return result
    }
}

class AuditDeviceSecurityUseCase @Inject constructor(
    private val deviceRepository: DeviceSecurityRepository
) {
    suspend operator fun invoke(): DeviceAudit {
        return deviceRepository.performDeviceAudit()
    }
}

class ProcessNotificationUseCase @Inject constructor(
    private val threatRepository: ThreatRepository,
    private val scanUrlUseCase: ScanUrlUseCase
) {
    suspend operator fun invoke(
        packageName: String,
        appLabel: String,
        title: String,
        text: String
    ): Threat? {
        val combined = "$title $text".lowercase()
        var riskScore = 0
        var threatType: String? = null
        val indicators = mutableListOf<String>()

        // 1. Phishing & Scam Lures Detection
        if (combined.contains("winner") || combined.contains("lottery") || combined.contains("won $") || combined.contains("claim prize")) {
            riskScore += 45
            threatType = "Fake Giveaway / Lottery Scam"
            indicators.add("Lottery lure pattern detected")
        }

        if (combined.contains("bitcoin") || combined.contains("crypto giveaway") || combined.contains("airdrop") || combined.contains("usdt")) {
            riskScore += 50
            threatType = "Cryptocurrency Scam"
            indicators.add("Crypto drain lure pattern detected")
        }

        if (combined.contains("suspended") || combined.contains("bank") || combined.contains("unauthorized transaction") || combined.contains("otp")) {
            riskScore += 45
            threatType = "Banking Smishing / Social Engineering"
            indicators.add("Banking urgency pattern detected")
        }

        // 2. Extract and evaluate URLs
        val urlRegex = Regex("""https?://[^\s]+""")
        val urls = urlRegex.findAll(combined).map { it.value }.toList()
        for (url in urls) {
            val urlRes = scanUrlUseCase(url)
            urlRes.onSuccess { threat ->
                if (threat.verdict != Verdict.SAFE) {
                    riskScore = maxOf(riskScore, threat.riskScore)
                    threatType = "Malicious Link in Message"
                    indicators.add("Contains flagged URL: $url")
                }
            }
        }

        if (riskScore >= 35) {
            val threatLevel = if (riskScore >= 75) ThreatLevel.CRITICAL else ThreatLevel.HIGH
            val verdict = if (riskScore >= 70) Verdict.MALICIOUS else Verdict.SUSPICIOUS
            val threat = Threat(
                id = UUID.randomUUID().toString(),
                moduleType = ModuleType.NOTIFICATION,
                threatLevel = threatLevel,
                verdict = verdict,
                riskScore = riskScore,
                title = "$threatType ($appLabel)",
                description = "Suspicious message intercepted from $appLabel: \"${text.take(60)}...\"",
                actionTaken = "BLOCKED",
                rawPayload = text,
                indicators = indicators,
                timestampMs = System.currentTimeMillis()
            )
            threatRepository.recordThreat(threat)
            return threat
        }
        return null
    }
}

class GetDashboardSummaryUseCase @Inject constructor(
    private val threatRepository: ThreatRepository,
    private val deviceSecurityRepository: DeviceSecurityRepository
) {
    fun getSecurityScore(): Flow<SecurityScore> = deviceSecurityRepository.getSecurityScore()
    fun getRecentThreats(): Flow<List<Threat>> = threatRepository.getRecentThreats(limit = 5)
}
