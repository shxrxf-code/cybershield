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
import com.shieldguard.ai.scanner.LocalUrlThreatAnalyzer
import com.shieldguard.ai.service.NotificationMonitorHub
import com.shieldguard.ai.service.ScannedNotificationEvent
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
    private val scanUrlUseCase: ScanUrlUseCase,
    private val localUrlThreatAnalyzer: LocalUrlThreatAnalyzer,
    private val notificationMonitorHub: NotificationMonitorHub
) {
    suspend operator fun invoke(
        packageName: String,
        appLabel: String,
        title: String,
        text: String
    ): Threat? {
        val combined = "$title\n$text"
        val combinedLower = combined.lowercase()
        var riskScore = 0
        var threatType: String? = null
        val indicators = mutableListOf<String>()

        // 1. Phishing & Scam Lures Detection
        if (combinedLower.contains("winner") || combinedLower.contains("lottery") || combinedLower.contains("won $") || combinedLower.contains("claim prize")) {
            riskScore += 45
            threatType = "Fake Giveaway / Lottery Scam"
            indicators.add("Lottery lure pattern detected")
        }

        if (combinedLower.contains("bitcoin") || combinedLower.contains("crypto giveaway") || combinedLower.contains("airdrop") || combinedLower.contains("usdt")) {
            riskScore += 50
            threatType = "Cryptocurrency Scam"
            indicators.add("Crypto drain lure pattern detected")
        }

        if (combinedLower.contains("suspended") || combinedLower.contains("bank") || combinedLower.contains("unauthorized transaction") || combinedLower.contains("otp")) {
            riskScore += 45
            threatType = "Banking Smishing / Social Engineering"
            indicators.add("Banking urgency pattern detected")
        }

        // 2. Extract and evaluate ALL URLs (including MessagingStyle chats & scheme-less domains)
        val urls = localUrlThreatAnalyzer.extractUrls(combined)
        for (url in urls) {
            val urlRes = scanUrlUseCase(url)
            urlRes.onSuccess { threat ->
                if (threat.verdict != Verdict.SAFE) {
                    riskScore = maxOf(riskScore, threat.riskScore)
                    threatType = if (threat.verdict == Verdict.MALICIOUS) "Malicious Link in Chat" else "Suspicious Link in Chat"
                    indicators.add("Flagged URL ($url): ${threat.description}")
                }
            }
        }

        val finalVerdict = when {
            riskScore >= 70 -> Verdict.MALICIOUS
            riskScore >= 35 -> Verdict.SUSPICIOUS
            else -> Verdict.SAFE
        }

        notificationMonitorHub.recordNotification(
            ScannedNotificationEvent(
                id = UUID.randomUUID().toString(),
                packageName = packageName,
                appLabel = appLabel,
                senderOrTitle = title.ifBlank { appLabel },
                messageSnippet = text.take(140),
                detectedUrls = urls,
                verdict = finalVerdict,
                riskScore = riskScore,
                timestampMs = System.currentTimeMillis()
            )
        )

        if (riskScore >= 35) {
            val threatLevel = if (riskScore >= 75) ThreatLevel.CRITICAL else ThreatLevel.HIGH
            val threat = Threat(
                id = UUID.randomUUID().toString(),
                moduleType = ModuleType.NOTIFICATION,
                threatLevel = threatLevel,
                verdict = finalVerdict,
                riskScore = riskScore,
                title = "${threatType ?: "Suspicious Message"} ($appLabel)",
                description = "Intercepted from $appLabel: \"${text.take(80)}\"",
                actionTaken = if (finalVerdict == Verdict.MALICIOUS) "BLOCKED_ALERT" else "WARNED",
                rawPayload = if (urls.isNotEmpty()) urls.joinToString(", ") else text,
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
