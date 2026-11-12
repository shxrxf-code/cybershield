package com.shieldguard.ai.domain.repository

import com.shieldguard.ai.domain.model.AppThreatInfo
import com.shieldguard.ai.domain.model.DeviceAudit
import com.shieldguard.ai.domain.model.ScanResult
import com.shieldguard.ai.domain.model.SecurityScore
import com.shieldguard.ai.domain.model.Threat
import kotlinx.coroutines.flow.Flow

interface ThreatRepository {
    fun getAllThreats(): Flow<List<Threat>>
    fun getRecentThreats(limit: Int = 10): Flow<List<Threat>>
    suspend fun recordThreat(threat: Threat)
    suspend fun resolveThreat(threatId: String)
    suspend fun clearThreatsByModule(moduleType: com.shieldguard.ai.domain.model.ModuleType)
    suspend fun clearThreats()
}

interface ScannerRepository {
    suspend fun scanUrl(url: String, deepAnalysis: Boolean = true): Result<Threat>
    suspend fun scanApk(packageInfo: AppThreatInfo): Result<AppThreatInfo>
    suspend fun scanDocument(filePath: String): Result<Threat>
    suspend fun recordScanResult(scanResult: ScanResult)
    fun getScanHistory(): Flow<List<ScanResult>>
}

interface DeviceSecurityRepository {
    suspend fun performDeviceAudit(): DeviceAudit
    fun getSecurityScore(): Flow<SecurityScore>
    suspend fun updateProtectionStatus(vpnEnabled: Boolean, notifEnabled: Boolean)
    suspend fun updateScanMetrics(appsCount: Int, filesCount: Int, securityScore: Int)
}
