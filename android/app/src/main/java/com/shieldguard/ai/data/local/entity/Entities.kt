package com.shieldguard.ai.data.local.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import com.shieldguard.ai.domain.model.ModuleType
import com.shieldguard.ai.domain.model.Threat
import com.shieldguard.ai.domain.model.ThreatLevel
import com.shieldguard.ai.domain.model.Verdict

@Entity(
    tableName = "threats",
    indices = [
        Index("moduleType"),
        Index("threatLevel"),
        Index("timestampMs")
    ]
)
data class ThreatEntity(
    @PrimaryKey
    val id: String,
    val moduleType: String,
    val threatLevel: String,
    val verdict: String,
    val riskScore: Int,
    val title: String,
    val description: String,
    val actionTaken: String,
    val rawPayload: String,
    val indicators: List<String>,
    val timestampMs: Long
) {
    fun toDomain(): Threat = Threat(
        id = id,
        moduleType = runCatching { ModuleType.valueOf(moduleType) }.getOrDefault(ModuleType.URL),
        threatLevel = runCatching { ThreatLevel.valueOf(threatLevel) }.getOrDefault(ThreatLevel.LOW),
        verdict = runCatching { Verdict.valueOf(verdict) }.getOrDefault(Verdict.SAFE),
        riskScore = riskScore,
        title = title,
        description = description,
        actionTaken = actionTaken,
        rawPayload = rawPayload,
        indicators = indicators,
        timestampMs = timestampMs
    )

    companion object {
        fun fromDomain(threat: Threat): ThreatEntity = ThreatEntity(
            id = threat.id,
            moduleType = threat.moduleType.name,
            threatLevel = threat.threatLevel.name,
            verdict = threat.verdict.name,
            riskScore = threat.riskScore,
            title = threat.title,
            description = threat.description,
            actionTaken = threat.actionTaken,
            rawPayload = threat.rawPayload,
            indicators = threat.indicators,
            timestampMs = threat.timestampMs
        )
    }
}

@Entity(
    tableName = "scan_history",
    indices = [Index("timestampMs")]
)
data class ScanHistoryEntity(
    @PrimaryKey
    val scanId: String,
    val scanType: String,
    val status: String,
    val riskScore: Int,
    val findingsCount: Int,
    val scannedItemsCount: Int,
    val findings: List<String>,
    val durationMs: Long,
    val timestampMs: Long
)
