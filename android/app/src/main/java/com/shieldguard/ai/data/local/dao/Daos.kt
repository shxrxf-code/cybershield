package com.shieldguard.ai.data.local.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.shieldguard.ai.data.local.entity.ScanHistoryEntity
import com.shieldguard.ai.data.local.entity.ThreatEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ThreatDao {
    @Query("SELECT * FROM threats ORDER BY timestampMs DESC")
    fun getAllThreats(): Flow<List<ThreatEntity>>

    @Query("SELECT * FROM threats ORDER BY timestampMs DESC LIMIT :limit")
    fun getRecentThreats(limit: Int): Flow<List<ThreatEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertThreat(threat: ThreatEntity)

    @Query("DELETE FROM threats WHERE id = :threatId")
    suspend fun deleteThreat(threatId: String)

    @Query("DELETE FROM threats WHERE moduleType = :moduleType")
    suspend fun deleteThreatsByModule(moduleType: String)

    @Query("DELETE FROM threats")
    suspend fun clearAllThreats()

    @Query("SELECT COUNT(*) FROM threats")
    fun getThreatsCount(): Flow<Int>
}

@Dao
interface ScanHistoryDao {
    @Query("SELECT * FROM scan_history ORDER BY timestampMs DESC")
    fun getAllScans(): Flow<List<ScanHistoryEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScan(scan: ScanHistoryEntity)
}
