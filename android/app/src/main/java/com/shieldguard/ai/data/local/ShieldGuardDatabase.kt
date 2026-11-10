package com.shieldguard.ai.data.local

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.shieldguard.ai.data.local.dao.ScanHistoryDao
import com.shieldguard.ai.data.local.dao.ThreatDao
import com.shieldguard.ai.data.local.entity.ScanHistoryEntity
import com.shieldguard.ai.data.local.entity.ThreatEntity

@Database(
    entities = [
        ThreatEntity::class,
        ScanHistoryEntity::class
    ],
    version = 1,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class ShieldGuardDatabase : RoomDatabase() {
    abstract fun threatDao(): ThreatDao
    abstract fun scanHistoryDao(): ScanHistoryDao
}
