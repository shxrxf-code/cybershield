package com.shieldguard.ai.data.local;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\'\u0018\u00002\u00020\u0001B\u0005\u00a2\u0006\u0002\u0010\u0002J\b\u0010\u0003\u001a\u00020\u0004H&J\b\u0010\u0005\u001a\u00020\u0006H&\u00a8\u0006\u0007"}, d2 = {"Lcom/shieldguard/ai/data/local/ShieldGuardDatabase;", "Landroidx/room/RoomDatabase;", "()V", "scanHistoryDao", "Lcom/shieldguard/ai/data/local/dao/ScanHistoryDao;", "threatDao", "Lcom/shieldguard/ai/data/local/dao/ThreatDao;", "app_debug"})
@androidx.room.Database(entities = {com.shieldguard.ai.data.local.entity.ThreatEntity.class, com.shieldguard.ai.data.local.entity.ScanHistoryEntity.class}, version = 1, exportSchema = false)
@androidx.room.TypeConverters(value = {com.shieldguard.ai.data.local.Converters.class})
public abstract class ShieldGuardDatabase extends androidx.room.RoomDatabase {
    
    public ShieldGuardDatabase() {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public abstract com.shieldguard.ai.data.local.dao.ThreatDao threatDao();
    
    @org.jetbrains.annotations.NotNull()
    public abstract com.shieldguard.ai.data.local.dao.ScanHistoryDao scanHistoryDao();
}