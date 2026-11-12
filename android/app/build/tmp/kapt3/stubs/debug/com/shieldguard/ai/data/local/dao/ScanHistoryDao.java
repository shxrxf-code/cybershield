package com.shieldguard.ai.data.local.dao;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\bg\u0018\u00002\u00020\u0001J\u0014\u0010\u0002\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00050\u00040\u0003H\'J\u0016\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u0005H\u00a7@\u00a2\u0006\u0002\u0010\t\u00a8\u0006\n"}, d2 = {"Lcom/shieldguard/ai/data/local/dao/ScanHistoryDao;", "", "getAllScans", "Lkotlinx/coroutines/flow/Flow;", "", "Lcom/shieldguard/ai/data/local/entity/ScanHistoryEntity;", "insertScan", "", "scan", "(Lcom/shieldguard/ai/data/local/entity/ScanHistoryEntity;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "app_debug"})
@androidx.room.Dao()
public abstract interface ScanHistoryDao {
    
    @androidx.room.Query(value = "SELECT * FROM scan_history ORDER BY timestampMs DESC")
    @org.jetbrains.annotations.NotNull()
    public abstract kotlinx.coroutines.flow.Flow<java.util.List<com.shieldguard.ai.data.local.entity.ScanHistoryEntity>> getAllScans();
    
    @androidx.room.Insert(onConflict = 1)
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object insertScan(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.local.entity.ScanHistoryEntity scan, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super kotlin.Unit> $completion);
}