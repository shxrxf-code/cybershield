package com.shieldguard.ai.service;

@javax.inject.Singleton()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\u0007\b\u0007\u00a2\u0006\u0002\u0010\u0002J\u000e\u0010\n\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\rR\u0014\u0010\u0003\u001a\b\u0012\u0004\u0012\u00020\u00050\u0004X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0017\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\u00050\u0007\u00a2\u0006\b\n\u0000\u001a\u0004\b\b\u0010\t\u00a8\u0006\u000e"}, d2 = {"Lcom/shieldguard/ai/service/NotificationMonitorHub;", "", "()V", "_state", "Lkotlinx/coroutines/flow/MutableStateFlow;", "Lcom/shieldguard/ai/service/NotificationMonitorState;", "state", "Lkotlinx/coroutines/flow/StateFlow;", "getState", "()Lkotlinx/coroutines/flow/StateFlow;", "recordNotification", "", "event", "Lcom/shieldguard/ai/service/ScannedNotificationEvent;", "app_debug"})
public final class NotificationMonitorHub {
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.flow.MutableStateFlow<com.shieldguard.ai.service.NotificationMonitorState> _state = null;
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.flow.StateFlow<com.shieldguard.ai.service.NotificationMonitorState> state = null;
    
    @javax.inject.Inject()
    public NotificationMonitorHub() {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final kotlinx.coroutines.flow.StateFlow<com.shieldguard.ai.service.NotificationMonitorState> getState() {
        return null;
    }
    
    public final void recordNotification(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.service.ScannedNotificationEvent event) {
    }
}