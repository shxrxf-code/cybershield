package com.shieldguard.ai.service;

@dagger.hilt.android.AndroidEntryPoint()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000H\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\b\u0007\u0018\u00002\u00020\u0001B\u0005\u00a2\u0006\u0002\u0010\u0002J\u0010\u0010\u0015\u001a\u00020\u00112\u0006\u0010\u0016\u001a\u00020\u0017H\u0002J\b\u0010\u0018\u001a\u00020\u0019H\u0016J\u0012\u0010\u001a\u001a\u00020\u00192\b\u0010\u001b\u001a\u0004\u0018\u00010\u001cH\u0016J\u0018\u0010\u001d\u001a\u00020\u00192\u0006\u0010\u001e\u001a\u00020\u00112\u0006\u0010\u001f\u001a\u00020\u0011H\u0002R\u001e\u0010\u0003\u001a\u00020\u00048\u0006@\u0006X\u0087.\u00a2\u0006\u000e\n\u0000\u001a\u0004\b\u0005\u0010\u0006\"\u0004\b\u0007\u0010\bR\u001e\u0010\t\u001a\u00020\n8\u0006@\u0006X\u0087.\u00a2\u0006\u000e\n\u0000\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000eR\u001a\u0010\u000f\u001a\u000e\u0012\u0004\u0012\u00020\u0011\u0012\u0004\u0012\u00020\u00120\u0010X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0013\u001a\u00020\u0014X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006 "}, d2 = {"Lcom/shieldguard/ai/service/NotificationMonitorService;", "Landroid/service/notification/NotificationListenerService;", "()V", "preferencesManager", "Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;", "getPreferencesManager", "()Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;", "setPreferencesManager", "(Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;)V", "processNotificationUseCase", "Lcom/shieldguard/ai/domain/usecase/ProcessNotificationUseCase;", "getProcessNotificationUseCase", "()Lcom/shieldguard/ai/domain/usecase/ProcessNotificationUseCase;", "setProcessNotificationUseCase", "(Lcom/shieldguard/ai/domain/usecase/ProcessNotificationUseCase;)V", "recentHashes", "Ljava/util/concurrent/ConcurrentHashMap;", "", "", "serviceScope", "Lkotlinx/coroutines/CoroutineScope;", "extractFullChatAndNotificationText", "extras", "Landroid/os/Bundle;", "onDestroy", "", "onNotificationPosted", "sbn", "Landroid/service/notification/StatusBarNotification;", "showThreatAlert", "title", "message", "app_debug"})
public final class NotificationMonitorService extends android.service.notification.NotificationListenerService {
    @javax.inject.Inject()
    public com.shieldguard.ai.domain.usecase.ProcessNotificationUseCase processNotificationUseCase;
    @javax.inject.Inject()
    public com.shieldguard.ai.data.local.EncryptedPreferencesManager preferencesManager;
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.CoroutineScope serviceScope = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.concurrent.ConcurrentHashMap<java.lang.String, java.lang.Long> recentHashes = null;
    
    public NotificationMonitorService() {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.usecase.ProcessNotificationUseCase getProcessNotificationUseCase() {
        return null;
    }
    
    public final void setProcessNotificationUseCase(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.usecase.ProcessNotificationUseCase p0) {
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.data.local.EncryptedPreferencesManager getPreferencesManager() {
        return null;
    }
    
    public final void setPreferencesManager(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.local.EncryptedPreferencesManager p0) {
    }
    
    @java.lang.Override()
    public void onNotificationPosted(@org.jetbrains.annotations.Nullable()
    android.service.notification.StatusBarNotification sbn) {
    }
    
    /**
     * Reads complete chat payloads from MessagingStyle bundles (WhatsApp, Telegram, Messages,
     * Instagram, Messenger), BigText, InboxStyle textLines, and standard text fields.
     */
    private final java.lang.String extractFullChatAndNotificationText(android.os.Bundle extras) {
        return null;
    }
    
    private final void showThreatAlert(java.lang.String title, java.lang.String message) {
    }
    
    @java.lang.Override()
    public void onDestroy() {
    }
}