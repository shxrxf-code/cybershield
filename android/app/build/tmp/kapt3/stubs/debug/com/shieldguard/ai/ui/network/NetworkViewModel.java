package com.shieldguard.ai.ui.network;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0007\u0018\u00002\u00020\u0001B\u0017\b\u0007\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0002\u0010\u0006J\u000e\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u0014J\u000e\u0010\u0015\u001a\u00020\u00122\u0006\u0010\u0016\u001a\u00020\tJ\u000e\u0010\u0017\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u0014J\u000e\u0010\u0018\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u0014R\u0014\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\t0\bX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0017\u0010\n\u001a\b\u0012\u0004\u0012\u00020\t0\u000b\u00a2\u0006\b\n\u0000\u001a\u0004\b\f\u0010\rR\u0017\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\u000f0\u000b\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0010\u0010\rR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u0019"}, d2 = {"Lcom/shieldguard/ai/ui/network/NetworkViewModel;", "Landroidx/lifecycle/ViewModel;", "networkTrafficMonitor", "Lcom/shieldguard/ai/service/NetworkTrafficMonitor;", "preferencesManager", "Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;", "(Lcom/shieldguard/ai/service/NetworkTrafficMonitor;Lcom/shieldguard/ai/data/local/EncryptedPreferencesManager;)V", "_blockInput", "Lkotlinx/coroutines/flow/MutableStateFlow;", "", "blockInput", "Lkotlinx/coroutines/flow/StateFlow;", "getBlockInput", "()Lkotlinx/coroutines/flow/StateFlow;", "monitorState", "Lcom/shieldguard/ai/service/NetworkMonitorState;", "getMonitorState", "addBlockRule", "", "context", "Landroid/content/Context;", "onBlockInputChanged", "value", "startFirewallService", "stopFirewallService", "app_debug"})
@dagger.hilt.android.lifecycle.HiltViewModel()
public final class NetworkViewModel extends androidx.lifecycle.ViewModel {
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.service.NetworkTrafficMonitor networkTrafficMonitor = null;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.data.local.EncryptedPreferencesManager preferencesManager = null;
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.flow.StateFlow<com.shieldguard.ai.service.NetworkMonitorState> monitorState = null;
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.flow.MutableStateFlow<java.lang.String> _blockInput = null;
    @org.jetbrains.annotations.NotNull()
    private final kotlinx.coroutines.flow.StateFlow<java.lang.String> blockInput = null;
    
    @javax.inject.Inject()
    public NetworkViewModel(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.service.NetworkTrafficMonitor networkTrafficMonitor, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.local.EncryptedPreferencesManager preferencesManager) {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final kotlinx.coroutines.flow.StateFlow<com.shieldguard.ai.service.NetworkMonitorState> getMonitorState() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final kotlinx.coroutines.flow.StateFlow<java.lang.String> getBlockInput() {
        return null;
    }
    
    public final void onBlockInputChanged(@org.jetbrains.annotations.NotNull()
    java.lang.String value) {
    }
    
    public final void startFirewallService(@org.jetbrains.annotations.NotNull()
    android.content.Context context) {
    }
    
    public final void stopFirewallService(@org.jetbrains.annotations.NotNull()
    android.content.Context context) {
    }
    
    public final void addBlockRule(@org.jetbrains.annotations.NotNull()
    android.content.Context context) {
    }
}