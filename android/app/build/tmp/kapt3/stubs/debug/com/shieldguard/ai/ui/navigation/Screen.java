package com.shieldguard.ai.ui.navigation;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\b6\u0018\u00002\u00020\u0001:\u0005\t\n\u000b\f\rB\u0017\b\u0004\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0002\u0010\u0005R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0006\u0010\u0007R\u0011\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b\b\u0010\u0007\u0082\u0001\u0005\u000e\u000f\u0010\u0011\u0012\u00a8\u0006\u0013"}, d2 = {"Lcom/shieldguard/ai/ui/navigation/Screen;", "", "route", "", "title", "(Ljava/lang/String;Ljava/lang/String;)V", "getRoute", "()Ljava/lang/String;", "getTitle", "AppScanner", "Dashboard", "NetworkProtection", "Reports", "UrlScanner", "Lcom/shieldguard/ai/ui/navigation/Screen$AppScanner;", "Lcom/shieldguard/ai/ui/navigation/Screen$Dashboard;", "Lcom/shieldguard/ai/ui/navigation/Screen$NetworkProtection;", "Lcom/shieldguard/ai/ui/navigation/Screen$Reports;", "Lcom/shieldguard/ai/ui/navigation/Screen$UrlScanner;", "app_debug"})
public abstract class Screen {
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String route = null;
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String title = null;
    
    private Screen(java.lang.String route, java.lang.String title) {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getRoute() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getTitle() {
        return null;
    }
    
    @kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u00c6\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002\u00a2\u0006\u0002\u0010\u0002\u00a8\u0006\u0003"}, d2 = {"Lcom/shieldguard/ai/ui/navigation/Screen$AppScanner;", "Lcom/shieldguard/ai/ui/navigation/Screen;", "()V", "app_debug"})
    public static final class AppScanner extends com.shieldguard.ai.ui.navigation.Screen {
        @org.jetbrains.annotations.NotNull()
        public static final com.shieldguard.ai.ui.navigation.Screen.AppScanner INSTANCE = null;
        
        private AppScanner() {
        }
    }
    
    @kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u00c6\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002\u00a2\u0006\u0002\u0010\u0002\u00a8\u0006\u0003"}, d2 = {"Lcom/shieldguard/ai/ui/navigation/Screen$Dashboard;", "Lcom/shieldguard/ai/ui/navigation/Screen;", "()V", "app_debug"})
    public static final class Dashboard extends com.shieldguard.ai.ui.navigation.Screen {
        @org.jetbrains.annotations.NotNull()
        public static final com.shieldguard.ai.ui.navigation.Screen.Dashboard INSTANCE = null;
        
        private Dashboard() {
        }
    }
    
    @kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u00c6\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002\u00a2\u0006\u0002\u0010\u0002\u00a8\u0006\u0003"}, d2 = {"Lcom/shieldguard/ai/ui/navigation/Screen$NetworkProtection;", "Lcom/shieldguard/ai/ui/navigation/Screen;", "()V", "app_debug"})
    public static final class NetworkProtection extends com.shieldguard.ai.ui.navigation.Screen {
        @org.jetbrains.annotations.NotNull()
        public static final com.shieldguard.ai.ui.navigation.Screen.NetworkProtection INSTANCE = null;
        
        private NetworkProtection() {
        }
    }
    
    @kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u00c6\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002\u00a2\u0006\u0002\u0010\u0002\u00a8\u0006\u0003"}, d2 = {"Lcom/shieldguard/ai/ui/navigation/Screen$Reports;", "Lcom/shieldguard/ai/ui/navigation/Screen;", "()V", "app_debug"})
    public static final class Reports extends com.shieldguard.ai.ui.navigation.Screen {
        @org.jetbrains.annotations.NotNull()
        public static final com.shieldguard.ai.ui.navigation.Screen.Reports INSTANCE = null;
        
        private Reports() {
        }
    }
    
    @kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u00c6\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002\u00a2\u0006\u0002\u0010\u0002\u00a8\u0006\u0003"}, d2 = {"Lcom/shieldguard/ai/ui/navigation/Screen$UrlScanner;", "Lcom/shieldguard/ai/ui/navigation/Screen;", "()V", "app_debug"})
    public static final class UrlScanner extends com.shieldguard.ai.ui.navigation.Screen {
        @org.jetbrains.annotations.NotNull()
        public static final com.shieldguard.ai.ui.navigation.Screen.UrlScanner INSTANCE = null;
        
        private UrlScanner() {
        }
    }
}