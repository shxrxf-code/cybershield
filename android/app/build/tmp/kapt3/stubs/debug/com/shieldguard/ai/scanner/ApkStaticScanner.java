package com.shieldguard.ai.scanner;

@javax.inject.Singleton()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000Z\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010$\n\u0002\u0010\u000e\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010 \n\u0000\n\u0002\u0010\"\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\u0011\b\u0007\u0012\b\b\u0001\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0002\u0010\u0004J\u0016\u0010\u000e\u001a\u00020\u000f2\u0006\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u0013J\u001a\u0010\u0014\u001a\u0004\u0018\u00010\u00072\u0006\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0015\u001a\u00020\u0007H\u0002Jg\u0010\u0016\u001a\b\u0012\u0004\u0012\u00020\u000f0\u000b2\b\b\u0002\u0010\u0017\u001a\u00020\u00182O\b\u0002\u0010\u0019\u001aI\u0012\u0013\u0012\u00110\b\u00a2\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\u001d\u0012\u0013\u0012\u00110\b\u00a2\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\u001e\u0012\u0013\u0012\u00110\u0007\u00a2\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\u001f\u0012\u0004\u0012\u00020 \u0018\u00010\u001aR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u001a\u0010\u0005\u001a\u000e\u0012\u0004\u0012\u00020\u0007\u0012\u0004\u0012\u00020\b0\u0006X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u001a\u0010\t\u001a\u000e\u0012\u0004\u0012\u00020\u0007\u0012\u0004\u0012\u00020\b0\u0006X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\n\u001a\b\u0012\u0004\u0012\u00020\u00070\u000bX\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u00070\rX\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006!"}, d2 = {"Lcom/shieldguard/ai/scanner/ApkStaticScanner;", "", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "highRiskAbusePermissions", "", "", "", "standardRuntimePermissions", "trustedOemPrefixes", "", "trustedStoreInstallers", "", "analyzePackage", "Lcom/shieldguard/ai/domain/model/AppThreatInfo;", "pm", "Landroid/content/pm/PackageManager;", "pkg", "Landroid/content/pm/PackageInfo;", "getInstallerPackage", "packageName", "scanAllInstalledApps", "includeSystemApps", "", "onProgress", "Lkotlin/Function3;", "Lkotlin/ParameterName;", "name", "current", "total", "appName", "", "app_debug"})
public final class ApkStaticScanner {
    @org.jetbrains.annotations.NotNull()
    private final android.content.Context context = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.Set<java.lang.String> trustedStoreInstallers = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> trustedOemPrefixes = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.Map<java.lang.String, java.lang.Integer> highRiskAbusePermissions = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.Map<java.lang.String, java.lang.Integer> standardRuntimePermissions = null;
    
    @javax.inject.Inject()
    public ApkStaticScanner(@dagger.hilt.android.qualifiers.ApplicationContext()
    @org.jetbrains.annotations.NotNull()
    android.content.Context context) {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<com.shieldguard.ai.domain.model.AppThreatInfo> scanAllInstalledApps(boolean includeSystemApps, @org.jetbrains.annotations.Nullable()
    kotlin.jvm.functions.Function3<? super java.lang.Integer, ? super java.lang.Integer, ? super java.lang.String, kotlin.Unit> onProgress) {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.AppThreatInfo analyzePackage(@org.jetbrains.annotations.NotNull()
    android.content.pm.PackageManager pm, @org.jetbrains.annotations.NotNull()
    android.content.pm.PackageInfo pkg) {
        return null;
    }
    
    private final java.lang.String getInstallerPackage(android.content.pm.PackageManager pm, java.lang.String packageName) {
        return null;
    }
}