package com.shieldguard.ai.domain.model;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\b=\b\u0086\b\u0018\u00002\u00020\u0001B\u00d5\u0001\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\u0006\u0010\u0007\u001a\u00020\b\u0012\u0006\u0010\t\u001a\u00020\n\u0012\u0006\u0010\u000b\u001a\u00020\f\u0012\u0006\u0010\r\u001a\u00020\u000e\u0012\f\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010\u0012\f\u0010\u0011\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010\u0012\f\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010\u0012\u0006\u0010\u0013\u001a\u00020\u0003\u0012\n\b\u0002\u0010\u0014\u001a\u0004\u0018\u00010\u0003\u0012\b\b\u0002\u0010\u0015\u001a\u00020\b\u0012\b\b\u0002\u0010\u0016\u001a\u00020\u0003\u0012\n\b\u0002\u0010\u0017\u001a\u0004\u0018\u00010\u0003\u0012\b\b\u0002\u0010\u0018\u001a\u00020\f\u0012\u000e\b\u0002\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010\u0012\u000e\b\u0002\u0010\u001a\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010\u0012\u000e\b\u0002\u0010\u001b\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010\u00a2\u0006\u0002\u0010\u001cJ\t\u00105\u001a\u00020\u0003H\u00c6\u0003J\u000f\u00106\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010H\u00c6\u0003J\t\u00107\u001a\u00020\u0003H\u00c6\u0003J\u000b\u00108\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\t\u00109\u001a\u00020\bH\u00c6\u0003J\t\u0010:\u001a\u00020\u0003H\u00c6\u0003J\u000b\u0010;\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\t\u0010<\u001a\u00020\fH\u00c6\u0003J\u000f\u0010=\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010H\u00c6\u0003J\u000f\u0010>\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010H\u00c6\u0003J\u000f\u0010?\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010H\u00c6\u0003J\t\u0010@\u001a\u00020\u0003H\u00c6\u0003J\t\u0010A\u001a\u00020\u0006H\u00c6\u0003J\t\u0010B\u001a\u00020\bH\u00c6\u0003J\t\u0010C\u001a\u00020\nH\u00c6\u0003J\t\u0010D\u001a\u00020\fH\u00c6\u0003J\t\u0010E\u001a\u00020\u000eH\u00c6\u0003J\u000f\u0010F\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010H\u00c6\u0003J\u000f\u0010G\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010H\u00c6\u0003J\u00ef\u0001\u0010H\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00032\b\b\u0002\u0010\u0005\u001a\u00020\u00062\b\b\u0002\u0010\u0007\u001a\u00020\b2\b\b\u0002\u0010\t\u001a\u00020\n2\b\b\u0002\u0010\u000b\u001a\u00020\f2\b\b\u0002\u0010\r\u001a\u00020\u000e2\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00030\u00102\u000e\b\u0002\u0010\u0011\u001a\b\u0012\u0004\u0012\u00020\u00030\u00102\u000e\b\u0002\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00030\u00102\b\b\u0002\u0010\u0013\u001a\u00020\u00032\n\b\u0002\u0010\u0014\u001a\u0004\u0018\u00010\u00032\b\b\u0002\u0010\u0015\u001a\u00020\b2\b\b\u0002\u0010\u0016\u001a\u00020\u00032\n\b\u0002\u0010\u0017\u001a\u0004\u0018\u00010\u00032\b\b\u0002\u0010\u0018\u001a\u00020\f2\u000e\b\u0002\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00030\u00102\u000e\b\u0002\u0010\u001a\u001a\b\u0012\u0004\u0012\u00020\u00030\u00102\u000e\b\u0002\u0010\u001b\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010H\u00c6\u0001J\u0013\u0010I\u001a\u00020\b2\b\u0010J\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010K\u001a\u00020\fH\u00d6\u0001J\t\u0010L\u001a\u00020\u0003H\u00d6\u0001R\u0011\u0010\u0016\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001d\u0010\u001eR\u0013\u0010\u0014\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001f\u0010\u001eR\u0011\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b \u0010\u001eR\u0017\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010\u00a2\u0006\b\n\u0000\u001a\u0004\b!\u0010\"R\u0013\u0010\u0017\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b#\u0010\u001eR\u0017\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010\u00a2\u0006\b\n\u0000\u001a\u0004\b$\u0010\"R\u0017\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010\u00a2\u0006\b\n\u0000\u001a\u0004\b%\u0010\"R\u0011\u0010\u0018\u001a\u00020\f\u00a2\u0006\b\n\u0000\u001a\u0004\b&\u0010\'R\u0017\u0010\u001b\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010\u00a2\u0006\b\n\u0000\u001a\u0004\b(\u0010\"R\u0011\u0010\u0007\u001a\u00020\b\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0007\u0010)R\u0011\u0010\u0015\u001a\u00020\b\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0015\u0010)R\u0017\u0010\u0011\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010\u00a2\u0006\b\n\u0000\u001a\u0004\b*\u0010\"R\u0017\u0010\u001a\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010\u00a2\u0006\b\n\u0000\u001a\u0004\b+\u0010\"R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b,\u0010\u001eR\u0011\u0010\u0013\u001a\u00020\u0003\u00a2\u0006\b\n\u0000\u001a\u0004\b-\u0010\u001eR\u0011\u0010\u000b\u001a\u00020\f\u00a2\u0006\b\n\u0000\u001a\u0004\b.\u0010\'R\u0011\u0010\r\u001a\u00020\u000e\u00a2\u0006\b\n\u0000\u001a\u0004\b/\u00100R\u0011\u0010\t\u001a\u00020\n\u00a2\u0006\b\n\u0000\u001a\u0004\b1\u00102R\u0011\u0010\u0005\u001a\u00020\u0006\u00a2\u0006\b\n\u0000\u001a\u0004\b3\u00104\u00a8\u0006M"}, d2 = {"Lcom/shieldguard/ai/domain/model/AppThreatInfo;", "", "packageName", "", "appName", "versionCode", "", "isSystemApp", "", "verdict", "Lcom/shieldguard/ai/domain/model/Verdict;", "riskScore", "", "threatLevel", "Lcom/shieldguard/ai/domain/model/ThreatLevel;", "dangerousPermissions", "", "malwareFamilies", "behaviors", "recommendation", "apkPath", "isTrustedStore", "analysisEngine", "certSha256", "dexCount", "dangerousApis", "nativeLibraries", "embeddedUrls", "(Ljava/lang/String;Ljava/lang/String;JZLcom/shieldguard/ai/domain/model/Verdict;ILcom/shieldguard/ai/domain/model/ThreatLevel;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;ILjava/util/List;Ljava/util/List;Ljava/util/List;)V", "getAnalysisEngine", "()Ljava/lang/String;", "getApkPath", "getAppName", "getBehaviors", "()Ljava/util/List;", "getCertSha256", "getDangerousApis", "getDangerousPermissions", "getDexCount", "()I", "getEmbeddedUrls", "()Z", "getMalwareFamilies", "getNativeLibraries", "getPackageName", "getRecommendation", "getRiskScore", "getThreatLevel", "()Lcom/shieldguard/ai/domain/model/ThreatLevel;", "getVerdict", "()Lcom/shieldguard/ai/domain/model/Verdict;", "getVersionCode", "()J", "component1", "component10", "component11", "component12", "component13", "component14", "component15", "component16", "component17", "component18", "component19", "component2", "component3", "component4", "component5", "component6", "component7", "component8", "component9", "copy", "equals", "other", "hashCode", "toString", "app_debug"})
public final class AppThreatInfo {
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String packageName = null;
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String appName = null;
    private final long versionCode = 0L;
    private final boolean isSystemApp = false;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.model.Verdict verdict = null;
    private final int riskScore = 0;
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.domain.model.ThreatLevel threatLevel = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> dangerousPermissions = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> malwareFamilies = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> behaviors = null;
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String recommendation = null;
    @org.jetbrains.annotations.Nullable()
    private final java.lang.String apkPath = null;
    private final boolean isTrustedStore = false;
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String analysisEngine = null;
    @org.jetbrains.annotations.Nullable()
    private final java.lang.String certSha256 = null;
    private final int dexCount = 0;
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> dangerousApis = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> nativeLibraries = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> embeddedUrls = null;
    
    public AppThreatInfo(@org.jetbrains.annotations.NotNull()
    java.lang.String packageName, @org.jetbrains.annotations.NotNull()
    java.lang.String appName, long versionCode, boolean isSystemApp, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.Verdict verdict, int riskScore, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.ThreatLevel threatLevel, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> dangerousPermissions, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> malwareFamilies, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> behaviors, @org.jetbrains.annotations.NotNull()
    java.lang.String recommendation, @org.jetbrains.annotations.Nullable()
    java.lang.String apkPath, boolean isTrustedStore, @org.jetbrains.annotations.NotNull()
    java.lang.String analysisEngine, @org.jetbrains.annotations.Nullable()
    java.lang.String certSha256, int dexCount, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> dangerousApis, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> nativeLibraries, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> embeddedUrls) {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getPackageName() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getAppName() {
        return null;
    }
    
    public final long getVersionCode() {
        return 0L;
    }
    
    public final boolean isSystemApp() {
        return false;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.Verdict getVerdict() {
        return null;
    }
    
    public final int getRiskScore() {
        return 0;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.ThreatLevel getThreatLevel() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getDangerousPermissions() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getMalwareFamilies() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getBehaviors() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getRecommendation() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String getApkPath() {
        return null;
    }
    
    public final boolean isTrustedStore() {
        return false;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getAnalysisEngine() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String getCertSha256() {
        return null;
    }
    
    public final int getDexCount() {
        return 0;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getDangerousApis() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getNativeLibraries() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getEmbeddedUrls() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component1() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component10() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component11() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String component12() {
        return null;
    }
    
    public final boolean component13() {
        return false;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component14() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String component15() {
        return null;
    }
    
    public final int component16() {
        return 0;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component17() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component18() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component19() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component2() {
        return null;
    }
    
    public final long component3() {
        return 0L;
    }
    
    public final boolean component4() {
        return false;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.Verdict component5() {
        return null;
    }
    
    public final int component6() {
        return 0;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.ThreatLevel component7() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component8() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component9() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.AppThreatInfo copy(@org.jetbrains.annotations.NotNull()
    java.lang.String packageName, @org.jetbrains.annotations.NotNull()
    java.lang.String appName, long versionCode, boolean isSystemApp, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.Verdict verdict, int riskScore, @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.domain.model.ThreatLevel threatLevel, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> dangerousPermissions, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> malwareFamilies, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> behaviors, @org.jetbrains.annotations.NotNull()
    java.lang.String recommendation, @org.jetbrains.annotations.Nullable()
    java.lang.String apkPath, boolean isTrustedStore, @org.jetbrains.annotations.NotNull()
    java.lang.String analysisEngine, @org.jetbrains.annotations.Nullable()
    java.lang.String certSha256, int dexCount, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> dangerousApis, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> nativeLibraries, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> embeddedUrls) {
        return null;
    }
    
    @java.lang.Override()
    public boolean equals(@org.jetbrains.annotations.Nullable()
    java.lang.Object other) {
        return false;
    }
    
    @java.lang.Override()
    public int hashCode() {
        return 0;
    }
    
    @java.lang.Override()
    @org.jetbrains.annotations.NotNull()
    public java.lang.String toString() {
        return null;
    }
}