package com.shieldguard.ai.data.remote.dto;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\b@\n\u0002\u0010\u000b\n\u0002\b\u0004\b\u0086\b\u0018\u00002\u00020\u0001B\u00fb\u0001\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\u0006\u0010\u0007\u001a\u00020\u0003\u0012\f\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00030\t\u0012\f\u0010\n\u001a\b\u0012\u0004\u0012\u00020\u00030\t\u0012\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\u00030\t\u0012\u0006\u0010\f\u001a\u00020\u0003\u0012\u0006\u0010\r\u001a\u00020\u0003\u0012\b\b\u0002\u0010\u000e\u001a\u00020\u0003\u0012\n\b\u0002\u0010\u000f\u001a\u0004\u0018\u00010\u0003\u0012\n\b\u0002\u0010\u0010\u001a\u0004\u0018\u00010\u0003\u0012\n\b\u0002\u0010\u0011\u001a\u0004\u0018\u00010\u0003\u0012\n\b\u0002\u0010\u0012\u001a\u0004\u0018\u00010\u0003\u0012\b\b\u0002\u0010\u0013\u001a\u00020\u0006\u0012\n\b\u0002\u0010\u0014\u001a\u0004\u0018\u00010\u0003\u0012\n\b\u0002\u0010\u0015\u001a\u0004\u0018\u00010\u0003\u0012\u000e\b\u0002\u0010\u0016\u001a\b\u0012\u0004\u0012\u00020\u00030\t\u0012\u000e\b\u0002\u0010\u0017\u001a\b\u0012\u0004\u0012\u00020\u00030\t\u0012\u000e\b\u0002\u0010\u0018\u001a\b\u0012\u0004\u0012\u00020\u00030\t\u0012\u000e\b\u0002\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00030\t\u00a2\u0006\u0002\u0010\u001aJ\t\u00103\u001a\u00020\u0003H\u00c6\u0003J\t\u00104\u001a\u00020\u0003H\u00c6\u0003J\u000b\u00105\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u00106\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u00107\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u00108\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\t\u00109\u001a\u00020\u0006H\u00c6\u0003J\u000b\u0010:\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010;\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000f\u0010<\u001a\b\u0012\u0004\u0012\u00020\u00030\tH\u00c6\u0003J\u000f\u0010=\u001a\b\u0012\u0004\u0012\u00020\u00030\tH\u00c6\u0003J\t\u0010>\u001a\u00020\u0003H\u00c6\u0003J\u000f\u0010?\u001a\b\u0012\u0004\u0012\u00020\u00030\tH\u00c6\u0003J\u000f\u0010@\u001a\b\u0012\u0004\u0012\u00020\u00030\tH\u00c6\u0003J\t\u0010A\u001a\u00020\u0006H\u00c6\u0003J\t\u0010B\u001a\u00020\u0003H\u00c6\u0003J\u000f\u0010C\u001a\b\u0012\u0004\u0012\u00020\u00030\tH\u00c6\u0003J\u000f\u0010D\u001a\b\u0012\u0004\u0012\u00020\u00030\tH\u00c6\u0003J\u000f\u0010E\u001a\b\u0012\u0004\u0012\u00020\u00030\tH\u00c6\u0003J\t\u0010F\u001a\u00020\u0003H\u00c6\u0003J\t\u0010G\u001a\u00020\u0003H\u00c6\u0003J\u0091\u0002\u0010H\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00032\b\b\u0002\u0010\u0005\u001a\u00020\u00062\b\b\u0002\u0010\u0007\u001a\u00020\u00032\u000e\b\u0002\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00030\t2\u000e\b\u0002\u0010\n\u001a\b\u0012\u0004\u0012\u00020\u00030\t2\u000e\b\u0002\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\u00030\t2\b\b\u0002\u0010\f\u001a\u00020\u00032\b\b\u0002\u0010\r\u001a\u00020\u00032\b\b\u0002\u0010\u000e\u001a\u00020\u00032\n\b\u0002\u0010\u000f\u001a\u0004\u0018\u00010\u00032\n\b\u0002\u0010\u0010\u001a\u0004\u0018\u00010\u00032\n\b\u0002\u0010\u0011\u001a\u0004\u0018\u00010\u00032\n\b\u0002\u0010\u0012\u001a\u0004\u0018\u00010\u00032\b\b\u0002\u0010\u0013\u001a\u00020\u00062\n\b\u0002\u0010\u0014\u001a\u0004\u0018\u00010\u00032\n\b\u0002\u0010\u0015\u001a\u0004\u0018\u00010\u00032\u000e\b\u0002\u0010\u0016\u001a\b\u0012\u0004\u0012\u00020\u00030\t2\u000e\b\u0002\u0010\u0017\u001a\b\u0012\u0004\u0012\u00020\u00030\t2\u000e\b\u0002\u0010\u0018\u001a\b\u0012\u0004\u0012\u00020\u00030\t2\u000e\b\u0002\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00030\tH\u00c6\u0001J\u0013\u0010I\u001a\u00020J2\b\u0010K\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010L\u001a\u00020\u0006H\u00d6\u0001J\t\u0010M\u001a\u00020\u0003H\u00d6\u0001R\u0016\u0010\u000e\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001b\u0010\u001cR\u0018\u0010\u000f\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001d\u0010\u001cR\u0018\u0010\u0014\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001e\u0010\u001cR\u0018\u0010\u0015\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001f\u0010\u001cR\u001c\u0010\u0016\u001a\b\u0012\u0004\u0012\u00020\u00030\t8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b \u0010!R\u001c\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00030\t8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\"\u0010!R\u0016\u0010\u0013\u001a\u00020\u00068\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b#\u0010$R\u001c\u0010\u0018\u001a\b\u0012\u0004\u0012\u00020\u00030\t8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b%\u0010!R\u001c\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00030\t8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b&\u0010!R\u0018\u0010\u0011\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\'\u0010\u001cR\u001c\u0010\u0017\u001a\b\u0012\u0004\u0012\u00020\u00030\t8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b(\u0010!R\u0016\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b)\u0010\u001cR\u0016\u0010\r\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b*\u0010\u001cR\u0016\u0010\f\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b+\u0010\u001cR\u0016\u0010\u0005\u001a\u00020\u00068\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b,\u0010$R\u001c\u0010\n\u001a\b\u0012\u0004\u0012\u00020\u00030\t8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b-\u0010!R\u001c\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\u00030\t8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b.\u0010!R\u0018\u0010\u0012\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b/\u0010\u001cR\u0016\u0010\u0007\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b0\u0010\u001cR\u0016\u0010\u0004\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b1\u0010\u001cR\u0018\u0010\u0010\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b2\u0010\u001c\u00a8\u0006N"}, d2 = {"Lcom/shieldguard/ai/data/remote/dto/ApkScanResponseDto;", "", "packageName", "", "verdict", "riskScore", "", "threatLevel", "detectedFamilies", "", "riskyPermissions", "suspiciousBehaviors", "reputationStatus", "recommendation", "analysisEngine", "appName", "versionName", "minSdk", "targetSdk", "dexCount", "certSha256", "certSubject", "dangerousApis", "nativeLibraries", "embeddedUrls", "exportedComponents", "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;)V", "getAnalysisEngine", "()Ljava/lang/String;", "getAppName", "getCertSha256", "getCertSubject", "getDangerousApis", "()Ljava/util/List;", "getDetectedFamilies", "getDexCount", "()I", "getEmbeddedUrls", "getExportedComponents", "getMinSdk", "getNativeLibraries", "getPackageName", "getRecommendation", "getReputationStatus", "getRiskScore", "getRiskyPermissions", "getSuspiciousBehaviors", "getTargetSdk", "getThreatLevel", "getVerdict", "getVersionName", "component1", "component10", "component11", "component12", "component13", "component14", "component15", "component16", "component17", "component18", "component19", "component2", "component20", "component21", "component3", "component4", "component5", "component6", "component7", "component8", "component9", "copy", "equals", "", "other", "hashCode", "toString", "app_debug"})
public final class ApkScanResponseDto {
    @com.google.gson.annotations.SerializedName(value = "package_name")
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String packageName = null;
    @com.google.gson.annotations.SerializedName(value = "verdict")
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String verdict = null;
    @com.google.gson.annotations.SerializedName(value = "risk_score")
    private final int riskScore = 0;
    @com.google.gson.annotations.SerializedName(value = "threat_level")
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String threatLevel = null;
    @com.google.gson.annotations.SerializedName(value = "detected_families")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> detectedFamilies = null;
    @com.google.gson.annotations.SerializedName(value = "risky_permissions")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> riskyPermissions = null;
    @com.google.gson.annotations.SerializedName(value = "suspicious_behaviors")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> suspiciousBehaviors = null;
    @com.google.gson.annotations.SerializedName(value = "reputation_status")
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String reputationStatus = null;
    @com.google.gson.annotations.SerializedName(value = "recommendation")
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String recommendation = null;
    @com.google.gson.annotations.SerializedName(value = "analysis_engine")
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String analysisEngine = null;
    @com.google.gson.annotations.SerializedName(value = "app_name")
    @org.jetbrains.annotations.Nullable()
    private final java.lang.String appName = null;
    @com.google.gson.annotations.SerializedName(value = "version_name")
    @org.jetbrains.annotations.Nullable()
    private final java.lang.String versionName = null;
    @com.google.gson.annotations.SerializedName(value = "min_sdk")
    @org.jetbrains.annotations.Nullable()
    private final java.lang.String minSdk = null;
    @com.google.gson.annotations.SerializedName(value = "target_sdk")
    @org.jetbrains.annotations.Nullable()
    private final java.lang.String targetSdk = null;
    @com.google.gson.annotations.SerializedName(value = "dex_count")
    private final int dexCount = 0;
    @com.google.gson.annotations.SerializedName(value = "cert_sha256")
    @org.jetbrains.annotations.Nullable()
    private final java.lang.String certSha256 = null;
    @com.google.gson.annotations.SerializedName(value = "cert_subject")
    @org.jetbrains.annotations.Nullable()
    private final java.lang.String certSubject = null;
    @com.google.gson.annotations.SerializedName(value = "dangerous_apis")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> dangerousApis = null;
    @com.google.gson.annotations.SerializedName(value = "native_libraries")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> nativeLibraries = null;
    @com.google.gson.annotations.SerializedName(value = "embedded_urls")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> embeddedUrls = null;
    @com.google.gson.annotations.SerializedName(value = "exported_components")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> exportedComponents = null;
    
    public ApkScanResponseDto(@org.jetbrains.annotations.NotNull()
    java.lang.String packageName, @org.jetbrains.annotations.NotNull()
    java.lang.String verdict, int riskScore, @org.jetbrains.annotations.NotNull()
    java.lang.String threatLevel, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> detectedFamilies, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> riskyPermissions, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> suspiciousBehaviors, @org.jetbrains.annotations.NotNull()
    java.lang.String reputationStatus, @org.jetbrains.annotations.NotNull()
    java.lang.String recommendation, @org.jetbrains.annotations.NotNull()
    java.lang.String analysisEngine, @org.jetbrains.annotations.Nullable()
    java.lang.String appName, @org.jetbrains.annotations.Nullable()
    java.lang.String versionName, @org.jetbrains.annotations.Nullable()
    java.lang.String minSdk, @org.jetbrains.annotations.Nullable()
    java.lang.String targetSdk, int dexCount, @org.jetbrains.annotations.Nullable()
    java.lang.String certSha256, @org.jetbrains.annotations.Nullable()
    java.lang.String certSubject, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> dangerousApis, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> nativeLibraries, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> embeddedUrls, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> exportedComponents) {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getPackageName() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getVerdict() {
        return null;
    }
    
    public final int getRiskScore() {
        return 0;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getThreatLevel() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getDetectedFamilies() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getRiskyPermissions() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getSuspiciousBehaviors() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getReputationStatus() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getRecommendation() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getAnalysisEngine() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String getAppName() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String getVersionName() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String getMinSdk() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String getTargetSdk() {
        return null;
    }
    
    public final int getDexCount() {
        return 0;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String getCertSha256() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String getCertSubject() {
        return null;
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
    public final java.util.List<java.lang.String> getExportedComponents() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component1() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component10() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String component11() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String component12() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String component13() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String component14() {
        return null;
    }
    
    public final int component15() {
        return 0;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String component16() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String component17() {
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
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component20() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component21() {
        return null;
    }
    
    public final int component3() {
        return 0;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component4() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component5() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component6() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component7() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component8() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component9() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.data.remote.dto.ApkScanResponseDto copy(@org.jetbrains.annotations.NotNull()
    java.lang.String packageName, @org.jetbrains.annotations.NotNull()
    java.lang.String verdict, int riskScore, @org.jetbrains.annotations.NotNull()
    java.lang.String threatLevel, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> detectedFamilies, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> riskyPermissions, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> suspiciousBehaviors, @org.jetbrains.annotations.NotNull()
    java.lang.String reputationStatus, @org.jetbrains.annotations.NotNull()
    java.lang.String recommendation, @org.jetbrains.annotations.NotNull()
    java.lang.String analysisEngine, @org.jetbrains.annotations.Nullable()
    java.lang.String appName, @org.jetbrains.annotations.Nullable()
    java.lang.String versionName, @org.jetbrains.annotations.Nullable()
    java.lang.String minSdk, @org.jetbrains.annotations.Nullable()
    java.lang.String targetSdk, int dexCount, @org.jetbrains.annotations.Nullable()
    java.lang.String certSha256, @org.jetbrains.annotations.Nullable()
    java.lang.String certSubject, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> dangerousApis, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> nativeLibraries, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> embeddedUrls, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> exportedComponents) {
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