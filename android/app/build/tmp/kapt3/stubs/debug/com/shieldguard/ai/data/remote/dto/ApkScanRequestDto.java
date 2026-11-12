package com.shieldguard.ai.data.remote.dto;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\t\n\u0000\n\u0002\u0010 \n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b \n\u0002\u0010\b\n\u0002\b\u0002\b\u0086\b\u0018\u00002\u00020\u0001B}\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\b\u0010\u0004\u001a\u0004\u0018\u00010\u0003\u0012\b\u0010\u0005\u001a\u0004\u0018\u00010\u0006\u0012\f\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\u00030\b\u0012\u000e\b\u0002\u0010\t\u001a\b\u0012\u0004\u0012\u00020\u00030\b\u0012\u000e\b\u0002\u0010\n\u001a\b\u0012\u0004\u0012\u00020\u00030\b\u0012\u000e\b\u0002\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\u00030\b\u0012\b\b\u0002\u0010\f\u001a\u00020\r\u0012\b\b\u0002\u0010\u000e\u001a\u00020\r\u0012\b\b\u0002\u0010\u000f\u001a\u00020\r\u00a2\u0006\u0002\u0010\u0010J\t\u0010\u001f\u001a\u00020\u0003H\u00c6\u0003J\t\u0010 \u001a\u00020\rH\u00c6\u0003J\u000b\u0010!\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u0010\u0010\"\u001a\u0004\u0018\u00010\u0006H\u00c6\u0003\u00a2\u0006\u0002\u0010\u001dJ\u000f\u0010#\u001a\b\u0012\u0004\u0012\u00020\u00030\bH\u00c6\u0003J\u000f\u0010$\u001a\b\u0012\u0004\u0012\u00020\u00030\bH\u00c6\u0003J\u000f\u0010%\u001a\b\u0012\u0004\u0012\u00020\u00030\bH\u00c6\u0003J\u000f\u0010&\u001a\b\u0012\u0004\u0012\u00020\u00030\bH\u00c6\u0003J\t\u0010\'\u001a\u00020\rH\u00c6\u0003J\t\u0010(\u001a\u00020\rH\u00c6\u0003J\u008e\u0001\u0010)\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\n\b\u0002\u0010\u0004\u001a\u0004\u0018\u00010\u00032\n\b\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u00062\u000e\b\u0002\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\u00030\b2\u000e\b\u0002\u0010\t\u001a\b\u0012\u0004\u0012\u00020\u00030\b2\u000e\b\u0002\u0010\n\u001a\b\u0012\u0004\u0012\u00020\u00030\b2\u000e\b\u0002\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\u00030\b2\b\b\u0002\u0010\f\u001a\u00020\r2\b\b\u0002\u0010\u000e\u001a\u00020\r2\b\b\u0002\u0010\u000f\u001a\u00020\rH\u00c6\u0001\u00a2\u0006\u0002\u0010*J\u0013\u0010+\u001a\u00020\r2\b\u0010,\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010-\u001a\u00020.H\u00d6\u0001J\t\u0010/\u001a\u00020\u0003H\u00d6\u0001R\u0018\u0010\u0004\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0011\u0010\u0012R\u001c\u0010\t\u001a\b\u0012\u0004\u0012\u00020\u00030\b8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0013\u0010\u0014R\u001c\u0010\n\u001a\b\u0012\u0004\u0012\u00020\u00030\b8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0015\u0010\u0014R\u0016\u0010\f\u001a\u00020\r8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\f\u0010\u0016R\u001c\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\u00030\b8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0017\u0010\u0014R\u0016\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0018\u0010\u0012R\u001c\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\u00030\b8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0019\u0010\u0014R\u0016\u0010\u000e\u001a\u00020\r8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001a\u0010\u0016R\u0016\u0010\u000f\u001a\u00020\r8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001b\u0010\u0016R\u001a\u0010\u0005\u001a\u0004\u0018\u00010\u00068\u0006X\u0087\u0004\u00a2\u0006\n\n\u0002\u0010\u001e\u001a\u0004\b\u001c\u0010\u001d\u00a8\u00060"}, d2 = {"Lcom/shieldguard/ai/data/remote/dto/ApkScanRequestDto;", "", "packageName", "", "appName", "versionCode", "", "permissions", "", "dangerousApis", "embeddedUrls", "nativeLibraries", "isDebuggable", "", "usesAccessibility", "usesOverlay", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Long;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;ZZZ)V", "getAppName", "()Ljava/lang/String;", "getDangerousApis", "()Ljava/util/List;", "getEmbeddedUrls", "()Z", "getNativeLibraries", "getPackageName", "getPermissions", "getUsesAccessibility", "getUsesOverlay", "getVersionCode", "()Ljava/lang/Long;", "Ljava/lang/Long;", "component1", "component10", "component2", "component3", "component4", "component5", "component6", "component7", "component8", "component9", "copy", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Long;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;ZZZ)Lcom/shieldguard/ai/data/remote/dto/ApkScanRequestDto;", "equals", "other", "hashCode", "", "toString", "app_debug"})
public final class ApkScanRequestDto {
    @com.google.gson.annotations.SerializedName(value = "package_name")
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String packageName = null;
    @com.google.gson.annotations.SerializedName(value = "app_name")
    @org.jetbrains.annotations.Nullable()
    private final java.lang.String appName = null;
    @com.google.gson.annotations.SerializedName(value = "version_code")
    @org.jetbrains.annotations.Nullable()
    private final java.lang.Long versionCode = null;
    @com.google.gson.annotations.SerializedName(value = "permissions")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> permissions = null;
    @com.google.gson.annotations.SerializedName(value = "dangerous_apis")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> dangerousApis = null;
    @com.google.gson.annotations.SerializedName(value = "embedded_urls")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> embeddedUrls = null;
    @com.google.gson.annotations.SerializedName(value = "native_libraries")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> nativeLibraries = null;
    @com.google.gson.annotations.SerializedName(value = "is_debuggable")
    private final boolean isDebuggable = false;
    @com.google.gson.annotations.SerializedName(value = "uses_accessibility")
    private final boolean usesAccessibility = false;
    @com.google.gson.annotations.SerializedName(value = "uses_overlay")
    private final boolean usesOverlay = false;
    
    public ApkScanRequestDto(@org.jetbrains.annotations.NotNull()
    java.lang.String packageName, @org.jetbrains.annotations.Nullable()
    java.lang.String appName, @org.jetbrains.annotations.Nullable()
    java.lang.Long versionCode, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> permissions, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> dangerousApis, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> embeddedUrls, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> nativeLibraries, boolean isDebuggable, boolean usesAccessibility, boolean usesOverlay) {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getPackageName() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String getAppName() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.Long getVersionCode() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getPermissions() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getDangerousApis() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getEmbeddedUrls() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getNativeLibraries() {
        return null;
    }
    
    public final boolean isDebuggable() {
        return false;
    }
    
    public final boolean getUsesAccessibility() {
        return false;
    }
    
    public final boolean getUsesOverlay() {
        return false;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component1() {
        return null;
    }
    
    public final boolean component10() {
        return false;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.String component2() {
        return null;
    }
    
    @org.jetbrains.annotations.Nullable()
    public final java.lang.Long component3() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component4() {
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
    
    public final boolean component8() {
        return false;
    }
    
    public final boolean component9() {
        return false;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.data.remote.dto.ApkScanRequestDto copy(@org.jetbrains.annotations.NotNull()
    java.lang.String packageName, @org.jetbrains.annotations.Nullable()
    java.lang.String appName, @org.jetbrains.annotations.Nullable()
    java.lang.Long versionCode, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> permissions, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> dangerousApis, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> embeddedUrls, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> nativeLibraries, boolean isDebuggable, boolean usesAccessibility, boolean usesOverlay) {
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