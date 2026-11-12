package com.shieldguard.ai.data.remote.dto;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010 \n\u0002\b\u000f\n\u0002\u0010\u000b\n\u0002\b\u0004\b\u0086\b\u0018\u00002\u00020\u0001B1\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\f\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\u00050\u0007\u0012\f\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00050\u0007\u00a2\u0006\u0002\u0010\tJ\t\u0010\u0011\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0012\u001a\u00020\u0005H\u00c6\u0003J\u000f\u0010\u0013\u001a\b\u0012\u0004\u0012\u00020\u00050\u0007H\u00c6\u0003J\u000f\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u00050\u0007H\u00c6\u0003J=\u0010\u0015\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00052\u000e\b\u0002\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\u00050\u00072\u000e\b\u0002\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00050\u0007H\u00c6\u0001J\u0013\u0010\u0016\u001a\u00020\u00172\b\u0010\u0018\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u0019\u001a\u00020\u0003H\u00d6\u0001J\t\u0010\u001a\u001a\u00020\u0005H\u00d6\u0001R\u001c\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\u00050\u00078\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\n\u0010\u000bR\u0016\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\f\u0010\rR\u001c\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00050\u00078\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u000e\u0010\u000bR\u0016\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u000f\u0010\u0010\u00a8\u0006\u001b"}, d2 = {"Lcom/shieldguard/ai/data/remote/dto/DeviceAuditResponseDto;", "", "overallSecurityScore", "", "securityPosture", "", "criticalFindings", "", "remediationSteps", "(ILjava/lang/String;Ljava/util/List;Ljava/util/List;)V", "getCriticalFindings", "()Ljava/util/List;", "getOverallSecurityScore", "()I", "getRemediationSteps", "getSecurityPosture", "()Ljava/lang/String;", "component1", "component2", "component3", "component4", "copy", "equals", "", "other", "hashCode", "toString", "app_debug"})
public final class DeviceAuditResponseDto {
    @com.google.gson.annotations.SerializedName(value = "overall_security_score")
    private final int overallSecurityScore = 0;
    @com.google.gson.annotations.SerializedName(value = "security_posture")
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String securityPosture = null;
    @com.google.gson.annotations.SerializedName(value = "critical_findings")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> criticalFindings = null;
    @com.google.gson.annotations.SerializedName(value = "remediation_steps")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> remediationSteps = null;
    
    public DeviceAuditResponseDto(int overallSecurityScore, @org.jetbrains.annotations.NotNull()
    java.lang.String securityPosture, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> criticalFindings, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> remediationSteps) {
        super();
    }
    
    public final int getOverallSecurityScore() {
        return 0;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getSecurityPosture() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getCriticalFindings() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getRemediationSteps() {
        return null;
    }
    
    public final int component1() {
        return 0;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component2() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component3() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> component4() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.data.remote.dto.DeviceAuditResponseDto copy(int overallSecurityScore, @org.jetbrains.annotations.NotNull()
    java.lang.String securityPosture, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> criticalFindings, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> remediationSteps) {
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