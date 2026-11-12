package com.shieldguard.ai.data.remote.dto;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\t\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010 \n\u0002\b\u001b\n\u0002\u0010\b\n\u0002\b\u0002\b\u0086\b\u0018\u00002\u00020\u0001B_\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\u0006\u0010\u0007\u001a\u00020\u0003\u0012\b\b\u0002\u0010\b\u001a\u00020\t\u0012\u000e\b\u0002\u0010\n\u001a\b\u0012\u0004\u0012\u00020\u00030\u000b\u0012\u000e\b\u0002\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u00030\u000b\u0012\u000e\b\u0002\u0010\r\u001a\b\u0012\u0004\u0012\u00020\u00030\u000b\u00a2\u0006\u0002\u0010\u000eJ\t\u0010\u001b\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001c\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001d\u001a\u00020\u0006H\u00c6\u0003J\t\u0010\u001e\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001f\u001a\u00020\tH\u00c6\u0003J\u000f\u0010 \u001a\b\u0012\u0004\u0012\u00020\u00030\u000bH\u00c6\u0003J\u000f\u0010!\u001a\b\u0012\u0004\u0012\u00020\u00030\u000bH\u00c6\u0003J\u000f\u0010\"\u001a\b\u0012\u0004\u0012\u00020\u00030\u000bH\u00c6\u0003Jk\u0010#\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00032\b\b\u0002\u0010\u0005\u001a\u00020\u00062\b\b\u0002\u0010\u0007\u001a\u00020\u00032\b\b\u0002\u0010\b\u001a\u00020\t2\u000e\b\u0002\u0010\n\u001a\b\u0012\u0004\u0012\u00020\u00030\u000b2\u000e\b\u0002\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u00030\u000b2\u000e\b\u0002\u0010\r\u001a\b\u0012\u0004\u0012\u00020\u00030\u000bH\u00c6\u0001J\u0013\u0010$\u001a\u00020\t2\b\u0010%\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010&\u001a\u00020\'H\u00d6\u0001J\t\u0010(\u001a\u00020\u0003H\u00d6\u0001R\u001c\u0010\n\u001a\b\u0012\u0004\u0012\u00020\u00030\u000b8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u000f\u0010\u0010R\u001c\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u00030\u000b8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0011\u0010\u0010R\u0016\u0010\u0007\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0012\u0010\u0013R\u0016\u0010\u0004\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0014\u0010\u0013R\u0016\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0015\u0010\u0013R\u0016\u0010\u0005\u001a\u00020\u00068\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0016\u0010\u0017R\u0016\u0010\b\u001a\u00020\t8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0018\u0010\u0019R\u001c\u0010\r\u001a\b\u0012\u0004\u0012\u00020\u00030\u000b8\u0006X\u0087\u0004\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001a\u0010\u0010\u00a8\u0006)"}, d2 = {"Lcom/shieldguard/ai/data/remote/dto/DocumentScanRequestDto;", "", "fileName", "", "fileHashSha256", "fileSizeBytes", "", "fileExtension", "hasMacros", "", "embeddedScripts", "", "embeddedUrls", "suspiciousTags", "(Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;ZLjava/util/List;Ljava/util/List;Ljava/util/List;)V", "getEmbeddedScripts", "()Ljava/util/List;", "getEmbeddedUrls", "getFileExtension", "()Ljava/lang/String;", "getFileHashSha256", "getFileName", "getFileSizeBytes", "()J", "getHasMacros", "()Z", "getSuspiciousTags", "component1", "component2", "component3", "component4", "component5", "component6", "component7", "component8", "copy", "equals", "other", "hashCode", "", "toString", "app_debug"})
public final class DocumentScanRequestDto {
    @com.google.gson.annotations.SerializedName(value = "file_name")
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String fileName = null;
    @com.google.gson.annotations.SerializedName(value = "file_hash_sha256")
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String fileHashSha256 = null;
    @com.google.gson.annotations.SerializedName(value = "file_size_bytes")
    private final long fileSizeBytes = 0L;
    @com.google.gson.annotations.SerializedName(value = "file_extension")
    @org.jetbrains.annotations.NotNull()
    private final java.lang.String fileExtension = null;
    @com.google.gson.annotations.SerializedName(value = "has_macros")
    private final boolean hasMacros = false;
    @com.google.gson.annotations.SerializedName(value = "embedded_scripts")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> embeddedScripts = null;
    @com.google.gson.annotations.SerializedName(value = "embedded_urls")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> embeddedUrls = null;
    @com.google.gson.annotations.SerializedName(value = "suspicious_tags")
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> suspiciousTags = null;
    
    public DocumentScanRequestDto(@org.jetbrains.annotations.NotNull()
    java.lang.String fileName, @org.jetbrains.annotations.NotNull()
    java.lang.String fileHashSha256, long fileSizeBytes, @org.jetbrains.annotations.NotNull()
    java.lang.String fileExtension, boolean hasMacros, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> embeddedScripts, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> embeddedUrls, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> suspiciousTags) {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getFileName() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getFileHashSha256() {
        return null;
    }
    
    public final long getFileSizeBytes() {
        return 0L;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String getFileExtension() {
        return null;
    }
    
    public final boolean getHasMacros() {
        return false;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getEmbeddedScripts() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getEmbeddedUrls() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> getSuspiciousTags() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component1() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component2() {
        return null;
    }
    
    public final long component3() {
        return 0L;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.lang.String component4() {
        return null;
    }
    
    public final boolean component5() {
        return false;
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
    public final java.util.List<java.lang.String> component8() {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.data.remote.dto.DocumentScanRequestDto copy(@org.jetbrains.annotations.NotNull()
    java.lang.String fileName, @org.jetbrains.annotations.NotNull()
    java.lang.String fileHashSha256, long fileSizeBytes, @org.jetbrains.annotations.NotNull()
    java.lang.String fileExtension, boolean hasMacros, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> embeddedScripts, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> embeddedUrls, @org.jetbrains.annotations.NotNull()
    java.util.List<java.lang.String> suspiciousTags) {
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