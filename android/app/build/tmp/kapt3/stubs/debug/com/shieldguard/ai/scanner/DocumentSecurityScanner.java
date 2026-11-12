package com.shieldguard.ai.scanner;

@javax.inject.Singleton()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\"\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010 \n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010!\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\b\u0007\u0018\u0000 \u00182\u00020\u0001:\u0001\u0018B\u0007\b\u0007\u00a2\u0006\u0002\u0010\u0002J\u0010\u0010\t\u001a\u00020\u00052\u0006\u0010\n\u001a\u00020\u000bH\u0002J\u001e\u0010\f\u001a\u00020\r2\u0006\u0010\n\u001a\u00020\u000b2\f\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\u00050\u000fH\u0002J\u000e\u0010\u0010\u001a\u00020\u00112\u0006\u0010\n\u001a\u00020\u000bJ&\u0010\u0012\u001a\u00020\r2\u0006\u0010\n\u001a\u00020\u000b2\u0006\u0010\u0013\u001a\u00020\u00052\f\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\u00050\u000fH\u0002J\u001e\u0010\u0014\u001a\u00020\r2\u0006\u0010\n\u001a\u00020\u000b2\f\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\u00050\u000fH\u0002J\u001e\u0010\u0015\u001a\u00020\r2\u0006\u0010\n\u001a\u00020\u000b2\f\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\u00050\u000fH\u0002J&\u0010\u0016\u001a\u00020\r2\u0006\u0010\n\u001a\u00020\u000b2\u0006\u0010\u0017\u001a\u00020\u00052\f\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\u00050\u000fH\u0002R\u0014\u0010\u0003\u001a\b\u0012\u0004\u0012\u00020\u00050\u0004X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\u00050\u0007X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00050\u0007X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u0019"}, d2 = {"Lcom/shieldguard/ai/scanner/DocumentSecurityScanner;", "", "()V", "highRiskArchivePayloads", "", "", "scriptKeywords", "", "suspiciousPdfTags", "readBoundedBytes", "file", "Ljava/io/File;", "scanArchiveContent", "", "indicators", "", "scanDocumentFile", "Lcom/shieldguard/ai/domain/model/Threat;", "scanOfficeContent", "extension", "scanPdfContent", "scanScriptContent", "scanScriptOrExecutable", "ext", "Companion", "app_debug"})
public final class DocumentSecurityScanner {
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> suspiciousPdfTags = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.Set<java.lang.String> highRiskArchivePayloads = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> scriptKeywords = null;
    private static final int MAX_TEXT_SCAN_BYTES = 4194304;
    @org.jetbrains.annotations.NotNull()
    public static final com.shieldguard.ai.scanner.DocumentSecurityScanner.Companion Companion = null;
    
    @javax.inject.Inject()
    public DocumentSecurityScanner() {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.Threat scanDocumentFile(@org.jetbrains.annotations.NotNull()
    java.io.File file) {
        return null;
    }
    
    private final java.lang.String readBoundedBytes(java.io.File file) {
        return null;
    }
    
    private final int scanPdfContent(java.io.File file, java.util.List<java.lang.String> indicators) {
        return 0;
    }
    
    private final int scanOfficeContent(java.io.File file, java.lang.String extension, java.util.List<java.lang.String> indicators) {
        return 0;
    }
    
    private final int scanArchiveContent(java.io.File file, java.util.List<java.lang.String> indicators) {
        return 0;
    }
    
    private final int scanScriptOrExecutable(java.io.File file, java.lang.String ext, java.util.List<java.lang.String> indicators) {
        return 0;
    }
    
    private final int scanScriptContent(java.io.File file, java.util.List<java.lang.String> indicators) {
        return 0;
    }
    
    @kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002\u00a2\u0006\u0002\u0010\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u0005"}, d2 = {"Lcom/shieldguard/ai/scanner/DocumentSecurityScanner$Companion;", "", "()V", "MAX_TEXT_SCAN_BYTES", "", "app_debug"})
    public static final class Companion {
        
        private Companion() {
            super();
        }
    }
}