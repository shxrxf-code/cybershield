package com.shieldguard.ai.scanner;

@javax.inject.Singleton()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\"\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0003\b\u0007\u0018\u00002\u00020\u0001B\u000f\b\u0007\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0002\u0010\u0004J\u000e\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u0007J\u0014\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\u00070\u00062\u0006\u0010\u000f\u001a\u00020\u0007J\u0018\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u00072\u0006\u0010\u0013\u001a\u00020\u0007H\u0002J\u0018\u0010\u0014\u001a\u00020\u00152\u0006\u0010\u0016\u001a\u00020\u00072\u0006\u0010\u0017\u001a\u00020\u0007H\u0002R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\u0005\u001a\b\u0012\u0004\u0012\u00020\u00070\u0006X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00070\u0006X\u0082\u0004\u00a2\u0006\u0002\n\u0000R\u0014\u0010\t\u001a\b\u0012\u0004\u0012\u00020\u00070\nX\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u0018"}, d2 = {"Lcom/shieldguard/ai/scanner/LocalUrlThreatAnalyzer;", "", "networkTrafficMonitor", "Lcom/shieldguard/ai/service/NetworkTrafficMonitor;", "(Lcom/shieldguard/ai/service/NetworkTrafficMonitor;)V", "phishingKeywords", "", "", "popularBrands", "shorteners", "", "analyzeUrl", "Lcom/shieldguard/ai/domain/model/Threat;", "rawUrl", "extractUrls", "text", "isCloseTypo", "", "a", "b", "levenshtein", "", "lhs", "rhs", "app_debug"})
public final class LocalUrlThreatAnalyzer {
    @org.jetbrains.annotations.NotNull()
    private final com.shieldguard.ai.service.NetworkTrafficMonitor networkTrafficMonitor = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> popularBrands = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.List<java.lang.String> phishingKeywords = null;
    @org.jetbrains.annotations.NotNull()
    private final java.util.Set<java.lang.String> shorteners = null;
    
    @javax.inject.Inject()
    public LocalUrlThreatAnalyzer(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.service.NetworkTrafficMonitor networkTrafficMonitor) {
        super();
    }
    
    @org.jetbrains.annotations.NotNull()
    public final java.util.List<java.lang.String> extractUrls(@org.jetbrains.annotations.NotNull()
    java.lang.String text) {
        return null;
    }
    
    @org.jetbrains.annotations.NotNull()
    public final com.shieldguard.ai.domain.model.Threat analyzeUrl(@org.jetbrains.annotations.NotNull()
    java.lang.String rawUrl) {
        return null;
    }
    
    private final boolean isCloseTypo(java.lang.String a, java.lang.String b) {
        return false;
    }
    
    private final int levenshtein(java.lang.String lhs, java.lang.String rhs) {
        return 0;
    }
}