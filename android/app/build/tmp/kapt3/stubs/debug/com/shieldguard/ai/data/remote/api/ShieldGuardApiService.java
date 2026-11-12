package com.shieldguard.ai.data.remote.api;

@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000N\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\bf\u0018\u00002\u00020\u0001J\u001e\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u00032\b\b\u0001\u0010\u0005\u001a\u00020\u0006H\u00a7@\u00a2\u0006\u0002\u0010\u0007J\u001e\u0010\b\u001a\b\u0012\u0004\u0012\u00020\t0\u00032\b\b\u0001\u0010\u0005\u001a\u00020\nH\u00a7@\u00a2\u0006\u0002\u0010\u000bJ(\u0010\f\u001a\b\u0012\u0004\u0012\u00020\t0\u00032\b\b\u0001\u0010\r\u001a\u00020\u000e2\b\b\u0001\u0010\u000f\u001a\u00020\u0010H\u00a7@\u00a2\u0006\u0002\u0010\u0011J\u001e\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00130\u00032\b\b\u0001\u0010\u0005\u001a\u00020\u0014H\u00a7@\u00a2\u0006\u0002\u0010\u0015J\u001e\u0010\u0016\u001a\b\u0012\u0004\u0012\u00020\u00170\u00032\b\b\u0001\u0010\u0005\u001a\u00020\u0018H\u00a7@\u00a2\u0006\u0002\u0010\u0019\u00a8\u0006\u001a"}, d2 = {"Lcom/shieldguard/ai/data/remote/api/ShieldGuardApiService;", "", "auditDevice", "Lretrofit2/Response;", "Lcom/shieldguard/ai/data/remote/dto/DeviceAuditResponseDto;", "request", "Lcom/shieldguard/ai/data/remote/dto/DeviceAuditRequestDto;", "(Lcom/shieldguard/ai/data/remote/dto/DeviceAuditRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "scanApk", "Lcom/shieldguard/ai/data/remote/dto/ApkScanResponseDto;", "Lcom/shieldguard/ai/data/remote/dto/ApkScanRequestDto;", "(Lcom/shieldguard/ai/data/remote/dto/ApkScanRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "scanApkFile", "file", "Lokhttp3/MultipartBody$Part;", "isTrustedStore", "Lokhttp3/RequestBody;", "(Lokhttp3/MultipartBody$Part;Lokhttp3/RequestBody;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "scanDocument", "Lcom/shieldguard/ai/data/remote/dto/DocumentScanResponseDto;", "Lcom/shieldguard/ai/data/remote/dto/DocumentScanRequestDto;", "(Lcom/shieldguard/ai/data/remote/dto/DocumentScanRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "scanUrl", "Lcom/shieldguard/ai/data/remote/dto/UrlScanResponseDto;", "Lcom/shieldguard/ai/data/remote/dto/UrlScanRequestDto;", "(Lcom/shieldguard/ai/data/remote/dto/UrlScanRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "app_debug"})
public abstract interface ShieldGuardApiService {
    
    @retrofit2.http.POST(value = "api/v1/urls/scan")
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object scanUrl(@retrofit2.http.Body()
    @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.remote.dto.UrlScanRequestDto request, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super retrofit2.Response<com.shieldguard.ai.data.remote.dto.UrlScanResponseDto>> $completion);
    
    @retrofit2.http.POST(value = "api/v1/apks/scan")
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object scanApk(@retrofit2.http.Body()
    @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.remote.dto.ApkScanRequestDto request, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super retrofit2.Response<com.shieldguard.ai.data.remote.dto.ApkScanResponseDto>> $completion);
    
    @retrofit2.http.Multipart()
    @retrofit2.http.POST(value = "api/v1/apks/scan-file")
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object scanApkFile(@retrofit2.http.Part()
    @org.jetbrains.annotations.NotNull()
    okhttp3.MultipartBody.Part file, @retrofit2.http.Part(value = "is_trusted_store")
    @org.jetbrains.annotations.NotNull()
    okhttp3.RequestBody isTrustedStore, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super retrofit2.Response<com.shieldguard.ai.data.remote.dto.ApkScanResponseDto>> $completion);
    
    @retrofit2.http.POST(value = "api/v1/documents/scan")
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object scanDocument(@retrofit2.http.Body()
    @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.remote.dto.DocumentScanRequestDto request, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super retrofit2.Response<com.shieldguard.ai.data.remote.dto.DocumentScanResponseDto>> $completion);
    
    @retrofit2.http.POST(value = "api/v1/devices/audit")
    @org.jetbrains.annotations.Nullable()
    public abstract java.lang.Object auditDevice(@retrofit2.http.Body()
    @org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.remote.dto.DeviceAuditRequestDto request, @org.jetbrains.annotations.NotNull()
    kotlin.coroutines.Continuation<? super retrofit2.Response<com.shieldguard.ai.data.remote.dto.DeviceAuditResponseDto>> $completion);
}