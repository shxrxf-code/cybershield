package com.shieldguard.ai.di;

@dagger.Module()
@kotlin.Metadata(mv = {1, 9, 0}, k = 1, xi = 48, d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\b\'\u0018\u00002\u00020\u0001B\u0005\u00a2\u0006\u0002\u0010\u0002J\u0010\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u0006H\'J\u0010\u0010\u0007\u001a\u00020\b2\u0006\u0010\u0005\u001a\u00020\tH\'J\u0010\u0010\n\u001a\u00020\u000b2\u0006\u0010\u0005\u001a\u00020\fH\'\u00a8\u0006\r"}, d2 = {"Lcom/shieldguard/ai/di/RepositoryModule;", "", "()V", "bindDeviceSecurityRepository", "Lcom/shieldguard/ai/domain/repository/DeviceSecurityRepository;", "impl", "Lcom/shieldguard/ai/data/repository/DeviceSecurityRepositoryImpl;", "bindScannerRepository", "Lcom/shieldguard/ai/domain/repository/ScannerRepository;", "Lcom/shieldguard/ai/data/repository/ScannerRepositoryImpl;", "bindThreatRepository", "Lcom/shieldguard/ai/domain/repository/ThreatRepository;", "Lcom/shieldguard/ai/data/repository/ThreatRepositoryImpl;", "app_debug"})
@dagger.hilt.InstallIn(value = {dagger.hilt.components.SingletonComponent.class})
public abstract class RepositoryModule {
    
    public RepositoryModule() {
        super();
    }
    
    @dagger.Binds()
    @javax.inject.Singleton()
    @org.jetbrains.annotations.NotNull()
    public abstract com.shieldguard.ai.domain.repository.ThreatRepository bindThreatRepository(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.repository.ThreatRepositoryImpl impl);
    
    @dagger.Binds()
    @javax.inject.Singleton()
    @org.jetbrains.annotations.NotNull()
    public abstract com.shieldguard.ai.domain.repository.ScannerRepository bindScannerRepository(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.repository.ScannerRepositoryImpl impl);
    
    @dagger.Binds()
    @javax.inject.Singleton()
    @org.jetbrains.annotations.NotNull()
    public abstract com.shieldguard.ai.domain.repository.DeviceSecurityRepository bindDeviceSecurityRepository(@org.jetbrains.annotations.NotNull()
    com.shieldguard.ai.data.repository.DeviceSecurityRepositoryImpl impl);
}