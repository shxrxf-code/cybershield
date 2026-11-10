package com.shieldguard.ai.di

import android.content.Context
import androidx.room.Room
import com.shieldguard.ai.data.local.ShieldGuardDatabase
import com.shieldguard.ai.data.local.dao.ScanHistoryDao
import com.shieldguard.ai.data.local.dao.ThreatDao
import com.shieldguard.ai.data.remote.AuthInterceptor
import com.shieldguard.ai.data.remote.api.ShieldGuardApiService
import com.shieldguard.ai.data.repository.DeviceSecurityRepositoryImpl
import com.shieldguard.ai.data.repository.ScannerRepositoryImpl
import com.shieldguard.ai.data.repository.ThreatRepositoryImpl
import com.shieldguard.ai.domain.repository.DeviceSecurityRepository
import com.shieldguard.ai.domain.repository.ScannerRepository
import com.shieldguard.ai.domain.repository.ThreatRepository
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): ShieldGuardDatabase {
        return Room.databaseBuilder(
            context,
            ShieldGuardDatabase::class.java,
            "shieldguard_database.db"
        )
        .fallbackToDestructiveMigration()
        .build()
    }

    @Provides
    fun provideThreatDao(database: ShieldGuardDatabase): ThreatDao = database.threatDao()

    @Provides
    fun provideScanHistoryDao(database: ShieldGuardDatabase): ScanHistoryDao = database.scanHistoryDao()
}

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    private const val BASE_URL = "http://10.0.2.2:8000/" // Android emulator host alias / production gateway

    @Provides
    @Singleton
    fun provideOkHttpClient(authInterceptor: AuthInterceptor): OkHttpClient {
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BODY
        }

        // Production Certificate Pinning configuration
        val certificatePinner = CertificatePinner.Builder()
            .add("api.shieldguard.ai", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .build()

        return OkHttpClient.Builder()
            .addInterceptor(authInterceptor)
            .addInterceptor(logging)
            .certificatePinner(certificatePinner)
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build()
    }

    @Provides
    @Singleton
    fun provideRetrofit(okHttpClient: OkHttpClient): Retrofit {
        return Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
    }

    @Provides
    @Singleton
    fun provideApiService(retrofit: Retrofit): ShieldGuardApiService {
        return retrofit.create(ShieldGuardApiService::class.java)
    }
}

@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {

    @Binds
    @Singleton
    abstract fun bindThreatRepository(impl: ThreatRepositoryImpl): ThreatRepository

    @Binds
    @Singleton
    abstract fun bindScannerRepository(impl: ScannerRepositoryImpl): ScannerRepository

    @Binds
    @Singleton
    abstract fun bindDeviceSecurityRepository(impl: DeviceSecurityRepositoryImpl): DeviceSecurityRepository
}
