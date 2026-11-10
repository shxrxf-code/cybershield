package com.shieldguard.ai.data.remote

import com.shieldguard.ai.data.local.EncryptedPreferencesManager
import okhttp3.Interceptor
import okhttp3.Response
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AuthInterceptor @Inject constructor(
    private val preferencesManager: EncryptedPreferencesManager
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()
        val requestBuilder = original.newBuilder()
            .header("X-ShieldGuard-Key", preferencesManager.getAuthToken())
            .header("X-Device-UUID", preferencesManager.getDeviceUuid())
            .header("Content-Type", "application/json")
            .method(original.method, original.body)

        return chain.proceed(requestBuilder.build())
    }
}
