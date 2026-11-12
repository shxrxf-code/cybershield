package com.shieldguard.ai.data.remote.api

import com.shieldguard.ai.data.remote.dto.ApkScanRequestDto
import com.shieldguard.ai.data.remote.dto.ApkScanResponseDto
import com.shieldguard.ai.data.remote.dto.DeviceAuditRequestDto
import com.shieldguard.ai.data.remote.dto.DeviceAuditResponseDto
import com.shieldguard.ai.data.remote.dto.DocumentScanRequestDto
import com.shieldguard.ai.data.remote.dto.DocumentScanResponseDto
import com.shieldguard.ai.data.remote.dto.UrlScanRequestDto
import com.shieldguard.ai.data.remote.dto.UrlScanResponseDto
import okhttp3.MultipartBody
import okhttp3.RequestBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part

interface ShieldGuardApiService {

    @POST("api/v1/urls/scan")
    suspend fun scanUrl(@Body request: UrlScanRequestDto): Response<UrlScanResponseDto>

    @POST("api/v1/apks/scan")
    suspend fun scanApk(@Body request: ApkScanRequestDto): Response<ApkScanResponseDto>

    @Multipart
    @POST("api/v1/apks/scan-file")
    suspend fun scanApkFile(
        @Part file: MultipartBody.Part,
        @Part("is_trusted_store") isTrustedStore: RequestBody
    ): Response<ApkScanResponseDto>

    @POST("api/v1/documents/scan")
    suspend fun scanDocument(@Body request: DocumentScanRequestDto): Response<DocumentScanResponseDto>

    @POST("api/v1/devices/audit")
    suspend fun auditDevice(@Body request: DeviceAuditRequestDto): Response<DeviceAuditResponseDto>
}
