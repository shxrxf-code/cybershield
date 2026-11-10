package com.shieldguard.ai.data.remote.api

import com.shieldguard.ai.data.remote.dto.ApkScanRequestDto
import com.shieldguard.ai.data.remote.dto.ApkScanResponseDto
import com.shieldguard.ai.data.remote.dto.DeviceAuditRequestDto
import com.shieldguard.ai.data.remote.dto.DeviceAuditResponseDto
import com.shieldguard.ai.data.remote.dto.DocumentScanRequestDto
import com.shieldguard.ai.data.remote.dto.DocumentScanResponseDto
import com.shieldguard.ai.data.remote.dto.UrlScanRequestDto
import com.shieldguard.ai.data.remote.dto.UrlScanResponseDto
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.POST

interface ShieldGuardApiService {

    @POST("api/v1/urls/scan")
    suspend fun scanUrl(@Body request: UrlScanRequestDto): Response<UrlScanResponseDto>

    @POST("api/v1/apks/scan")
    suspend fun scanApk(@Body request: ApkScanRequestDto): Response<ApkScanResponseDto>

    @POST("api/v1/documents/scan")
    suspend fun scanDocument(@Body request: DocumentScanRequestDto): Response<DocumentScanResponseDto>

    @POST("api/v1/devices/audit")
    suspend fun auditDevice(@Body request: DeviceAuditRequestDto): Response<DeviceAuditResponseDto>
}
