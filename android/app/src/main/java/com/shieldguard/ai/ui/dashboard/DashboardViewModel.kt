package com.shieldguard.ai.ui.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.shieldguard.ai.domain.model.DeviceAudit
import com.shieldguard.ai.domain.model.ModuleType
import com.shieldguard.ai.domain.model.ScanResult
import com.shieldguard.ai.domain.model.SecurityScore
import com.shieldguard.ai.domain.model.Threat
import com.shieldguard.ai.domain.model.ThreatLevel
import com.shieldguard.ai.domain.model.Verdict
import com.shieldguard.ai.domain.repository.DeviceSecurityRepository
import com.shieldguard.ai.domain.repository.ScannerRepository
import com.shieldguard.ai.domain.repository.ThreatRepository
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationManagerCompat
import com.shieldguard.ai.domain.usecase.AuditDeviceSecurityUseCase
import com.shieldguard.ai.scanner.ApkStaticScanner
import com.shieldguard.ai.scanner.FullDeviceFileScanner
import com.shieldguard.ai.service.NetworkTrafficMonitor
import com.shieldguard.ai.service.NotificationMonitorHub
import com.shieldguard.ai.service.NotificationMonitorState
import com.shieldguard.ai.service.ShieldGuardVpnService
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import javax.inject.Inject

data class DashboardUiState(
    val isScanning: Boolean = false,
    val scanProgress: Float = 0f,
    val scanStatusMessage: String = "System ready",
    val liveCurrentItem: String = "",
    val lastScanSummary: String? = null,
    val hasAllFilesAccess: Boolean = false,
    val hasNotificationAccess: Boolean = false,
    val notificationMonitorState: NotificationMonitorState = NotificationMonitorState(),
    val securityScore: SecurityScore = SecurityScore(
        overallScore = 95,
        threatLevel = ThreatLevel.LOW,
        activeThreatsCount = 0,
        scannedAppsCount = 0,
        scannedFilesCount = 0,
        networkProtected = false,
        notificationShieldActive = true
    ),
    val deviceAudit: DeviceAudit? = null,
    val recentThreats: List<Threat> = emptyList()
)

@HiltViewModel
class DashboardViewModel @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val deviceSecurityRepository: DeviceSecurityRepository,
    private val threatRepository: ThreatRepository,
    private val scannerRepository: ScannerRepository,
    private val auditDeviceSecurityUseCase: AuditDeviceSecurityUseCase,
    private val apkStaticScanner: ApkStaticScanner,
    private val fullDeviceFileScanner: FullDeviceFileScanner,
    private val networkTrafficMonitor: NetworkTrafficMonitor,
    private val notificationMonitorHub: NotificationMonitorHub
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        DashboardUiState(
            hasAllFilesAccess = fullDeviceFileScanner.hasAllFilesAccess(),
            hasNotificationAccess = NotificationManagerCompat.getEnabledListenerPackages(appContext)
                .contains(appContext.packageName)
        )
    )
    val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

    init {
        observeSecurityScore()
        observeRecentThreats()
        observeNotificationMonitor()
        performInitialAudit()
    }

    fun refreshStoragePermission() {
        _uiState.value = _uiState.value.copy(
            hasAllFilesAccess = fullDeviceFileScanner.hasAllFilesAccess(),
            hasNotificationAccess = NotificationManagerCompat.getEnabledListenerPackages(appContext)
                .contains(appContext.packageName)
        )
    }

    private fun observeNotificationMonitor() {
        notificationMonitorHub.state
            .onEach { notifState ->
                _uiState.value = _uiState.value.copy(
                    notificationMonitorState = notifState
                )
            }
            .launchIn(viewModelScope)
    }

    private fun observeSecurityScore() {
        deviceSecurityRepository.getSecurityScore()
            .onEach { score ->
                val isVpnLive = networkTrafficMonitor.state.value.isVpnRunning
                _uiState.value = _uiState.value.copy(
                    securityScore = score.copy(networkProtected = isVpnLive)
                )
            }
            .launchIn(viewModelScope)

        networkTrafficMonitor.state
            .onEach { netState ->
                _uiState.value = _uiState.value.copy(
                    securityScore = _uiState.value.securityScore.copy(
                        networkProtected = netState.isVpnRunning
                    )
                )
            }
            .launchIn(viewModelScope)
    }

    private fun observeRecentThreats() {
        threatRepository.getRecentThreats(limit = 5)
            .onEach { threats ->
                _uiState.value = _uiState.value.copy(recentThreats = threats)
            }
            .launchIn(viewModelScope)
    }

    fun performInitialAudit() {
        viewModelScope.launch {
            val audit = withContext(Dispatchers.IO) {
                auditDeviceSecurityUseCase()
            }
            _uiState.value = _uiState.value.copy(
                deviceAudit = audit,
                hasAllFilesAccess = fullDeviceFileScanner.hasAllFilesAccess()
            )
        }
    }

    fun performFullDeepScan() {
        if (_uiState.value.isScanning) return

        viewModelScope.launch {
            val startTime = System.currentTimeMillis()
            val hasStorageAccess = fullDeviceFileScanner.hasAllFilesAccess()
            _uiState.value = _uiState.value.copy(
                isScanning = true,
                hasAllFilesAccess = hasStorageAccess,
                scanProgress = 0.05f,
                scanStatusMessage = "Phase 1/3: Auditing root, ADB & OS integrity...",
                liveCurrentItem = "Checking hardware & OS security baseline",
                lastScanSummary = null
            )

            // Phase 1: Full Device Integrity & Root Check
            val audit = withContext(Dispatchers.IO) {
                auditDeviceSecurityUseCase()
            }
            _uiState.value = _uiState.value.copy(
                deviceAudit = audit,
                scanProgress = 0.15f,
                scanStatusMessage = "Phase 2/3: Scanning ALL installed & system apps..."
            )

            // Phase 2: Exhaustive Scan of ALL Apps (User + System)
            val apps = withContext(Dispatchers.IO) {
                threatRepository.clearThreatsByModule(ModuleType.APK)
                val scannedApps = apkStaticScanner.scanAllInstalledApps(includeSystemApps = true) { current, total, appName ->
                    val appRatio = if (total > 0) current.toFloat() / total else 1f
                    _uiState.value = _uiState.value.copy(
                        scanProgress = 0.15f + (appRatio * 0.35f),
                        scanStatusMessage = "Phase 2/3: Scanning apps ($current / $total)...",
                        liveCurrentItem = "App: $appName"
                    )
                }

                for (app in scannedApps) {
                    if (app.verdict != Verdict.SAFE) {
                        threatRepository.recordThreat(
                            Threat(
                                id = UUID.randomUUID().toString(),
                                moduleType = ModuleType.APK,
                                threatLevel = app.threatLevel,
                                verdict = app.verdict,
                                riskScore = app.riskScore,
                                title = "App Risk: ${app.appName}",
                                description = app.recommendation,
                                actionTaken = if (app.verdict == Verdict.MALICIOUS) "UNINSTALL_RECOMMENDED" else "WARNED",
                                rawPayload = app.packageName,
                                indicators = app.dangerousPermissions + app.malwareFamilies,
                                timestampMs = System.currentTimeMillis()
                            )
                        )
                    }
                }
                scannedApps
            }

            _uiState.value = _uiState.value.copy(
                scanProgress = 0.50f,
                scanStatusMessage = "Phase 3/3: Scanning ALL files on device storage...",
                liveCurrentItem = "Walking storage directories..."
            )

            // Phase 3: Exhaustive Full-Device File & Archive Scan (No Limits)
            val fileSummary = withContext(Dispatchers.IO) {
                threatRepository.clearThreatsByModule(ModuleType.DOCUMENT)
                val summary = fullDeviceFileScanner.scanEntireDeviceStorage { filesCount, threatsFound, currentName ->
                    // Smooth asymptotic progress between 0.50 and 0.98 as files grow
                    val fileProgress = 0.50f + (0.48f * (1f - (1f / (1f + filesCount / 1500f))))
                    _uiState.value = _uiState.value.copy(
                        scanProgress = fileProgress,
                        scanStatusMessage = "Phase 3/3: Scanned $filesCount files ($threatsFound alerts)...",
                        liveCurrentItem = "File: $currentName"
                    )
                }

                for (threat in summary.threats) {
                    threatRepository.recordThreat(threat)
                }
                summary
            }

            val appThreats = apps.count { it.verdict != Verdict.SAFE }
            val totalFindings = appThreats + fileSummary.threats.size + (if (audit.isRooted) 1 else 0)
            val durationMs = System.currentTimeMillis() - startTime
            val durationSec = String.format("%.1fs", durationMs / 1000.0)

            withContext(Dispatchers.IO) {
                deviceSecurityRepository.updateScanMetrics(
                    appsCount = apps.size,
                    filesCount = fileSummary.totalFilesScanned,
                    securityScore = audit.securityScore
                )
                scannerRepository.recordScanResult(
                    ScanResult(
                        scanId = UUID.randomUUID().toString(),
                        scanType = "FULL_DEVICE_DEEP_SCAN",
                        status = "COMPLETED",
                        riskScore = 100 - audit.securityScore,
                        findingsCount = totalFindings,
                        scannedItemsCount = apps.size + fileSummary.totalFilesScanned,
                        findings = audit.recommendations,
                        durationMs = durationMs,
                        timestampMs = System.currentTimeMillis()
                    )
                )
            }

            _uiState.value = _uiState.value.copy(
                isScanning = false,
                scanProgress = 1.0f,
                scanStatusMessage = "Full device scan complete ($durationSec)",
                liveCurrentItem = "",
                lastScanSummary = "Scanned ${apps.size} apps & ${fileSummary.totalFilesScanned} files (${fileSummary.inspectableFilesScanned} docs/APKs/archives) in $durationSec • $totalFindings issue(s)"
            )
        }
    }

    fun startVpnFirewall(context: Context) {
        val intent = Intent(context, ShieldGuardVpnService::class.java).apply {
            action = ShieldGuardVpnService.ACTION_START
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
        viewModelScope.launch {
            deviceSecurityRepository.updateProtectionStatus(
                vpnEnabled = true,
                notifEnabled = _uiState.value.securityScore.notificationShieldActive
            )
        }
    }

    fun stopVpnFirewall(context: Context) {
        val intent = Intent(context, ShieldGuardVpnService::class.java).apply {
            action = ShieldGuardVpnService.ACTION_STOP
        }
        context.startService(intent)
        viewModelScope.launch {
            deviceSecurityRepository.updateProtectionStatus(
                vpnEnabled = false,
                notifEnabled = _uiState.value.securityScore.notificationShieldActive
            )
        }
    }

    fun toggleNotificationShield(enabled: Boolean) {
        viewModelScope.launch {
            deviceSecurityRepository.updateProtectionStatus(
                vpnEnabled = _uiState.value.securityScore.networkProtected,
                notifEnabled = enabled
            )
        }
    }
}
