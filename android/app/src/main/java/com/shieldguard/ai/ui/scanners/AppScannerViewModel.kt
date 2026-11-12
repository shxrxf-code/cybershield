package com.shieldguard.ai.ui.scanners

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.shieldguard.ai.domain.model.AppThreatInfo
import com.shieldguard.ai.domain.model.ModuleType
import com.shieldguard.ai.domain.model.Verdict
import com.shieldguard.ai.domain.repository.ThreatRepository
import com.shieldguard.ai.domain.usecase.ScanApkUseCase
import com.shieldguard.ai.scanner.ApkStaticScanner
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

data class AppScannerUiState(
    val isScanning: Boolean = false,
    val isAndroguardScanning: Boolean = false,
    val androguardStatus: String = "",
    val scanningPackage: String? = null,
    val installedApps: List<AppThreatInfo> = emptyList(),
    val flaggedCount: Int = 0
)

@HiltViewModel
class AppScannerViewModel @Inject constructor(
    private val apkStaticScanner: ApkStaticScanner,
    private val scanApkUseCase: ScanApkUseCase,
    private val threatRepository: ThreatRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow(AppScannerUiState())
    val uiState: StateFlow<AppScannerUiState> = _uiState.asStateFlow()

    init {
        scanInstalledApplications()
    }

    fun scanInstalledApplications() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isScanning = true,
                androguardStatus = "Running local package audit & Androguard verification..."
            )
            val apps = withContext(Dispatchers.IO) {
                threatRepository.clearThreatsByModule(ModuleType.APK)
                val scanned = apkStaticScanner.scanAllInstalledApps().toMutableList()
                // Automatically verify flagged or sideloaded apps via Androguard backend if online
                for (i in scanned.indices) {
                    val app = scanned[i]
                    if (app.verdict != Verdict.SAFE || !app.isTrustedStore) {
                        scanned[i] = scanApkUseCase(app).getOrDefault(app)
                    }
                }
                scanned.sortedByDescending { it.riskScore }
            }

            val flagged = apps.count { it.verdict != Verdict.SAFE }
            val androguardVerifiedCount = apps.count { it.analysisEngine.startsWith("androguard") }
            _uiState.value = _uiState.value.copy(
                isScanning = false,
                androguardStatus = if (androguardVerifiedCount > 0) {
                    "Androguard verified $androguardVerifiedCount app(s)"
                } else {
                    "Local audit complete (connect Androguard backend via ADB reverse for deep DEX scan)"
                },
                installedApps = apps,
                flaggedCount = flagged
            )
        }
    }

    fun scanAllWithAndroguard() {
        if (_uiState.value.isAndroguardScanning || _uiState.value.isScanning) return
        viewModelScope.launch {
            val currentList = _uiState.value.installedApps.toMutableList()
            if (currentList.isEmpty()) return@launch

            _uiState.value = _uiState.value.copy(
                isAndroguardScanning = true,
                androguardStatus = "Starting Androguard binary APK scan..."
            )

            withContext(Dispatchers.IO) {
                threatRepository.clearThreatsByModule(ModuleType.APK)
                for (i in currentList.indices) {
                    val target = currentList[i]
                    _uiState.value = _uiState.value.copy(
                        scanningPackage = target.packageName,
                        androguardStatus = "Androguard (${i + 1}/${currentList.size}): ${target.appName}"
                    )
                    val updated = scanApkUseCase(target).getOrDefault(target)
                    currentList[i] = updated
                    val sorted = currentList.sortedByDescending { it.riskScore }
                    _uiState.value = _uiState.value.copy(
                        installedApps = sorted,
                        flaggedCount = sorted.count { it.verdict != Verdict.SAFE }
                    )
                }
            }

            val verified = currentList.count { it.analysisEngine.startsWith("androguard") }
            _uiState.value = _uiState.value.copy(
                isAndroguardScanning = false,
                scanningPackage = null,
                androguardStatus = if (verified > 0) {
                    "Androguard completed binary & DEX scan on $verified/${currentList.size} apps"
                } else {
                    "Androguard backend unreachable at 127.0.0.1:8000 (run backend + adb reverse tcp:8000 tcp:8000)"
                }
            )
        }
    }

    fun scanSingleAppWithAndroguard(packageName: String) {
        viewModelScope.launch {
            val currentList = _uiState.value.installedApps.toMutableList()
            val idx = currentList.indexOfFirst { it.packageName == packageName }
            if (idx < 0) return@launch

            val target = currentList[idx]
            _uiState.value = _uiState.value.copy(
                scanningPackage = packageName,
                androguardStatus = "Androguard analyzing ${target.appName} APK..."
            )
            val updated = withContext(Dispatchers.IO) {
                scanApkUseCase(target).getOrDefault(target)
            }
            currentList[idx] = updated
            val sorted = currentList.sortedByDescending { it.riskScore }
            _uiState.value = _uiState.value.copy(
                scanningPackage = null,
                installedApps = sorted,
                flaggedCount = sorted.count { it.verdict != Verdict.SAFE },
                androguardStatus = if (updated.analysisEngine.startsWith("androguard")) {
                    "Androguard scanned ${updated.appName}: ${updated.verdict.name} (${updated.dexCount} DEX)"
                } else {
                    "Backend offline: kept local heuristic for ${updated.appName}"
                }
            )
        }
    }
}
