package com.shieldguard.ai.ui.scanners

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.shieldguard.ai.domain.model.AppThreatInfo
import com.shieldguard.ai.domain.model.Verdict
import com.shieldguard.ai.domain.usecase.ScanApkUseCase
import com.shieldguard.ai.scanner.ApkStaticScanner
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class AppScannerUiState(
    val isScanning: Boolean = false,
    val installedApps: List<AppThreatInfo> = emptyList(),
    val flaggedCount: Int = 0
)

@HiltViewModel
class AppScannerViewModel @Inject constructor(
    private val apkStaticScanner: ApkStaticScanner,
    private val scanApkUseCase: ScanApkUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(AppScannerUiState())
    val uiState: StateFlow<AppScannerUiState> = _uiState.asStateFlow()

    init {
        scanInstalledApplications()
    }

    fun scanInstalledApplications() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isScanning = true)
            val apps = apkStaticScanner.scanAllInstalledApps()

            // Run through use case to persist any detected threats
            for (app in apps) {
                if (app.verdict != Verdict.SAFE) {
                    scanApkUseCase(app)
                }
            }

            val flagged = apps.count { it.verdict != Verdict.SAFE }
            _uiState.value = _uiState.value.copy(
                isScanning = false,
                installedApps = apps,
                flaggedCount = flagged
            )
        }
    }
}
