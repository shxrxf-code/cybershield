package com.shieldguard.ai.ui.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.shieldguard.ai.domain.model.DeviceAudit
import com.shieldguard.ai.domain.model.SecurityScore
import com.shieldguard.ai.domain.model.Threat
import com.shieldguard.ai.domain.model.ThreatLevel
import com.shieldguard.ai.domain.repository.DeviceSecurityRepository
import com.shieldguard.ai.domain.repository.ThreatRepository
import com.shieldguard.ai.domain.usecase.AuditDeviceSecurityUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

data class DashboardUiState(
    val isScanning: Boolean = false,
    val securityScore: SecurityScore = SecurityScore(
        overallScore = 95,
        threatLevel = ThreatLevel.LOW,
        activeThreatsCount = 0,
        scannedAppsCount = 124,
        scannedFilesCount = 890,
        networkProtected = true,
        notificationShieldActive = true
    ),
    val deviceAudit: DeviceAudit? = null,
    val recentThreats: List<Threat> = emptyList()
)

@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val deviceSecurityRepository: DeviceSecurityRepository,
    private val threatRepository: ThreatRepository,
    private val auditDeviceSecurityUseCase: AuditDeviceSecurityUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(DashboardUiState())
    val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

    init {
        observeSecurityScore()
        observeRecentThreats()
        performInitialAudit()
    }

    private fun observeSecurityScore() {
        deviceSecurityRepository.getSecurityScore()
            .onEach { score ->
                _uiState.value = _uiState.value.copy(securityScore = score)
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
            _uiState.value = _uiState.value.copy(isScanning = true)
            val audit = withContext(Dispatchers.IO) {
                auditDeviceSecurityUseCase()
            }
            _uiState.value = _uiState.value.copy(
                isScanning = false,
                deviceAudit = audit
            )
        }
    }

    fun toggleVpn(enabled: Boolean) {
        viewModelScope.launch {
            deviceSecurityRepository.updateProtectionStatus(
                vpnEnabled = enabled,
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
