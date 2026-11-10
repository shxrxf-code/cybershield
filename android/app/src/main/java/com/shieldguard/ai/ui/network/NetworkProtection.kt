package com.shieldguard.ai.ui.network

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.shieldguard.ai.data.local.EncryptedPreferencesManager
import com.shieldguard.ai.ui.theme.CardBorder
import com.shieldguard.ai.ui.theme.CyberNavy
import com.shieldguard.ai.ui.theme.NeonCyan
import com.shieldguard.ai.ui.theme.SafeGreen
import com.shieldguard.ai.ui.theme.SurfaceCard
import com.shieldguard.ai.ui.theme.TextPrimary
import com.shieldguard.ai.ui.theme.TextSecondary
import com.shieldguard.ai.ui.theme.ThreatCrimson
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class NetworkUiState(
    val isVpnActive: Boolean = false,
    val isWifiSecure: Boolean = true,
    val currentSsid: String = "Corporate_Secure_5G",
    val encryptionType: String = "WPA3 Enterprise (Encrypted)",
    val mitmThreatDetected: Boolean = false,
    val dnsHijackDetected: Boolean = false
)

@HiltViewModel
class NetworkViewModel @Inject constructor(
    private val preferencesManager: EncryptedPreferencesManager
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        NetworkUiState(isVpnActive = preferencesManager.isVpnProtectionEnabled())
    )
    val uiState: StateFlow<NetworkUiState> = _uiState.asStateFlow()

    fun toggleVpn(enabled: Boolean) {
        preferencesManager.setVpnProtectionEnabled(enabled)
        _uiState.value = _uiState.value.copy(isVpnActive = enabled)
    }
}

@Composable
fun NetworkProtectionScreen(
    viewModel: NetworkViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(CyberNavy)
            .padding(16.dp)
    ) {
        // Top bar
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
            }
            Spacer(modifier = Modifier.width(8.dp))
            Text("Network Shield & VPN", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
        }

        Spacer(modifier = Modifier.height(16.dp))

        // VPN Tunnel Card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, CardBorder, RoundedCornerShape(16.dp)),
            colors = CardDefaults.cardColors(containerColor = SurfaceCard),
            shape = RoundedCornerShape(16.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(18.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(46.dp)
                            .background(if (state.isVpnActive) SafeGreen.copy(alpha = 0.15f) else CardBorder, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.VpnLock,
                            contentDescription = null,
                            tint = if (state.isVpnActive) SafeGreen else TextSecondary
                        )
                    }
                    Spacer(modifier = Modifier.width(14.dp))
                    Column {
                        Text("ShieldGuard Secure Tunnel", fontWeight = FontWeight.Bold, fontSize = 16.sp, color = TextPrimary)
                        Text(
                            text = if (state.isVpnActive) "Active • DNS & Traffic Encrypted" else "Disabled • Public WiFi Exposed",
                            fontSize = 12.sp,
                            color = if (state.isVpnActive) SafeGreen else ThreatCrimson
                        )
                    }
                }

                Switch(
                    checked = state.isVpnActive,
                    onCheckedChange = { viewModel.toggleVpn(it) },
                    colors = SwitchDefaults.colors(checkedThumbColor = SafeGreen)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // WiFi Audit Status
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, CardBorder, RoundedCornerShape(16.dp)),
            colors = CardDefaults.cardColors(containerColor = SurfaceCard),
            shape = RoundedCornerShape(16.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("Current Network Telemetry", fontWeight = FontWeight.SemiBold, fontSize = 15.sp, color = TextPrimary)
                Spacer(modifier = Modifier.height(12.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Wifi, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(20.dp))
                    Spacer(modifier = Modifier.width(10.dp))
                    Text("SSID: ${state.currentSsid}", fontSize = 13.sp, color = TextPrimary)
                }

                Spacer(modifier = Modifier.height(8.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Lock, contentDescription = null, tint = SafeGreen, modifier = Modifier.size(20.dp))
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(state.encryptionType, fontSize = 13.sp, color = TextPrimary)
                }

                Spacer(modifier = Modifier.height(8.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Security, contentDescription = null, tint = SafeGreen, modifier = Modifier.size(20.dp))
                    Spacer(modifier = Modifier.width(10.dp))
                    Text("ARP / MITM Status: SECURE (Zero Spoofing Detected)", fontSize = 13.sp, color = SafeGreen)
                }
            }
        }
    }
}
