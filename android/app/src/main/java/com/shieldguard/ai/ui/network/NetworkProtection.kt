package com.shieldguard.ai.ui.network

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import com.shieldguard.ai.data.local.EncryptedPreferencesManager
import com.shieldguard.ai.service.NetworkMonitorState
import com.shieldguard.ai.service.NetworkTrafficEvent
import com.shieldguard.ai.service.NetworkTrafficMonitor
import com.shieldguard.ai.service.ShieldGuardVpnService
import com.shieldguard.ai.ui.components.StatMetricCard
import com.shieldguard.ai.ui.theme.CardBorder
import com.shieldguard.ai.ui.theme.CyberNavy
import com.shieldguard.ai.ui.theme.NeonCyan
import com.shieldguard.ai.ui.theme.SafeGreen
import com.shieldguard.ai.ui.theme.SurfaceCard
import com.shieldguard.ai.ui.theme.TextPrimary
import com.shieldguard.ai.ui.theme.TextSecondary
import com.shieldguard.ai.ui.theme.ThreatCrimson
import com.shieldguard.ai.ui.theme.WarningAmber
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

@HiltViewModel
class NetworkViewModel @Inject constructor(
    private val networkTrafficMonitor: NetworkTrafficMonitor,
    private val preferencesManager: EncryptedPreferencesManager
) : ViewModel() {

    val monitorState: StateFlow<NetworkMonitorState> = networkTrafficMonitor.state

    private val _blockInput = MutableStateFlow("")
    val blockInput: StateFlow<String> = _blockInput.asStateFlow()

    fun onBlockInputChanged(value: String) {
        _blockInput.value = value
    }

    fun startFirewallService(context: Context) {
        val intent = Intent(context, ShieldGuardVpnService::class.java).apply {
            action = ShieldGuardVpnService.ACTION_START
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
        preferencesManager.setVpnProtectionEnabled(true)
    }

    fun stopFirewallService(context: Context) {
        val intent = Intent(context, ShieldGuardVpnService::class.java).apply {
            action = ShieldGuardVpnService.ACTION_STOP
        }
        context.startService(intent)
        preferencesManager.setVpnProtectionEnabled(false)
    }

    fun addBlockRule(context: Context) {
        val hostOrIp = _blockInput.value.trim()
        if (hostOrIp.isEmpty()) return
        networkTrafficMonitor.addBlockedRule(hostOrIp)
        _blockInput.value = ""
        if (monitorState.value.isVpnRunning) {
            val reloadIntent = Intent(context, ShieldGuardVpnService::class.java).apply {
                action = ShieldGuardVpnService.ACTION_RELOAD
            }
            context.startService(reloadIntent)
        }
    }
}

@Composable
fun NetworkProtectionScreen(
    viewModel: NetworkViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    val state by viewModel.monitorState.collectAsState()
    val blockInput by viewModel.blockInput.collectAsState()
    val context = LocalContext.current

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.startFirewallService(context)
        }
    }

    val onToggleFirewall: (Boolean) -> Unit = { enable ->
        if (enable) {
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent != null) {
                vpnPermissionLauncher.launch(prepareIntent)
            } else {
                viewModel.startFirewallService(context)
            }
        } else {
            viewModel.stopFirewallService(context)
        }
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(CyberNavy)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                }
                Spacer(modifier = Modifier.width(8.dp))
                Column {
                    Text("Network Firewall & VPN", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                    Text("Inspects & blocks unauthorized network traffic", fontSize = 12.sp, color = TextSecondary)
                }
            }
        }

        // Firewall Switch Card
        item {
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
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                        Box(
                            modifier = Modifier
                                .size(46.dp)
                                .background(
                                    if (state.isVpnRunning) SafeGreen.copy(alpha = 0.15f) else CardBorder,
                                    CircleShape
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.VpnLock,
                                contentDescription = null,
                                tint = if (state.isVpnRunning) SafeGreen else TextSecondary
                            )
                        }
                        Spacer(modifier = Modifier.width(14.dp))
                        Column {
                            Text("ShieldGuard Firewall Tunnel", fontWeight = FontWeight.Bold, fontSize = 16.sp, color = TextPrimary)
                            Text(
                                text = if (state.isVpnRunning) "ACTIVE • Filtering DNS & Unauthorized IPs" else "STOPPED • Tap to start traffic inspection",
                                fontSize = 12.sp,
                                color = if (state.isVpnRunning) SafeGreen else ThreatCrimson
                            )
                        }
                    }

                    Switch(
                        checked = state.isVpnRunning,
                        onCheckedChange = onToggleFirewall,
                        colors = SwitchDefaults.colors(checkedThumbColor = SafeGreen)
                    )
                }
            }
        }

        if (state.suspiciousNetworkWarning != null) {
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, WarningAmber, RoundedCornerShape(12.dp)),
                    colors = CardDefaults.cardColors(containerColor = SurfaceCard),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Security, contentDescription = null, tint = WarningAmber)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(state.suspiciousNetworkWarning!!, color = WarningAmber, fontSize = 12.sp)
                    }
                }
            }
        }

        // Traffic Stats
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                StatMetricCard(
                    title = "Traffic Scanned",
                    value = "${state.packetsScanned}",
                    iconColor = NeonCyan,
                    modifier = Modifier.weight(1f)
                )
                StatMetricCard(
                    title = "Blocked Hosts",
                    value = "${state.blockedCount}",
                    iconColor = ThreatCrimson,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Custom Block Rule Input
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, CardBorder, RoundedCornerShape(16.dp)),
                colors = CardDefaults.cardColors(containerColor = SurfaceCard),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("Block Unauthorized Domain or IP", fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = TextPrimary)
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedTextField(
                            value = blockInput,
                            onValueChange = { viewModel.onBlockInputChanged(it) },
                            placeholder = { Text("evil.com or 185.x.x.x", color = TextSecondary, fontSize = 12.sp) },
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(10.dp),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = NeonCyan,
                                unfocusedBorderColor = CardBorder,
                                focusedTextColor = TextPrimary,
                                unfocusedTextColor = TextPrimary
                            )
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = { viewModel.addBlockRule(context) },
                            colors = ButtonDefaults.buttonColors(containerColor = ThreatCrimson),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text("BLOCK", fontWeight = FontWeight.Bold, color = TextPrimary)
                        }
                    }
                }
            }
        }

        // Live Traffic Stream Header
        item {
            Text(
                text = "Live Network Traffic Log (${state.recentEvents.size})",
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                color = TextPrimary
            )
        }

        if (state.recentEvents.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(SurfaceCard.copy(alpha = 0.5f), RoundedCornerShape(12.dp))
                        .padding(16.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = if (state.isVpnRunning) "Monitoring live connections... Browse or open an app to see traffic." else "Enable Firewall Tunnel above to scan live traffic.",
                        color = TextSecondary,
                        fontSize = 12.sp
                    )
                }
            }
        } else {
            items(state.recentEvents, key = { it.id }) { event ->
                NetworkEventRow(event)
            }
        }
    }
}

@Composable
private fun NetworkEventRow(event: NetworkTrafficEvent) {
    val isBlocked = event.status == "BLOCKED"
    val color = if (isBlocked) ThreatCrimson else SafeGreen

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, CardBorder, RoundedCornerShape(12.dp)),
        colors = CardDefaults.cardColors(containerColor = SurfaceCard),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = if (isBlocked) Icons.Default.Block else Icons.Default.CheckCircle,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = event.destination,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary
                )
                Text(
                    text = "${event.direction} • ${event.protocol} • ${event.reason}",
                    fontSize = 11.sp,
                    color = TextSecondary
                )
            }
            Text(
                text = event.status,
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                color = color
            )
        }
    }
}
