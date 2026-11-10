package com.shieldguard.ai.ui.dashboard

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
import androidx.compose.material.icons.filled.NotificationsActive
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
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
import com.shieldguard.ai.ui.components.SecurityScoreGauge
import com.shieldguard.ai.ui.components.StatMetricCard
import com.shieldguard.ai.ui.components.ThreatItemCard
import com.shieldguard.ai.ui.theme.CardBorder
import com.shieldguard.ai.ui.theme.CyberNavy
import com.shieldguard.ai.ui.theme.NeonCyan
import com.shieldguard.ai.ui.theme.SafeGreen
import com.shieldguard.ai.ui.theme.SurfaceCard
import com.shieldguard.ai.ui.theme.TextPrimary
import com.shieldguard.ai.ui.theme.TextSecondary
import com.shieldguard.ai.ui.theme.ThreatCrimson
import com.shieldguard.ai.ui.theme.WarningAmber

@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel,
    onNavigateToUrlScanner: () -> Unit,
    onNavigateToAppScanner: () -> Unit,
    onNavigateToNetwork: () -> Unit,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(CyberNavy)
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(8.dp))
            // Top App Bar row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "ShieldGuard AI",
                        fontSize = 24.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary
                    )
                    Text(
                        text = "Autonomous Cyber Defense Active",
                        fontSize = 12.sp,
                        color = SafeGreen
                    )
                }

                IconButton(
                    onClick = { viewModel.performInitialAudit() },
                    modifier = Modifier
                        .size(42.dp)
                        .background(SurfaceCard, CircleShape)
                        .border(1.dp, CardBorder, CircleShape)
                ) {
                    if (state.isScanning) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = NeonCyan,
                            strokeWidth = 2.dp
                        )
                    } else {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = "Rescan",
                            tint = NeonCyan
                        )
                    }
                }
            }
        }

        // Circular Security Gauge Card
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, CardBorder, RoundedCornerShape(20.dp)),
                colors = CardDefaults.cardColors(containerColor = SurfaceCard),
                shape = RoundedCornerShape(20.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    SecurityScoreGauge(
                        score = state.securityScore.overallScore,
                        threatLevel = state.securityScore.threatLevel
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    Button(
                        onClick = { viewModel.performInitialAudit() },
                        colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 24.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = CyberNavy
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (state.isScanning) "SCANNING SYSTEM..." else "START FULL DEEP SCAN",
                            fontWeight = FontWeight.Bold,
                            color = CyberNavy
                        )
                    }
                }
            }
        }

        // 2x2 Metric Grid
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                StatMetricCard(
                    title = "Blocked Threats",
                    value = "${state.securityScore.activeThreatsCount}",
                    iconColor = ThreatCrimson,
                    modifier = Modifier.weight(1f)
                )
                StatMetricCard(
                    title = "Scanned Apps",
                    value = "${state.securityScore.scannedAppsCount}",
                    iconColor = NeonCyan,
                    modifier = Modifier.weight(1f)
                )
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                StatMetricCard(
                    title = "Files Scanned",
                    value = "${state.securityScore.scannedFilesCount}",
                    iconColor = SafeGreen,
                    modifier = Modifier.weight(1f)
                )
                StatMetricCard(
                    title = "Network Risk",
                    value = if (state.securityScore.networkProtected) "LOW" else "HIGH",
                    iconColor = if (state.securityScore.networkProtected) SafeGreen else WarningAmber,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Live Protection Toggles
        item {
            Text(
                text = "Real-Time Protection Modules",
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                color = TextPrimary
            )
            Spacer(modifier = Modifier.height(8.dp))

            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, CardBorder, RoundedCornerShape(16.dp)),
                colors = CardDefaults.cardColors(containerColor = SurfaceCard),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    // VPN DNS Shield Toggle
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.VpnKey, contentDescription = null, tint = NeonCyan)
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text("Network DNS Shield & VPN", fontWeight = FontWeight.Medium, color = TextPrimary)
                                Text("Blocks phishing domains & DNS poisoning", fontSize = 12.sp, color = TextSecondary)
                            }
                        }
                        Switch(
                            checked = state.securityScore.networkProtected,
                            onCheckedChange = { viewModel.toggleVpn(it) },
                            colors = SwitchDefaults.colors(checkedThumbColor = NeonCyan)
                        )
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    // Notification Shield Toggle
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.NotificationsActive, contentDescription = null, tint = SafeGreen)
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text("Notification Scam Guard", fontWeight = FontWeight.Medium, color = TextPrimary)
                                Text("Monitors WhatsApp, Telegram & SMS lures", fontSize = 12.sp, color = TextSecondary)
                            }
                        }
                        Switch(
                            checked = state.securityScore.notificationShieldActive,
                            onCheckedChange = { viewModel.toggleNotificationShield(it) },
                            colors = SwitchDefaults.colors(checkedThumbColor = SafeGreen)
                        )
                    }
                }
            }
        }

        // Recent Threat Telemetry
        item {
            Text(
                text = "Live Threat Telemetry",
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                color = TextPrimary
            )
        }

        if (state.recentThreats.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 12.dp)
                        .background(SurfaceCard.copy(alpha = 0.5f), RoundedCornerShape(12.dp))
                        .padding(16.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "No active threats detected. System is secure.",
                        color = TextSecondary,
                        fontSize = 13.sp
                    )
                }
            }
        } else {
            items(state.recentThreats) { threat ->
                ThreatItemCard(threat = threat)
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}
