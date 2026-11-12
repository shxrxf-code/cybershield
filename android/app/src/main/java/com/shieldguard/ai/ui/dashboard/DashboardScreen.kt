package com.shieldguard.ai.ui.dashboard

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.provider.Settings
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
import androidx.compose.material.icons.filled.FolderOpen
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
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.shieldguard.ai.domain.model.Verdict
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
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.startVpnFirewall(context)
        }
    }

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                viewModel.refreshStoragePermission()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
        }
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(CyberNavy)
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(8.dp))
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
                    onClick = { viewModel.performFullDeepScan() },
                    enabled = !state.isScanning,
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

        // All-Files Storage Access Banner (Android 11+) if not granted
        if (!state.hasAllFilesAccess && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, WarningAmber.copy(alpha = 0.5f), RoundedCornerShape(14.dp)),
                    colors = CardDefaults.cardColors(containerColor = SurfaceCard),
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text(
                            text = "Full Storage Access Required for Deep File Scan",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            color = WarningAmber
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Grant 'All files access' so ShieldGuard can inspect every document, APK, ZIP, and folder on your phone.",
                            fontSize = 12.sp,
                            color = TextSecondary
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        OutlinedButton(
                            onClick = {
                                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                                    data = Uri.parse("package:${context.packageName}")
                                }
                                context.startActivity(intent)
                            },
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.FolderOpen, contentDescription = null, tint = WarningAmber)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("GRANT ALL FILES ACCESS", color = WarningAmber, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }

        // Notification Listener Access Banner if not granted
        if (!state.hasNotificationAccess) {
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, NeonCyan.copy(alpha = 0.55f), RoundedCornerShape(14.dp)),
                    colors = CardDefaults.cardColors(containerColor = SurfaceCard),
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text(
                            text = "Notification & Chat URL Access Required",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            color = NeonCyan
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Enable Notification Access so ShieldGuard can monitor notifications from ALL apps and inspect WhatsApp, Telegram, SMS & chat messages for dangerous links.",
                            fontSize = 12.sp,
                            color = TextSecondary
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        OutlinedButton(
                            onClick = {
                                context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                            },
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.NotificationsActive, contentDescription = null, tint = NeonCyan)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("GRANT NOTIFICATION ACCESS", color = NeonCyan, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }

        // Circular Security Gauge + Live Scan Progress Card
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

                    if (state.isScanning) {
                        Spacer(modifier = Modifier.height(12.dp))
                        LinearProgressIndicator(
                            progress = { state.scanProgress },
                            color = NeonCyan,
                            trackColor = CardBorder,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 24.dp)
                                .height(6.dp)
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = state.scanStatusMessage,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Medium,
                            color = NeonCyan,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 24.dp)
                        )
                        if (state.liveCurrentItem.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = state.liveCurrentItem,
                                fontSize = 11.sp,
                                color = TextSecondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 24.dp)
                            )
                        }
                    } else if (state.lastScanSummary != null) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = state.lastScanSummary!!,
                            fontSize = 12.sp,
                            color = SafeGreen,
                            fontWeight = FontWeight.Medium,
                            modifier = Modifier.padding(horizontal = 24.dp)
                        )
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Button(
                        onClick = { viewModel.performFullDeepScan() },
                        enabled = !state.isScanning,
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
                            text = if (state.isScanning) "SCANNING ENTIRE DEVICE..." else "START FULL DEEP SCAN",
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
                    title = "Active Alerts",
                    value = "${state.securityScore.activeThreatsCount}",
                    iconColor = if (state.securityScore.activeThreatsCount > 0) ThreatCrimson else SafeGreen,
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
                    value = if (state.securityScore.networkProtected) "LOW" else "MEDIUM",
                    iconColor = if (state.securityScore.networkProtected) SafeGreen else WarningAmber,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Device Integrity Findings Card
        state.deviceAudit?.let { audit ->
            item {
                Text(
                    text = "Device Security Audit (${audit.posture})",
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
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        AuditStatusRow("Root / Magisk Status", if (audit.isRooted) "ROOTED (Risk)" else "Clean", !audit.isRooted)
                        AuditStatusRow("USB Debugging (ADB)", if (audit.usbDebuggingEnabled) "Enabled (Dev)" else "Disabled", !audit.usbDebuggingEnabled)
                        AuditStatusRow("Developer Mode", if (audit.developerModeEnabled) "Enabled" else "Disabled", !audit.developerModeEnabled)
                        AuditStatusRow("Accessibility Services", "${audit.accessibilityAppsCount} active", audit.accessibilityAppsCount <= 2)
                        if (audit.recommendations.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "• ${audit.recommendations.first()}",
                                fontSize = 12.sp,
                                color = WarningAmber
                            )
                        }
                    }
                }
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
                            onCheckedChange = { enable ->
                                if (enable) {
                                    val prepareIntent = VpnService.prepare(context)
                                    if (prepareIntent != null) {
                                        vpnPermissionLauncher.launch(prepareIntent)
                                    } else {
                                        viewModel.startVpnFirewall(context)
                                    }
                                } else {
                                    viewModel.stopVpnFirewall(context)
                                }
                            },
                            colors = SwitchDefaults.colors(checkedThumbColor = NeonCyan)
                        )
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.NotificationsActive, contentDescription = null, tint = SafeGreen)
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text("Notification & Chat URL Guard", fontWeight = FontWeight.Medium, color = TextPrimary)
                                Text("Monitors ALL apps & messaging chats for URLs", fontSize = 12.sp, color = TextSecondary)
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

        // Notification & Chat URL Monitor Feed
        item {
            val notifState = state.notificationMonitorState
            Text(
                text = "Notification & Chat URL Monitor",
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
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = if (state.hasNotificationAccess) "LISTENER ACTIVE (ALL APPS)" else "LISTENER DISABLED",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (state.hasNotificationAccess) SafeGreen else WarningAmber
                        )
                        Text(
                            text = "${notifState.notificationsScannedCount} msgs • ${notifState.urlsDetectedCount} URLs • ${notifState.threatsBlockedCount} alerts",
                            fontSize = 11.sp,
                            color = TextSecondary
                        )
                    }

                    if (notifState.recentNotifications.isEmpty()) {
                        Text(
                            text = if (state.hasNotificationAccess) {
                                "Listening for notifications and messaging app chats. Incoming URLs will appear here automatically."
                            } else {
                                "Grant Notification Access above to inspect notifications and chat messages across all apps."
                            },
                            fontSize = 12.sp,
                            color = TextSecondary
                        )
                    } else {
                        notifState.recentNotifications.take(5).forEach { event ->
                            val verdictColor = when (event.verdict) {
                                Verdict.MALICIOUS -> ThreatCrimson
                                Verdict.SUSPICIOUS -> WarningAmber
                                Verdict.SAFE -> SafeGreen
                            }
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(CyberNavy.copy(alpha = 0.55f), RoundedCornerShape(10.dp))
                                    .padding(10.dp),
                                verticalArrangement = Arrangement.spacedBy(2.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        text = "${event.appLabel} • ${event.senderOrTitle}",
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = TextPrimary,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        modifier = Modifier.weight(1f)
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = event.verdict.name,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = verdictColor
                                    )
                                }
                                if (event.detectedUrls.isNotEmpty()) {
                                    Text(
                                        text = "URLs: ${event.detectedUrls.joinToString(", ")}",
                                        fontSize = 11.sp,
                                        color = NeonCyan,
                                        maxLines = 2,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                } else {
                                    Text(
                                        text = event.messageSnippet,
                                        fontSize = 11.sp,
                                        color = TextSecondary,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                        }
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

@Composable
private fun AuditStatusRow(label: String, value: String, isHealthy: Boolean) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(text = label, fontSize = 13.sp, color = TextSecondary)
        Text(
            text = value,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
            color = if (isHealthy) SafeGreen else WarningAmber
        )
    }
}
