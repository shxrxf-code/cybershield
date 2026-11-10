package com.shieldguard.ai.ui.scanners

import android.content.Intent
import android.net.Uri
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import com.shieldguard.ai.domain.model.AppThreatInfo
import com.shieldguard.ai.domain.model.Verdict
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
fun AppScannerScreen(
    viewModel: AppScannerViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(CyberNavy)
            .padding(16.dp)
    ) {
        // Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = onBack) {
                    Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                }
                Spacer(modifier = Modifier.width(6.dp))
                Column {
                    Text("APK Malware Scanner", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                    Text("${state.installedApps.size} apps scanned • ${state.flaggedCount} flagged", fontSize = 12.sp, color = TextSecondary)
                }
            }

            IconButton(onClick = { viewModel.scanInstalledApplications() }) {
                if (state.isScanning) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), color = NeonCyan, strokeWidth = 2.dp)
                } else {
                    Icon(Icons.Default.Refresh, contentDescription = "Rescan", tint = NeonCyan)
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // App list
        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.fillMaxSize()
        ) {
            items(state.installedApps) { app ->
                AppThreatCard(
                    app = app,
                    onUninstall = {
                        val intent = Intent(Intent.ACTION_DELETE).apply {
                            data = Uri.parse("package:${app.packageName}")
                        }
                        context.startActivity(intent)
                    }
                )
            }
        }
    }
}

@Composable
fun AppThreatCard(
    app: AppThreatInfo,
    onUninstall: () -> Unit,
    modifier: Modifier = Modifier
) {
    val badgeColor = when (app.verdict) {
        Verdict.MALICIOUS -> ThreatCrimson
        Verdict.SUSPICIOUS -> WarningAmber
        Verdict.SAFE -> SafeGreen
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, CardBorder, RoundedCornerShape(14.dp)),
        colors = CardDefaults.cardColors(containerColor = SurfaceCard),
        shape = RoundedCornerShape(14.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(app.appName, fontWeight = FontWeight.Bold, fontSize = 15.sp, color = TextPrimary)
                    Text(app.packageName, fontSize = 11.sp, color = TextSecondary)
                }
                Box(
                    modifier = Modifier
                        .background(badgeColor.copy(alpha = 0.15f), RoundedCornerShape(8.dp))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(app.verdict.name, color = badgeColor, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }

            if (app.malwareFamilies.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                for (family in app.malwareFamilies) {
                    Text("• Malware Signature: $family", color = ThreatCrimson, fontSize = 12.sp, fontWeight = FontWeight.Medium)
                }
            }

            if (app.dangerousPermissions.isNotEmpty()) {
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Risky Permissions: " + app.dangerousPermissions.take(4).joinToString(", "),
                    color = WarningAmber,
                    fontSize = 11.sp
                )
            }

            if (app.verdict == Verdict.MALICIOUS) {
                Spacer(modifier = Modifier.height(10.dp))
                Button(
                    onClick = onUninstall,
                    colors = ButtonDefaults.buttonColors(containerColor = ThreatCrimson),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Default.Delete, contentDescription = null, tint = TextPrimary)
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("UNINSTALL MALICIOUS APP", fontWeight = FontWeight.Bold, color = TextPrimary)
                }
            }
        }
    }
}
