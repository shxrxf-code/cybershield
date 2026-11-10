package com.shieldguard.ai.ui.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import com.shieldguard.ai.ui.dashboard.DashboardScreen
import com.shieldguard.ai.ui.dashboard.DashboardViewModel
import com.shieldguard.ai.ui.network.NetworkProtectionScreen
import com.shieldguard.ai.ui.network.NetworkViewModel
import com.shieldguard.ai.ui.reports.ReportsScreen
import com.shieldguard.ai.ui.reports.ReportsViewModel
import com.shieldguard.ai.ui.scanners.AppScannerScreen
import com.shieldguard.ai.ui.scanners.AppScannerViewModel
import com.shieldguard.ai.ui.scanners.UrlScannerScreen
import com.shieldguard.ai.ui.scanners.UrlScannerViewModel
import com.shieldguard.ai.ui.theme.CardBorder
import com.shieldguard.ai.ui.theme.NeonCyan
import com.shieldguard.ai.ui.theme.SurfaceCard
import com.shieldguard.ai.ui.theme.TextPrimary
import com.shieldguard.ai.ui.theme.TextSecondary

data class NavItem(val screen: Screen, val icon: ImageVector)

val navItems = listOf(
    NavItem(Screen.Dashboard, Icons.Default.Security),
    NavItem(Screen.UrlScanner, Icons.Default.Language),
    NavItem(Screen.AppScanner, Icons.Default.Apps),
    NavItem(Screen.NetworkProtection, Icons.Default.VpnLock),
    NavItem(Screen.Reports, Icons.Default.Assessment)
)

@Composable
fun MainNavGraph(
    navController: NavHostController,
    modifier: Modifier = Modifier
) {
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    Scaffold(
        bottomBar = {
            NavigationBar(
                containerColor = SurfaceCard,
                tonalElevation = androidx.compose.ui.unit.Dp(0f)
            ) {
                navItems.forEach { item ->
                    val selected = currentRoute == item.screen.route
                    NavigationBarItem(
                        selected = selected,
                        onClick = {
                            if (currentRoute != item.screen.route) {
                                navController.navigate(item.screen.route) {
                                    popUpTo(Screen.Dashboard.route) { saveState = true }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            }
                        },
                        icon = { Icon(item.icon, contentDescription = item.screen.title) },
                        label = { Text(item.screen.title) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = NeonCyan,
                            selectedTextColor = NeonCyan,
                            unselectedIconColor = TextSecondary,
                            unselectedTextColor = TextSecondary,
                            indicatorColor = SurfaceCard
                        )
                    )
                }
            }
        }
    ) { paddingValues ->
        NavHost(
            navController = navController,
            startDestination = Screen.Dashboard.route,
            modifier = modifier.padding(paddingValues)
        ) {
            composable(Screen.Dashboard.route) {
                val viewModel: DashboardViewModel = hiltViewModel()
                DashboardScreen(
                    viewModel = viewModel,
                    onNavigateToUrlScanner = { navController.navigate(Screen.UrlScanner.route) },
                    onNavigateToAppScanner = { navController.navigate(Screen.AppScanner.route) },
                    onNavigateToNetwork = { navController.navigate(Screen.NetworkProtection.route) }
                )
            }
            composable(Screen.UrlScanner.route) {
                val viewModel: UrlScannerViewModel = hiltViewModel()
                UrlScannerScreen(
                    viewModel = viewModel,
                    onBack = { navController.popBackStack() }
                )
            }
            composable(Screen.AppScanner.route) {
                val viewModel: AppScannerViewModel = hiltViewModel()
                AppScannerScreen(
                    viewModel = viewModel,
                    onBack = { navController.popBackStack() }
                )
            }
            composable(Screen.NetworkProtection.route) {
                val viewModel: NetworkViewModel = hiltViewModel()
                NetworkProtectionScreen(
                    viewModel = viewModel,
                    onBack = { navController.popBackStack() }
                )
            }
            composable(Screen.Reports.route) {
                val viewModel: ReportsViewModel = hiltViewModel()
                ReportsScreen(
                    viewModel = viewModel,
                    onBack = { navController.popBackStack() }
                )
            }
        }
    }
}
