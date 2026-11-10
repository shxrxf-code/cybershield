package com.shieldguard.ai.ui.navigation

sealed class Screen(val route: String, val title: String) {
    object Dashboard : Screen("dashboard", "Dashboard")
    object UrlScanner : Screen("url_scanner", "URL Shield")
    object AppScanner : Screen("app_scanner", "App Audit")
    object NetworkProtection : Screen("network_protection", "Network Shield")
    object Reports : Screen("reports", "Reports")
}
