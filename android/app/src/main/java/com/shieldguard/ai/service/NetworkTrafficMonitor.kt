package com.shieldguard.ai.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

data class NetworkTrafficEvent(
    val id: String,
    val destination: String,
    val direction: String, // OUTBOUND / INBOUND
    val protocol: String,  // DNS / UDP / TCP
    val status: String,    // ALLOWED / BLOCKED
    val reason: String,
    val timestampMs: Long
)

data class NetworkMonitorState(
    val isVpnRunning: Boolean = false,
    val packetsScanned: Int = 0,
    val blockedCount: Int = 0,
    val allowedCount: Int = 0,
    val suspiciousNetworkWarning: String? = null,
    val blockedHosts: Set<String> = emptySet(),
    val recentEvents: List<NetworkTrafficEvent> = emptyList()
)

@Singleton
class NetworkTrafficMonitor @Inject constructor() {

    private val defaultUnauthorizedDomains = setOf(
        "doubleclick.net",
        "adservice.google.com",
        "analytics.tiktok.com",
        "tracking.miui.com",
        "metrics.icloud.com",
        "paypa1-security-verify.xyz",
        "binance-airdrop-claim.top",
        "metamask-verify-wallet.click",
        "chase-login-alert.xyz",
        "eicar.org"
    )

    private val highRiskTlds = setOf(
        "tk", "ml", "ga", "cf", "gq", "buzz", "click", "top", "work", "loan", "bid"
    )

    private val suspiciousKeywords = listOf(
        "phish", "malware", "c2-", "rat-", "stealer", "airdrop-claim",
        "verify-wallet", "bank-login", "free-crypto", "keylogger"
    )

    // Known unauthorized / sinkholed IP addresses (C2 / test threat feeds)
    private val defaultUnauthorizedIps = setOf(
        "185.220.101.1",
        "45.155.205.233",
        "194.26.135.120",
        "91.92.240.15"
    )

    private val customBlockedHosts = mutableSetOf<String>()
    private val customBlockedIps = mutableSetOf<String>()

    private val _state = MutableStateFlow(
        NetworkMonitorState(blockedHosts = defaultUnauthorizedDomains)
    )
    val state: StateFlow<NetworkMonitorState> = _state.asStateFlow()

    fun setVpnRunning(running: Boolean) {
        _state.value = _state.value.copy(isVpnRunning = running)
    }

    fun setNetworkWarning(warning: String?) {
        _state.value = _state.value.copy(suspiciousNetworkWarning = warning)
    }

    fun addBlockedRule(hostOrIp: String) {
        val clean = hostOrIp.trim().lowercase()
        if (clean.isEmpty()) return
        val ipRegex = Regex("""^(\d{1,3}\.){3}\d{1,3}$""")
        if (ipRegex.matches(clean)) {
            customBlockedIps.add(clean)
        } else {
            customBlockedHosts.add(clean)
        }
        _state.value = _state.value.copy(
            blockedHosts = defaultUnauthorizedDomains + customBlockedHosts + customBlockedIps
        )
    }

    fun removeBlockedRule(hostOrIp: String) {
        val clean = hostOrIp.trim().lowercase()
        customBlockedHosts.remove(clean)
        customBlockedIps.remove(clean)
        _state.value = _state.value.copy(
            blockedHosts = defaultUnauthorizedDomains + customBlockedHosts + customBlockedIps
        )
    }

    fun getAllBlockedIps(): Set<String> = defaultUnauthorizedIps + customBlockedIps

    fun evaluateDomain(domain: String): Pair<Boolean, String> {
        val clean = domain.trim().lowercase().trimEnd('.')
        if (clean.isEmpty()) return Pair(false, "Empty query")

        // 1. Exact or subdomain match against unauthorized hosts
        val allBlocked = defaultUnauthorizedDomains + customBlockedHosts
        for (blocked in allBlocked) {
            if (clean == blocked || clean.endsWith(".$blocked")) {
                return Pair(true, "Blocked unauthorized host ($blocked)")
            }
        }

        // 2. Punycode homograph attack check
        if (clean.startsWith("xn--") || clean.contains(".xn--")) {
            return Pair(true, "Blocked Punycode / Homograph spoofed domain")
        }

        // 3. Suspicious phishing/C2 keyword pattern
        for (kw in suspiciousKeywords) {
            if (clean.contains(kw)) {
                return Pair(true, "Blocked malicious/phishing pattern '$kw'")
            }
        }

        // 4. High-risk disposable phishing TLDs
        val tld = clean.substringAfterLast('.', "")
        if (tld in highRiskTlds) {
            return Pair(true, "Blocked unauthorized high-risk TLD (.$tld)")
        }

        return Pair(false, "Authorized domain")
    }

    fun recordEvent(event: NetworkTrafficEvent) {
        val current = _state.value
        val isBlocked = event.status == "BLOCKED"
        val updatedEvents = (listOf(event) + current.recentEvents).take(40)
        _state.value = current.copy(
            packetsScanned = current.packetsScanned + 1,
            blockedCount = if (isBlocked) current.blockedCount + 1 else current.blockedCount,
            allowedCount = if (!isBlocked) current.allowedCount + 1 else current.allowedCount,
            recentEvents = updatedEvents
        )
    }
}
