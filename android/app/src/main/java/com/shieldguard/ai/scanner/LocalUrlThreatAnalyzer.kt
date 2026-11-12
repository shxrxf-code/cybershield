package com.shieldguard.ai.scanner

import com.shieldguard.ai.domain.model.ModuleType
import com.shieldguard.ai.domain.model.Threat
import com.shieldguard.ai.domain.model.ThreatLevel
import com.shieldguard.ai.domain.model.Verdict
import com.shieldguard.ai.service.NetworkTrafficMonitor
import java.net.URI
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class LocalUrlThreatAnalyzer @Inject constructor(
    private val networkTrafficMonitor: NetworkTrafficMonitor
) {

    private val popularBrands = listOf(
        "google", "apple", "microsoft", "amazon", "paypal", "netflix",
        "chase", "bankofamerica", "wellsfargo", "facebook", "instagram",
        "whatsapp", "telegram", "binance", "coinbase", "metamask", "flipkart", "myntra"
    )

    private val phishingKeywords = listOf(
        "login", "verify", "secure", "account", "banking", "update",
        "signin", "confirm", "wallet", "suspend", "airdrop", "claim",
        "reward", "gift", "kyc", "otp", "password", "bonus", "prize"
    )

    private val shorteners = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rb.gy", "cutt.ly", "shorturl.at"
    )

    fun extractUrls(text: String): List<String> {
        val results = LinkedHashSet<String>()
        val fullUrlRegex = Regex("""https?://[^\s<>"{}|\\^`\[\]]+""", RegexOption.IGNORE_CASE)
        fullUrlRegex.findAll(text).forEach { match ->
            results.add(match.value.trimEnd('.', ',', ')', ']', '!', '?'))
        }

        val domainUrlRegex = Regex(
            """\b(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:com|net|org|xyz|top|tk|ml|ga|cf|gq|click|buzz|work|loan|bid|info|io|co|in|me|ly|ru)(?:/[^\s<>"{}|\\^`\[\]]*)?""",
            RegexOption.IGNORE_CASE
        )
        domainUrlRegex.findAll(text).forEach { match ->
            val candidate = match.value.trimEnd('.', ',', ')', ']', '!', '?')
            if (results.none { it.contains(candidate, ignoreCase = true) }) {
                results.add("http://$candidate")
            }
        }
        return results.toList()
    }

    fun analyzeUrl(rawUrl: String): Threat {
        val normalizedUrl = if (rawUrl.startsWith("http://", true) || rawUrl.startsWith("https://", true)) {
            rawUrl.trim()
        } else {
            "http://${rawUrl.trim()}"
        }

        val uri = runCatching { URI(normalizedUrl) }.getOrNull()
        val host = (uri?.host ?: normalizedUrl.substringAfter("://").substringBefore("/")).lowercase()
        val lowerUrl = normalizedUrl.lowercase()

        var score = 0
        val indicators = mutableListOf<String>()

        // 1. Check NetworkTrafficMonitor domain policy
        val (domainBlocked, domainReason) = networkTrafficMonitor.evaluateDomain(host)
        if (domainBlocked) {
            score += 55
            indicators.add(domainReason)
        }

        // 2. Raw IP address host check
        if (Regex("""^(\d{1,3}\.){3}\d{1,3}$""").matches(host)) {
            score += 40
            indicators.add("Uses raw IP address instead of verified domain ($host)")
        }

        // 3. Direct executable / APK download URL
        if (lowerUrl.endsWith(".apk") || lowerUrl.endsWith(".exe") || lowerUrl.endsWith(".bat") || lowerUrl.contains(".apk?")) {
            score += 45
            indicators.add("Direct executable/APK download link detected")
        }

        // 4. Typosquatting check against major brands
        val mainLabel = host.split(".").dropLast(1).lastOrNull() ?: host
        for (brand in popularBrands) {
            if (mainLabel != brand && isCloseTypo(mainLabel, brand)) {
                score += 45
                indicators.add("Typosquatting attempt resembling '$brand'")
                break
            }
        }

        // 5. Phishing keywords in URL path/host
        val kwHits = phishingKeywords.filter { lowerUrl.contains(it) }
        if (kwHits.isNotEmpty()) {
            score += (kwHits.size * 12).coerceAtMost(36)
            indicators.add("Suspicious keywords in link: ${kwHits.joinToString(", ")}")
        }

        // 6. URL Shortener warning
        if (shorteners.any { host == it || host.endsWith(".$it") }) {
            score += 20
            indicators.add("Shortened URL hides true destination ($host)")
        }

        // 7. Insecure HTTP on sensitive path
        if (normalizedUrl.startsWith("http://", true) && kwHits.isNotEmpty()) {
            score += 15
            indicators.add("Unencrypted HTTP connection requesting sensitive action")
        }

        score = score.coerceIn(0, 100)

        val verdict = when {
            score >= 70 -> Verdict.MALICIOUS
            score >= 35 -> Verdict.SUSPICIOUS
            else -> Verdict.SAFE
        }

        val threatLevel = when {
            score >= 85 -> ThreatLevel.CRITICAL
            score >= 65 -> ThreatLevel.HIGH
            score >= 35 -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }

        return Threat(
            id = UUID.randomUUID().toString(),
            moduleType = ModuleType.URL,
            threatLevel = threatLevel,
            verdict = verdict,
            riskScore = score,
            title = when (verdict) {
                Verdict.MALICIOUS -> "Phishing / Malicious Link Blocked"
                Verdict.SUSPICIOUS -> "Suspicious Link Detected"
                Verdict.SAFE -> "Verified Safe URL"
            },
            description = indicators.firstOrNull() ?: "Domain $host passed local security inspection.",
            actionTaken = if (verdict == Verdict.MALICIOUS) "BLOCKED" else if (verdict == Verdict.SUSPICIOUS) "WARNED" else "ALLOWED",
            rawPayload = normalizedUrl,
            indicators = if (indicators.isEmpty()) listOf("Clean domain structure: $host") else indicators,
            timestampMs = System.currentTimeMillis()
        )
    }

    private fun isCloseTypo(a: String, b: String): Boolean {
        if (kotlin.math.abs(a.length - b.length) > 2) return false
        val normalizedA = a.replace('1', 'l').replace('0', 'o').replace('3', 'e').replace('5', 's')
        if (normalizedA == b && a != b) return true
        // Simple Levenshtein distance <= 2 for brands >= 5 chars
        if (b.length < 5) return false
        return levenshtein(a, b) in 1..2
    }

    private fun levenshtein(lhs: String, rhs: String): Int {
        val m = lhs.length
        val n = rhs.length
        val dp = Array(m + 1) { IntArray(n + 1) }
        for (i in 0..m) dp[i][0] = i
        for (j in 0..n) dp[0][j] = j
        for (i in 1..m) {
            for (j in 1..n) {
                val cost = if (lhs[i - 1] == rhs[j - 1]) 0 else 1
                dp[i][j] = minOf(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
            }
        }
        return dp[m][n]
    }
}
