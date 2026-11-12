package com.shieldguard.ai.scanner

import com.shieldguard.ai.domain.model.ModuleType
import com.shieldguard.ai.domain.model.Threat
import com.shieldguard.ai.domain.model.ThreatLevel
import com.shieldguard.ai.domain.model.Verdict
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.util.UUID
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DocumentSecurityScanner @Inject constructor() {

    private val suspiciousPdfTags = listOf("/JavaScript", "/JS", "/Launch", "/EmbeddedFiles", "/OpenAction")

    private val highRiskArchivePayloads = setOf(".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".hta", ".pif", ".apk")

    private val scriptKeywords = listOf(
        "wscript.shell", "powershell", "urldownloadtofile", "shellexecute",
        "rm -rf /", "chmod +x", "curl http", "wget http"
    )

    companion object {
        private const val MAX_TEXT_SCAN_BYTES = 4 * 1024 * 1024 // 4 MB cap per file stream
    }

    fun scanDocumentFile(file: File): Threat {
        val extension = file.extension.lowercase()
        val indicators = mutableListOf<String>()
        var riskScore = 0

        when (extension) {
            "pdf" -> {
                riskScore += scanPdfContent(file, indicators)
            }
            "docx", "xlsx", "pptx", "docm", "xlsm", "pptm" -> {
                riskScore += scanOfficeContent(file, extension, indicators)
            }
            "zip", "jar" -> {
                riskScore += scanArchiveContent(file, indicators)
            }
            "apk", "xapk", "apks" -> {
                val lowerName = file.name.lowercase()
                if (listOf("mod", "crack", "hack", "cheat", "free_coin", "unlock").any { lowerName.contains(it) }) {
                    riskScore += 75
                    indicators.add("High-risk modified/cracked APK installer package: ${file.name}")
                } else {
                    riskScore += 20
                    indicators.add("Standalone APK installer stored on device: ${file.name}")
                }
            }
            "exe", "scr", "bat", "vbs", "ps1", "hta" -> {
                riskScore += scanScriptOrExecutable(file, extension, indicators)
            }
            "sh", "js" -> {
                riskScore += scanScriptContent(file, indicators)
            }
            else -> {
                // Non-document / media / general files verified cleanly
            }
        }

        riskScore = riskScore.coerceIn(0, 100)

        val verdict = when {
            riskScore >= 70 -> Verdict.MALICIOUS
            riskScore >= 35 -> Verdict.SUSPICIOUS
            else -> Verdict.SAFE
        }

        val threatLevel = when {
            riskScore >= 80 -> ThreatLevel.CRITICAL
            riskScore >= 60 -> ThreatLevel.HIGH
            riskScore >= 35 -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }

        return Threat(
            id = UUID.randomUUID().toString(),
            moduleType = ModuleType.DOCUMENT,
            threatLevel = threatLevel,
            verdict = verdict,
            riskScore = riskScore,
            title = "File Threat: ${file.name}",
            description = if (verdict != Verdict.SAFE) {
                "Suspicious payload or exploit indicator found in ${file.absolutePath}"
            } else {
                "File analyzed cleanly. No active exploit vectors detected."
            },
            actionTaken = if (verdict == Verdict.MALICIOUS) "QUARANTINE_RECOMMENDED" else "MONITORED",
            rawPayload = file.absolutePath,
            indicators = indicators,
            timestampMs = System.currentTimeMillis()
        )
    }

    private fun readBoundedBytes(file: File): String {
        val buffer = ByteArray(minOf(file.length(), MAX_TEXT_SCAN_BYTES.toLong()).toInt().coerceAtLeast(0))
        if (buffer.isEmpty()) return ""
        BufferedInputStream(FileInputStream(file)).use { bis ->
            var offset = 0
            while (offset < buffer.size) {
                val read = bis.read(buffer, offset, buffer.size - offset)
                if (read == -1) break
                offset += read
            }
        }
        return String(buffer, Charsets.ISO_8859_1)
    }

    private fun scanPdfContent(file: File, indicators: MutableList<String>): Int {
        var score = 0
        try {
            val content = readBoundedBytes(file)
            for (tag in suspiciousPdfTags) {
                if (content.contains(tag, ignoreCase = false)) {
                    when (tag) {
                        "/Launch" -> {
                            score += 55
                            indicators.add("Critical PDF Exploit: Contains /Launch command execution tag")
                        }
                        "/JavaScript", "/JS" -> {
                            score += 35
                            indicators.add("PDF contains embedded interactive JavaScript stream ($tag)")
                        }
                        "/OpenAction" -> {
                            score += 15
                            indicators.add("PDF triggers automatic action on open (/OpenAction)")
                        }
                        "/EmbeddedFiles" -> {
                            score += 20
                            indicators.add("PDF embeds secondary hidden files (/EmbeddedFiles)")
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // Unreadable or locked file skipped safely
        }
        return score
    }

    private fun scanOfficeContent(file: File, extension: String, indicators: MutableList<String>): Int {
        var score = 0
        if (extension in listOf("docm", "xlsm", "pptm")) {
            score += 35
            indicators.add("Macro-enabled Office document format ($extension)")
        }

        try {
            ZipInputStream(BufferedInputStream(FileInputStream(file))).use { zip ->
                var entry = zip.nextEntry
                var entriesChecked = 0
                while (entry != null && entriesChecked < 500) {
                    entriesChecked++
                    val name = entry.name.lowercase()
                    if (name.contains("vbaproject.bin") || name.contains("vba/")) {
                        score += 45
                        indicators.add("Embedded VBA Macro bytecode container found (vbaProject.bin)")
                    }
                    if (name.contains("oleobject") || name.contains("embeddings/")) {
                        score += 25
                        indicators.add("Embedded OLE Object / Payload detected")
                    }
                    zip.closeEntry()
                    entry = zip.nextEntry
                }
            }
        } catch (_: Exception) {
            // Encrypted or non-ZIP Office binary
        }
        return score
    }

    private fun scanArchiveContent(file: File, indicators: MutableList<String>): Int {
        var score = 0
        try {
            ZipInputStream(BufferedInputStream(FileInputStream(file))).use { zip ->
                var entry = zip.nextEntry
                var entriesChecked = 0
                while (entry != null && entriesChecked < 500) {
                    entriesChecked++
                    val entryName = entry.name.lowercase()
                    if (highRiskArchivePayloads.any { entryName.endsWith(it) }) {
                        score += 40
                        indicators.add("Archive contains executable/installer payload: ${entry.name}")
                    }
                    if (entryName.contains("vbaproject.bin")) {
                        score += 40
                        indicators.add("Archive contains macro payload: ${entry.name}")
                    }
                    zip.closeEntry()
                    entry = zip.nextEntry
                }
            }
        } catch (_: Exception) {
            // Corrupted or password-protected archive
        }
        return score.coerceAtMost(85)
    }

    private fun scanScriptOrExecutable(file: File, ext: String, indicators: MutableList<String>): Int {
        var score = 40
        indicators.add("Executable/script binary detected in storage (.$ext)")
        if (ext in listOf("vbs", "ps1", "bat", "hta")) {
            score += scanScriptContent(file, indicators)
        }
        return score.coerceAtMost(95)
    }

    private fun scanScriptContent(file: File, indicators: MutableList<String>): Int {
        if (file.length() > MAX_TEXT_SCAN_BYTES) return 0
        var score = 0
        try {
            val content = readBoundedBytes(file).lowercase()
            for (kw in scriptKeywords) {
                if (content.contains(kw)) {
                    score += 35
                    indicators.add("Suspicious command/payload pattern '$kw' in ${file.name}")
                }
            }
        } catch (_: Exception) {
            // Skip unreadable
        }
        return score.coerceAtMost(80)
    }
}
