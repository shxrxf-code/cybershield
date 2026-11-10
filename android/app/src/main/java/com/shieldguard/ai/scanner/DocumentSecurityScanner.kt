package com.shieldguard.ai.scanner

import com.shieldguard.ai.domain.model.ModuleType
import com.shieldguard.ai.domain.model.Threat
import com.shieldguard.ai.domain.model.ThreatLevel
import com.shieldguard.ai.domain.model.Verdict
import java.io.File
import java.io.FileInputStream
import java.util.UUID
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DocumentSecurityScanner @Inject constructor() {

    private val suspiciousPdfTags = listOf("/JavaScript", "/JS", "/Launch", "/EmbeddedFiles", "/OpenAction")

    fun scanDocumentFile(file: File): Threat {
        val extension = file.extension.lowercase()
        val indicators = mutableListOf<String>()
        var riskScore = 0

        when (extension) {
            "pdf" -> {
                scanPdfContent(file, indicators).let { score -> riskScore += score }
            }
            "docx", "xlsx", "pptx", "docm", "xlsm", "pptm" -> {
                scanOfficeContent(file, extension, indicators).let { score -> riskScore += score }
            }
            "apk" -> {
                indicators.add("Sideloaded standalone APK installer file in storage")
                riskScore += 20
            }
            else -> {
                indicators.add("Standard file format verified")
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
            title = "Document Threat: ${file.name}",
            description = if (verdict != Verdict.SAFE) {
                "Detected weaponized macro or exploit stream in ${file.name}"
            } else {
                "File analyzed cleanly. No active exploit vectors detected."
            },
            actionTaken = if (verdict == Verdict.MALICIOUS) "QUARANTINED" else "MONITORED",
            rawPayload = file.absolutePath,
            indicators = indicators,
            timestampMs = System.currentTimeMillis()
        )
    }

    private fun scanPdfContent(file: File, indicators: MutableList<String>): Int {
        var score = 0
        try {
            val content = file.readBytes().toString(Charsets.ISO_8859_1)
            for (tag in suspiciousPdfTags) {
                if (content.contains(tag, ignoreCase = true)) {
                    if (tag.equals("/Launch", ignoreCase = true)) {
                        score += 50
                        indicators.add("Critical: PDF contains /Launch executable action")
                    } else if (tag.equals("/JavaScript", ignoreCase = true) || tag.equals("/JS", ignoreCase = true)) {
                        score += 35
                        indicators.add("PDF contains interactive embedded JavaScript stream")
                    } else {
                        score += 20
                        indicators.add("PDF contains suspicious structural tag: $tag")
                    }
                }
            }
        } catch (e: Exception) {
            indicators.add("Could not parse PDF binary streams: ${e.message}")
        }
        return score
    }

    private fun scanOfficeContent(file: File, extension: String, indicators: MutableList<String>): Int {
        var score = 0
        if (extension in listOf("docm", "xlsm", "pptm")) {
            score += 30
            indicators.add("Macro-enabled Office document format detected ($extension)")
        }

        try {
            ZipInputStream(FileInputStream(file)).use { zip ->
                var entry = zip.nextEntry
                while (entry != null) {
                    val name = entry.name.lowercase()
                    if (name.contains("vbaproject.bin") || name.contains("vba/")) {
                        score += 40
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
        } catch (e: Exception) {
            // Not a valid ZIP container (possibly legacy binary format or encrypted)
        }
        return score
    }
}
