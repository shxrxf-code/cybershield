package com.shieldguard.ai.scanner

import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import com.shieldguard.ai.domain.model.Threat
import com.shieldguard.ai.domain.model.Verdict
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.util.ArrayDeque
import javax.inject.Inject
import javax.inject.Singleton

data class FullFileScanSummary(
    val totalFilesScanned: Int,
    val inspectableFilesScanned: Int,
    val threats: List<Threat>,
    val usedAllFilesAccess: Boolean
)

@Singleton
class FullDeviceFileScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val documentSecurityScanner: DocumentSecurityScanner
) {

    private val inspectableExtensions = setOf(
        "pdf", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm",
        "zip", "jar", "apk", "xapk", "apks",
        "exe", "scr", "bat", "vbs", "ps1", "hta", "sh", "js"
    )

    fun hasAllFilesAccess(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            true
        }
    }

    fun scanEntireDeviceStorage(
        onProgress: (filesScanned: Int, threatsFound: Int, currentPath: String) -> Unit
    ): FullFileScanSummary {
        val hasAllAccess = hasAllFilesAccess()
        val visitedPaths = HashSet<String>()
        val threats = mutableListOf<Threat>()
        var totalFiles = 0
        var inspectableFiles = 0

        // 1. Recursive BFS traversal of all accessible directories on External Storage + App Storage
        val roots = mutableListOf<File>()
        @Suppress("DEPRECATION")
        Environment.getExternalStorageDirectory()?.let { roots.add(it) }
        context.filesDir?.let { roots.add(it) }
        context.cacheDir?.let { roots.add(it) }

        val queue = ArrayDeque<File>()
        for (root in roots) {
            if (root.exists() && root.canRead()) {
                queue.add(root)
            }
        }

        while (queue.isNotEmpty()) {
            val dir = queue.removeFirst()
            val canonical = runCatching { dir.canonicalPath }.getOrNull() ?: continue
            if (!visitedPaths.add(canonical)) continue

            val children = dir.listFiles() ?: continue
            for (child in children) {
                if (child.isDirectory) {
                    if (child.canRead()) {
                        queue.add(child)
                    }
                } else if (child.isFile) {
                    val fileCanonical = runCatching { child.canonicalPath }.getOrNull() ?: child.absolutePath
                    if (!visitedPaths.add(fileCanonical)) continue

                    totalFiles++
                    val ext = child.extension.lowercase()
                    if (ext in inspectableExtensions) {
                        inspectableFiles++
                        val threat = documentSecurityScanner.scanDocumentFile(child)
                        if (threat.verdict != Verdict.SAFE) {
                            threats.add(threat)
                        }
                    }

                    if (totalFiles % 25 == 0) {
                        onProgress(totalFiles, threats.size, child.name)
                    }
                }
            }
        }

        // 2. Fallback / supplement via MediaStore.Files if All Files Access is not yet granted
        if (!hasAllAccess) {
            scanViaMediaStore(visitedPaths, threats) { count, name ->
                totalFiles += count
                onProgress(totalFiles, threats.size, name)
            }
        }

        onProgress(totalFiles, threats.size, "Storage scan finished")
        return FullFileScanSummary(
            totalFilesScanned = totalFiles,
            inspectableFilesScanned = inspectableFiles,
            threats = threats,
            usedAllFilesAccess = hasAllAccess
        )
    }

    private fun scanViaMediaStore(
        visitedPaths: HashSet<String>,
        threats: MutableList<Threat>,
        onBatchProgress: (addedCount: Int, lastName: String) -> Unit
    ) {
        try {
            val uri = MediaStore.Files.getContentUri("external")
            val projection = arrayOf(MediaStore.Files.FileColumns.DATA)
            context.contentResolver.query(uri, projection, null, null, null)?.use { cursor ->
                val dataCol = cursor.getColumnIndexOrThrow(MediaStore.Files.FileColumns.DATA)
                var batch = 0
                var lastName = ""
                while (cursor.moveToNext()) {
                    val path = cursor.getString(dataCol) ?: continue
                    val file = File(path)
                    if (!file.exists() || !file.isFile) continue
                    val canonical = runCatching { file.canonicalPath }.getOrNull() ?: file.absolutePath
                    if (!visitedPaths.add(canonical)) continue

                    batch++
                    lastName = file.name
                    val ext = file.extension.lowercase()
                    if (ext in inspectableExtensions && file.canRead()) {
                        val threat = documentSecurityScanner.scanDocumentFile(file)
                        if (threat.verdict != Verdict.SAFE) {
                            threats.add(threat)
                        }
                    }

                    if (batch >= 25) {
                        onBatchProgress(batch, lastName)
                        batch = 0
                    }
                }
                if (batch > 0) {
                    onBatchProgress(batch, lastName)
                }
            }
        } catch (_: Exception) {
            // MediaStore query restricted
        }
    }
}
