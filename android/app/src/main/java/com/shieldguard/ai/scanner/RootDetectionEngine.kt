package com.shieldguard.ai.scanner

import android.content.Context
import android.os.Build
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class RootDetectionEngine @Inject constructor(
    @ApplicationContext private val context: Context
) {

    private val suBinaryPaths = listOf(
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su"
    )

    private val dangerousPackages = listOf(
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.zachspong.temprootremovejb",
        "com.ramdroid.appquarantine",
        "com.topjohnwu.magisk"
    )

    fun checkRootStatus(): Pair<Boolean, List<String>> {
        val indicators = mutableListOf<String>()

        if (checkTestKeys()) {
            indicators.add("OS build tags contain 'test-keys' (Custom / Unofficial ROM)")
        }

        if (checkSuBinaries()) {
            indicators.add("Root Superuser 'su' binary found in system executable paths")
        }

        if (checkDangerousRootApps()) {
            indicators.add("Superuser / Magisk root management application installed")
        }

        if (checkSuCanExecute()) {
            indicators.add("Able to execute root shell command (su)")
        }

        val isRooted = indicators.isNotEmpty()
        return Pair(isRooted, indicators)
    }

    private fun checkTestKeys(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun checkSuBinaries(): Boolean {
        for (path in suBinaryPaths) {
            if (File(path).exists()) {
                return true
            }
        }
        return false
    }

    private fun checkDangerousRootApps(): Boolean {
        val pm = context.packageManager
        for (pkg in dangerousPackages) {
            try {
                pm.getPackageInfo(pkg, 0)
                return true
            } catch (e: Exception) {
                // Not found
            }
        }
        return false
    }

    private fun checkSuCanExecute(): Boolean {
        var process: Process? = null
        return try {
            process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val reader = process.inputStream.bufferedReader()
            reader.readLine() != null
        } catch (t: Throwable) {
            false
        } finally {
            process?.destroy()
        }
    }
}
