package com.cybershield.cybershield_client

import android.content.pm.PackageManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            "cybershield.device/apps"
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "listInstalledApps" -> result.success(listInstalledApps())
                else -> result.notImplemented()
            }
        }
    }

    /**
     * Informational package-manager listing: package name, display label,
     * version and permissions *declared* in the manifest. Nothing is read
     * from app data and nothing is executed.
     */
    private fun listInstalledApps(): List<Map<String, Any>> {
        val pm = packageManager
        val installed = pm.getInstalledApplications(0)
        val out = mutableListOf<Map<String, Any>>()
        for (app in installed) {
            val label = try {
                pm.getApplicationLabel(app).toString()
            } catch (_: Exception) {
                app.packageName
            }
            val versionName = try {
                pm.getPackageInfo(app.packageName, 0).versionName ?: ""
            } catch (_: Exception) {
                ""
            }
            val permissions = try {
                pm.getPackageInfo(app.packageName, PackageManager.GET_PERMISSIONS)
                    ?.requestedPermissions?.toList() ?: emptyList()
            } catch (_: Exception) {
                emptyList<String>()
            }
            out.add(
                mapOf(
                    "packageName" to app.packageName,
                    "label" to label,
                    "versionName" to versionName,
                    "requestedPermissions" to permissions
                )
            )
        }
        return out.sortedBy { (it["label"] as String).lowercase() }
    }
}