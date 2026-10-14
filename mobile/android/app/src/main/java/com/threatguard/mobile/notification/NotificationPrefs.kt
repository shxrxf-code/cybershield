package com.threatguard.mobile.notification

import android.content.Context
import android.content.pm.PackageManager

/**
 * Small preferences store shared between the notification listener service and
 * the RN bridge module.
 *
 * The service runs even when no React context is alive, so the user's choices
 * (monitoring on/off and the per-app ignore list) are mirrored here in plain
 * SharedPreferences. The message itself is never written here — only the list of
 * packages that have posted a notification, so the UI can offer per-app toggles.
 */
object NotificationPrefs {

    private const val PREFS = "threatguard_notification_monitor"
    private const val KEY_ENABLED = "monitoring_enabled"
    private const val KEY_IGNORED = "ignored_packages"
    private const val KEY_SEEN = "seen_sources"

    /** Field separator for the seen-source entries (never appears in a label). */
    private const val SEP = "\u001F"
    private const val MAX_SEEN = 100

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun isMonitoringEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_ENABLED, false)

    fun setMonitoringEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_ENABLED, enabled).apply()
    }

    fun ignoredPackages(context: Context): Set<String> =
        prefs(context).getStringSet(KEY_IGNORED, emptySet())?.toSet() ?: emptySet()

    fun isIgnored(context: Context, packageName: String): Boolean =
        ignoredPackages(context).contains(packageName)

    fun setIgnoredPackages(context: Context, packages: Set<String>) {
        prefs(context).edit().putStringSet(KEY_IGNORED, packages.toSet()).apply()
    }

    /** Best-effort human label for a package, falling back to the package id. */
    fun appLabel(context: Context, packageName: String): String {
        return try {
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            context.packageManager.getApplicationLabel(info).toString()
        } catch (e: PackageManager.NameNotFoundException) {
            packageName
        } catch (e: Exception) {
            packageName
        }
    }

    /** Remembers that this package posted a notification (label + time only). */
    fun recordSource(context: Context, packageName: String, label: String) {
        val store = prefs(context)
        val current = store.getStringSet(KEY_SEEN, emptySet())?.toMutableSet() ?: mutableSetOf()
        val prefix = packageName + SEP
        current.removeAll { it.startsWith(prefix) }
        current.add(packageName + SEP + label.replace(SEP, " ") + SEP + System.currentTimeMillis())
        val trimmed = if (current.size > MAX_SEEN) current.toList().takeLast(MAX_SEEN).toSet() else current
        store.edit().putStringSet(KEY_SEEN, trimmed).apply()
    }

    /** Observed sources as (packageName, appLabel, lastSeenMillis) triples. */
    fun seenSources(context: Context): List<Triple<String, String, Long>> {
        val entries = prefs(context).getStringSet(KEY_SEEN, emptySet()) ?: emptySet()
        return entries.mapNotNull { entry ->
            val parts = entry.split(SEP)
            if (parts.size < 3) null
            else Triple(parts[0], parts[1], parts[2].toLongOrNull() ?: 0L)
        }.sortedByDescending { it.third }
    }

    fun clearSeenSources(context: Context) {
        prefs(context).edit().remove(KEY_SEEN).apply()
    }
}
