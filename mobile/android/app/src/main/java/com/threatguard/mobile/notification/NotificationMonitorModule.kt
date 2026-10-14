package com.threatguard.mobile.notification

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.service.notification.NotificationListenerService
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.module.annotations.ReactModule

/**
 * React Native bridge for notification monitoring.
 *
 * The module only exposes state and preferences; the actual listening happens in
 * [NotificationMonitorService]. It registers itself with [NotificationBridge] so
 * the service can deliver events to JavaScript while a React context is alive.
 */
@ReactModule(name = NotificationMonitorModule.NAME)
class NotificationMonitorModule(
    private val reactContext: ReactApplicationContext,
) : ReactContextBaseJavaModule(reactContext) {

    init {
        NotificationBridge.attach(reactContext)
    }

    override fun getName(): String = NAME

    override fun getConstants(): Map<String, Any> = mapOf("ENGINE_VERSION" to 1)

    /** Whether the user has granted notification access in Android settings. */
    @ReactMethod
    fun isAccessGranted(promise: Promise) {
        promise.resolve(NotificationMonitorService.isAccessGranted(reactContext))
    }

    /**
     * Whether the OS currently has our listener bound. Asking the system to
     * rebind first helps in the moment just after the user grants access.
     */
    @ReactMethod
    fun isConnected(promise: Promise) {
        try {
            NotificationListenerService.requestRebind(
                ComponentName(reactContext, NotificationMonitorService::class.java)
            )
        } catch (e: Exception) {
            // Non-fatal: we simply report our cached state.
        }
        promise.resolve(NotificationMonitorService.connected)
    }

    /** Opens Android's notification-access settings screen. */
    @ReactMethod
    fun openNotificationSettings() {
        val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            reactContext.startActivity(intent)
        } catch (e: Exception) {
            val fallback = Intent(Settings.ACTION_SETTINGS)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            try {
                reactContext.startActivity(fallback)
            } catch (ignored: Exception) {
                // Nothing more we can do; the UI already offers a fallback.
            }
        }
    }

    /** Mirrors the in-app monitoring preference so the service can honour it. */
    @ReactMethod
    fun setMonitoringEnabled(enabled: Boolean, promise: Promise) {
        NotificationPrefs.setMonitoringEnabled(reactContext, enabled)
        promise.resolve(true)
    }

    @ReactMethod
    fun isMonitoringEnabled(promise: Promise) {
        promise.resolve(NotificationPrefs.isMonitoringEnabled(reactContext))
    }

    @ReactMethod
    fun getIgnoredPackages(promise: Promise) {
        val array = Arguments.createArray()
        for (pkg in NotificationPrefs.ignoredPackages(reactContext)) {
            array.pushString(pkg)
        }
        promise.resolve(array)
    }

    @ReactMethod
    fun setIgnoredPackages(packages: ReadableArray, promise: Promise) {
        val set = mutableSetOf<String>()
        for (i in 0 until packages.size()) {
            packages.getString(i)?.let { set.add(it) }
        }
        NotificationPrefs.setIgnoredPackages(reactContext, set)
        promise.resolve(true)
    }

    /** Packages the listener has observed posting notifications. */
    @ReactMethod
    fun getSeenSources(promise: Promise) {
        val array = Arguments.createArray()
        for (source in NotificationPrefs.seenSources(reactContext)) {
            val map = Arguments.createMap()
            map.putString("packageName", source.first)
            map.putString("appLabel", source.second)
            map.putDouble("lastSeen", source.third.toDouble())
            array.pushMap(map)
        }
        promise.resolve(array)
    }

    @ReactMethod
    fun clearSeenSources(promise: Promise) {
        NotificationPrefs.clearSeenSources(reactContext)
        promise.resolve(true)
    }

    /** True when a system notification may be posted (always true below API 33). */
    @ReactMethod
    fun hasNotificationPermission(promise: Promise) {
        promise.resolve(canPostNotifications())
    }

    /**
     * Posts a single local alert notification for a flagged message.
     *
     * This is deliberately minimal — a fixed channel and no queueing. The full
     * alerting layer (channel policy, grouping, de-duplication and tap-through)
     * is a later phase; this exists so the "alert notifications" switch raises a
     * real notification rather than pretending to.
     */
    @ReactMethod
    fun postThreatAlert(title: String, body: String, promise: Promise) {
        if (!canPostNotifications()) {
            promise.reject("E_NO_NOTIFICATION_PERMISSION", "Notification permission has not been granted.")
            return
        }
        try {
            val manager = reactContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    "Threat alerts",
                    NotificationManager.IMPORTANCE_HIGH
                )
                channel.description = "Alerts when ThreatGuard flags a suspicious message or link"
                manager.createNotificationChannel(channel)
            }

            val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Notification.Builder(reactContext, CHANNEL_ID)
            } else {
                @Suppress("DEPRECATION")
                Notification.Builder(reactContext).setPriority(Notification.PRIORITY_HIGH)
            }

            val notification = builder
                .setContentTitle(title)
                .setContentText(body)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setStyle(Notification.BigTextStyle().bigText(body))
                .setAutoCancel(true)
                .build()

            manager.notify(nextNotificationId(), notification)
            promise.resolve(true)
        } catch (e: Exception) {
            promise.reject("E_NOTIFY_FAILED", e.message ?: "Could not post the alert notification.", e)
        }
    }

    private fun canPostNotifications(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
        return reactContext.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
    }

    private fun nextNotificationId(): Int = NOTIFICATION_ID.getAndIncrement()

    // Required by NativeEventEmitter so event subscriptions can be registered.
    @ReactMethod
    fun addListener(eventName: String) {
        // no-op
    }

    @ReactMethod
    fun removeListeners(count: Double) {
        // no-op
    }

    override fun invalidate() {
        NotificationBridge.detach(reactContext)
        super.invalidate()
    }

    companion object {
        const val NAME = "NotificationMonitor"
        private const val CHANNEL_ID = "threatguard_alerts"
        private val NOTIFICATION_ID = java.util.concurrent.atomic.AtomicInteger(1000)
    }
}
