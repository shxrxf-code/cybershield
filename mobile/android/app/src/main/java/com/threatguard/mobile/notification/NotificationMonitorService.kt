package com.threatguard.mobile.notification

import android.app.Notification
import android.content.ComponentName
import android.content.Context
import android.provider.Settings
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import com.facebook.react.bridge.Arguments
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Reads the text Android exposes for notifications and forwards it to JavaScript
 * for on-device scam/phishing analysis.
 *
 * Privacy boundaries, stated plainly:
 *
 *  - Only the fields a NotificationListener is granted — title, body, big-text and
 *    sub-text — are read. The service never opens the posting app, never reads its
 *    files and never draws on screen. It cannot see anything the user has not
 *    allowed Android to expose.
 *  - Fields are capped at [MAX_FIELD] characters and are only ever held in memory
 *    for the duration of the callback. Nothing is persisted here.
 *  - Nothing is forwarded unless the user has switched monitoring on and not muted
 *    the posting app.
 *  - The app's own notifications are ignored.
 */
class NotificationMonitorService : NotificationListenerService() {

    override fun onListenerConnected() {
        super.onListenerConnected()
        connected = true
        NotificationBridge.emitStatus(true, isAccessGranted(this))
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        connected = false
        NotificationBridge.emitStatus(false, isAccessGranted(this))
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        val notification = sbn ?: return
        val packageName = notification.packageName ?: return
        val app = applicationContext
        if (packageName == app.packageName) return

        if (!NotificationPrefs.isMonitoringEnabled(app)) return
        if (NotificationPrefs.isIgnored(app, packageName)) return

        val extras = notification.notification?.extras ?: return
        val title = cap(extras.getCharSequence(Notification.EXTRA_TITLE))
        val text = cap(
            extras.getCharSequence(Notification.EXTRA_TEXT)
                ?: extras.getCharSequence(Notification.EXTRA_BIG_TEXT)
        )
        val subText = cap(extras.getCharSequence(Notification.EXTRA_SUB_TEXT))
        if (title == null && text == null) return

        val label = NotificationPrefs.appLabel(app, packageName)
        NotificationPrefs.recordSource(app, packageName, label)

        val payload = Arguments.createMap()
        payload.putString("packageName", packageName)
        payload.putString("appLabel", label)
        if (title != null) payload.putString("title", title)
        if (text != null) payload.putString("text", text)
        if (subText != null) payload.putString("subText", subText)
        payload.putString("postedAt", isoTime(notification.postTime))
        notification.key?.let { payload.putString("key", it) }

        NotificationBridge.emitNotification(payload)
    }

    companion object {
        private const val MAX_FIELD = 500

        /** Set while the OS has our listener bound; read by the bridge module. */
        @Volatile
        var connected: Boolean = false

        /**
         * True when the user has enabled notification access for this app. This
         * reads the platform's own "enabled_notification_listeners" setting rather
         * than assuming, so the UI can show the real state.
         */
        fun isAccessGranted(context: Context): Boolean {
            val flat = Settings.Secure.getString(
                context.contentResolver,
                "enabled_notification_listeners"
            )
            if (flat.isNullOrEmpty()) return false
            val component = ComponentName(context, NotificationMonitorService::class.java)
            val full = component.flattenToString()
            val short = component.flattenToShortString()
            return flat.split(":")
                .any { it.equals(full, ignoreCase = true) || it.equals(short, ignoreCase = true) }
        }

        private fun cap(value: CharSequence?): String? {
            if (value == null) return null
            val text = value.toString().trim()
            if (text.isEmpty()) return null
            return if (text.length > MAX_FIELD) text.substring(0, MAX_FIELD) else text
        }

        private fun isoTime(millis: Long): String =
            SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.US).format(Date(millis))
    }
}
