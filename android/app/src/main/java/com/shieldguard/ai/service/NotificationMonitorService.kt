package com.shieldguard.ai.service

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import androidx.core.app.NotificationCompat
import com.shieldguard.ai.MainActivity
import com.shieldguard.ai.ShieldGuardApp
import com.shieldguard.ai.data.local.EncryptedPreferencesManager
import com.shieldguard.ai.domain.usecase.ProcessNotificationUseCase
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject

@AndroidEntryPoint
class NotificationMonitorService : NotificationListenerService() {

    @Inject
    lateinit var processNotificationUseCase: ProcessNotificationUseCase

    @Inject
    lateinit var preferencesManager: EncryptedPreferencesManager

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val recentHashes = ConcurrentHashMap<String, Long>()

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null || !preferencesManager.isNotificationMonitorEnabled()) return

        val pkgName = sbn.packageName ?: return

        // Ignore ShieldGuard's own notifications and silent system progress bars
        if (pkgName == packageName) return
        val notification = sbn.notification ?: return
        if ((notification.flags and Notification.FLAG_GROUP_SUMMARY) != 0) {
            // Still inspect if it carries textLines / messages, otherwise ignore empty summaries
            val hasLines = notification.extras?.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)?.isNotEmpty() == true
            if (!hasLines) return
        }

        val extras = notification.extras ?: return
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()?.trim() ?: ""
        val extractedBody = extractFullChatAndNotificationText(extras)

        if (extractedBody.isBlank() && title.isBlank()) return

        // Deduplicate rapid identical re-posts within 15 seconds
        val dedupKey = "$pkgName|$title|${extractedBody.hashCode()}"
        val now = System.currentTimeMillis()
        val lastSeen = recentHashes[dedupKey]
        if (lastSeen != null && (now - lastSeen) < 15_000L) return
        recentHashes[dedupKey] = now
        if (recentHashes.size > 200) {
            recentHashes.entries.removeIf { now - it.value > 60_000L }
        }

        serviceScope.launch {
            val appLabel = runCatching {
                val appInfo = packageManager.getApplicationInfo(pkgName, 0)
                packageManager.getApplicationLabel(appInfo).toString()
            }.getOrDefault(pkgName)

            val threat = processNotificationUseCase(
                packageName = pkgName,
                appLabel = appLabel,
                title = title,
                text = extractedBody
            )

            if (threat != null) {
                showThreatAlert(threat.title, threat.description)
            }
        }
    }

    /**
     * Reads complete chat payloads from MessagingStyle bundles (WhatsApp, Telegram, Messages,
     * Instagram, Messenger), BigText, InboxStyle textLines, and standard text fields.
     */
    private fun extractFullChatAndNotificationText(extras: Bundle): String {
        val parts = LinkedHashSet<String>()

        extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.let {
            parts.add(it)
        }
        extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.let {
            parts.add(it)
        }
        extras.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.let {
            parts.add(it)
        }

        // Stacked chat lines (InboxStyle used by WhatsApp, Telegram, Gmail, SMS)
        extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)?.forEach { line ->
            line?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.let { parts.add(it) }
        }

        // MessagingStyle chat messages array
        @Suppress("DEPRECATION")
        val rawMessages = extras.getParcelableArray(Notification.EXTRA_MESSAGES)
        rawMessages?.forEach { item ->
            if (item is Bundle) {
                val sender = item.getCharSequence("sender")?.toString()?.trim()
                val msgText = item.getCharSequence("text")?.toString()?.trim()
                if (!msgText.isNullOrEmpty()) {
                    parts.add(if (!sender.isNullOrEmpty()) "$sender: $msgText" else msgText)
                }
            }
        }

        return parts.joinToString("\n")
    }

    private fun showThreatAlert(title: String, message: String) {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }

        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, ShieldGuardApp.CHANNEL_THREAT_ALERTS)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("🚨 $title")
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager?.notify(System.currentTimeMillis().toInt(), notification)
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }
}
