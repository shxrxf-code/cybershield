package com.shieldguard.ai.service

import com.shieldguard.ai.domain.model.Verdict
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

data class ScannedNotificationEvent(
    val id: String,
    val packageName: String,
    val appLabel: String,
    val senderOrTitle: String,
    val messageSnippet: String,
    val detectedUrls: List<String>,
    val verdict: Verdict,
    val riskScore: Int,
    val timestampMs: Long
)

data class NotificationMonitorState(
    val notificationsScannedCount: Int = 0,
    val urlsDetectedCount: Int = 0,
    val threatsBlockedCount: Int = 0,
    val recentNotifications: List<ScannedNotificationEvent> = emptyList()
)

@Singleton
class NotificationMonitorHub @Inject constructor() {

    private val _state = MutableStateFlow(NotificationMonitorState())
    val state: StateFlow<NotificationMonitorState> = _state.asStateFlow()

    fun recordNotification(event: ScannedNotificationEvent) {
        val current = _state.value
        val isThreat = event.verdict != Verdict.SAFE
        _state.value = current.copy(
            notificationsScannedCount = current.notificationsScannedCount + 1,
            urlsDetectedCount = current.urlsDetectedCount + event.detectedUrls.size,
            threatsBlockedCount = if (isThreat) current.threatsBlockedCount + 1 else current.threatsBlockedCount,
            recentNotifications = (listOf(event) + current.recentNotifications).take(40)
        )
    }
}
