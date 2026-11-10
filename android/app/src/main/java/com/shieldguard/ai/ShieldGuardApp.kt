package com.shieldguard.ai

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject

@HiltAndroidApp
class ShieldGuardApp : Application(), Configuration.Provider {

    @Inject
    lateinit var workerFactory: HiltWorkerFactory

    companion object {
        const val CHANNEL_THREAT_ALERTS = "shieldguard_threat_alerts"
        const val CHANNEL_MONITOR_STATUS = "shieldguard_monitor_status"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val alertChannel = NotificationChannel(
                CHANNEL_THREAT_ALERTS,
                "ShieldGuard Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Critical alerts when malicious links, apps, or scams are detected."
                enableVibration(true)
            }

            val monitorChannel = NotificationChannel(
                CHANNEL_MONITOR_STATUS,
                "ShieldGuard Protection Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Displays active shield protection status."
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager?.createNotificationChannel(alertChannel)
            notificationManager?.createNotificationChannel(monitorChannel)
        }
    }

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(workerFactory)
            .build()
}
