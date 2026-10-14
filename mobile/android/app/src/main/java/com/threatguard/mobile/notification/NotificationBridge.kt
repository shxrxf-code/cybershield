package com.threatguard.mobile.notification

import android.util.Log
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.WritableMap
import java.lang.ref.WeakReference

/**
 * The bridge between the notification listener service and JavaScript.
 *
 * The service has no `ReactContext` of its own, so the bridge module attaches a
 * weak reference to the one it is created with. When a notification arrives, the
 * service calls [emitNotification]; if no React context is alive (the app process
 * is running only the service) the event is simply dropped — the message is never
 * buffered or written to disk.
 */
object NotificationBridge {

    const val EVENT_RECEIVED = "ThreatGuardNotificationReceived"
    const val EVENT_STATUS = "ThreatGuardNotificationStatus"

    private const val TAG = "NotificationBridge"

    @Volatile
    private var contextRef: WeakReference<ReactApplicationContext>? = null

    fun attach(context: ReactApplicationContext) {
        contextRef = WeakReference(context)
    }

    fun detach(context: ReactApplicationContext) {
        val current = contextRef?.get()
        if (current == null || current === context) {
            contextRef = null
        }
    }

    fun emitNotification(payload: WritableMap) {
        emit(EVENT_RECEIVED, payload)
    }

    fun emitStatus(connected: Boolean, granted: Boolean) {
        val payload = Arguments.createMap()
        payload.putBoolean("connected", connected)
        payload.putBoolean("granted", granted)
        emit(EVENT_STATUS, payload)
    }

    private fun emit(event: String, payload: WritableMap) {
        val context = contextRef?.get() ?: return
        if (!context.hasActiveReactInstance()) return
        try {
            context.emitDeviceEvent(event, payload)
        } catch (e: Exception) {
            Log.w(TAG, "Could not emit $event", e)
        }
    }
}
