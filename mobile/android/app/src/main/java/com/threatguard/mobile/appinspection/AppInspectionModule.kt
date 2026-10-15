package com.threatguard.mobile.appinspection

import android.content.pm.PackageManager
import android.util.Log

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.WritableMap
import com.facebook.react.module.annotations.ReactModule

import java.util.concurrent.atomic.AtomicBoolean

/**
 * React Native bridge for the app inspection engine.
 *
 * Uses Android PackageManager to enumerate installed applications and analyze
 * their permissions and risk profile. All heavy work runs on a background thread.
 */
@ReactModule(name = AppInspectionModule.NAME)
class AppInspectionModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {

    companion object {
        const val NAME = "AppInspection"
        private const val TAG = "AppInspectionModule"
    }

    private val service = AppInspectionService(reactContext.packageManager)
    private val isScanning = AtomicBoolean(false)

    override fun getName(): String = NAME

    override fun getConstants(): Map<String, Any> {
        val constants = hashMapOf<String, Any>()
        constants["ENGINE_VERSION"] = 1
        return constants
    }

    /**
     * Starts a full inspection of all visible installed applications.
     */
    @ReactMethod
    fun inspectAllApps(promise: Promise) {
        if (isScanning.getAndSet(true)) {
            promise.reject("E_SCAN_IN_PROGRESS", "An app inspection is already running.")
            return
        }

        service.inspectAllApps(object : AppInspectionService.Callback {
            override fun onComplete(results: List<AppRiskResult>) {
                isScanning.set(false)
                try {
                    val array = Arguments.createArray()
                    for (result in results) {
                        array.pushMap(riskResultToMap(result))
                    }
                    promise.resolve(array)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to serialize results", e)
                    promise.reject("E_SERIALIZE", "Failed to serialize inspection results.", e)
                }
            }

            override fun onError(error: Throwable) {
                isScanning.set(false)
                Log.e(TAG, "App inspection failed", error)
                promise.reject("E_INSPECTION_FAILED", "Failed to inspect installed apps: ${error.message}", error)
            }
        })
    }

    /**
     * Inspects a single package by name.
     */
    @ReactMethod
    fun inspectPackage(packageName: String, promise: Promise) {
        service.inspectPackage(packageName, object : AppInspectionService.Callback {
            override fun onComplete(results: List<AppRiskResult>) {
                try {
                    if (results.isNotEmpty()) {
                        promise.resolve(riskResultToMap(results[0]))
                    } else {
                        promise.reject("E_NOT_FOUND", "Package not found or could not be analyzed.")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to serialize result", e)
                    promise.reject("E_SERIALIZE", "Failed to serialize inspection result.", e)
                }
            }

            override fun onError(error: Throwable) {
                Log.e(TAG, "Single package inspection failed", error)
                promise.reject("E_INSPECTION_FAILED", "Failed to inspect package: ${error.message}", error)
            }
        })
    }

    /**
     * Cancels any in-flight inspection.
     */
    @ReactMethod
    fun cancelInspection(promise: Promise) {
        // The service doesn't support mid-scan cancellation in this simple impl,
        // but we expose the method for future enhancement.
        promise.resolve(!isScanning.get())
    }

    // Required by NativeEventEmitter so subscriptions can be registered.
    @ReactMethod
    fun addListener(eventName: String) {
        // no-op
    }

    @ReactMethod
    fun removeListeners(count: Int) {
        // no-op
    }

    override fun invalidate() {
        service.shutdown()
        super.invalidate()
    }

    /**
     * Converts an AppRiskResult to a WritableMap for the React Native bridge.
     */
    private fun riskResultToMap(result: AppRiskResult): WritableMap {
        val map = Arguments.createMap()
        map.putString("packageName", result.packageName)
        map.putString("appName", result.appName)
        map.putString("versionName", result.versionName)
        map.putDouble("versionCode", result.versionCode.toDouble())
        map.putBoolean("isSystemApp", result.isSystemApp)
        map.putString("riskLevel", result.riskLevel.name)
        map.putString("installationSource", result.installationSource ?: "")
        map.putInt("targetSdkVersion", result.targetSdkVersion)
        map.putString("targetSdkName", result.targetSdkName)
        map.putString("iconHash", result.iconHash ?: "")

        // Permissions array
        val permsArray = Arguments.createArray()
        for (perm in result.requestedPermissions) {
            val permMap = Arguments.createMap()
            permMap.putString("name", perm.name)
            permMap.putString("label", perm.label)
            permMap.putBoolean("isSensitive", perm.isSensitive)
            permMap.putBoolean("granted", perm.granted)
            permsArray.pushMap(permMap)
        }
        map.putArray("requestedPermissions", permsArray)

        // Reasons array
        val reasonsArray = Arguments.createArray()
        for (reason in result.reasons) {
            reasonsArray.pushString(reason)
        }
        map.putArray("reasons", reasonsArray)

        return map
    }
}