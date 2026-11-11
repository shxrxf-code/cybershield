# Add project specific ProGuard rules here.
-keepattributes *Annotation*
-keepclassmembers class * {
    @androidx.annotation.Keep <methods>;
}
-keep class com.shieldguard.ai.data.remote.dto.** { *; }
-dontwarn okhttp3.**
-dontwarn okio.**
