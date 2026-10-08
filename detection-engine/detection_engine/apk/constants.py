"""Reference data for Android package analysis.

The tables here are deliberately conservative.  A permission is dangerous because
of what it lets an app *do*, but almost every permission has a legitimate use, so
this module records the capability each permission confers and its protection
level rather than simply calling permissions "malicious".

``PROTECTION`` levels are taken from the Android platform: ``normal``,
``dangerous``, ``signature`` and ``signatureOrSystem``.  ``signature`` means only
an app signed with the same key can hold it, which is what makes
``android.permission.INSTALL_PACKAGES`` a much stronger signal than
``READ_SMS``: the first is effectively unobtainable for a store app, the second
is requested by thousands of legitimate apps.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "PERMISSION_CAPABILITIES",
    "PERMISSION_PROTECTION",
    "PERMISSION_RISK",
    "SMS_PERMISSIONS",
    "DANGEROUS_PERMISSION_GROUPS",
    "DYNAMIC_LOADING_APIS",
    "REFLECTION_APIS",
    "OBFUSCATION_INDICATORS",
    "PACKER_INDICATORS",
    "ROOT_DETECTION_APIS",
    "EMULATOR_DETECTION_APIS",
    "SUSPICIOUS_PACKAGE_TOKENS",
    "COUNTERFEIT_BRANDS",
    "SENSITIVE_STRING_PATTERNS",
    "NAMED_CREDENTIAL_PATTERNS",
    "GENERIC_SECRET_PATTERNS",
    "CRYPTO_AND_EXFIL_APIS",
    "OVERLAY_PERMISSIONS",
    "DEVICE_ADMIN_PERMISSIONS",
    "ACCESSIBILITY_SERVICE_PERMISSION",
    "PACKAGE_INSTALL_PERMISSIONS",
    "ROOT_HINT_PATHS",
]

#: What a permission actually lets an app do, and why that matters.
PERMISSION_CAPABILITIES: Final[dict[str, str]] = {
    "INTERNET": "Send and receive network traffic",
    "ACCESS_NETWORK_STATE": "Read whether the device has a network connection",
    "ACCESS_WIFI_STATE": "Read Wi-Fi and hotspot details",
    "READ_PHONE_STATE": "Read the device IMEI, phone number and call state",
    "READ_SMS": "Read stored text messages",
    "RECEIVE_SMS": "Intercept incoming text messages, including one-time codes",
    "SEND_SMS": "Send text messages, which can incur charges",
    "READ_CALL_LOG": "Read the call history",
    "WRITE_CALL_LOG": "Modify the call history",
    "CALL_PHONE": "Place calls without user interaction",
    "ANSWER_PHONE_CALLS": "Answer incoming calls",
    "READ_CONTACTS": "Read the address book",
    "WRITE_CONTACTS": "Create, change or delete contacts",
    "RECORD_AUDIO": "Record from the microphone",
    "CAMERA": "Take photographs and record video",
    "ACCESS_FINE_LOCATION": "Read GPS location to metre precision",
    "ACCESS_COARSE_LOCATION": "Read approximate location",
    "ACCESS_BACKGROUND_LOCATION": "Read location while the app is not in the foreground",
    "BODY_SENSORS": "Read heart rate and other body sensors",
    "ACTIVITY_RECOGNITION": "Infer what the user is doing",
    "GET_ACCOUNTS": "List Google and other accounts on the device",
    "MANAGE_ACCOUNTS": "Add, modify or remove accounts",
    "AUTHENTICATE_ACCOUNTS": "Use device account credentials",
    "USE_CREDENTIALS": "Use stored account credentials",
    "READ_EXTERNAL_STORAGE": "Read shared storage",
    "WRITE_EXTERNAL_STORAGE": "Write shared storage",
    "READ_MEDIA_IMAGES": "Read the user's photographs",
    "READ_MEDIA_VIDEO": "Read the user's videos",
    "READ_MEDIA_AUDIO": "Read the user's audio files",
    "SYSTEM_ALERT_WINDOW": "Draw over other apps",
    "REQUEST_INSTALL_PACKAGES": "Prompt the user to install APKs",
    "INSTALL_PACKAGES": "Install packages without user interaction",
    "DELETE_PACKAGES": "Delete installed packages",
    "REQUEST_DELETE_PACKAGES": "Prompt the user to remove packages",
    "BIND_ACCESSIBILITY_SERVICE": "Observe and act on screen content for accessibility",
    "BIND_DEVICE_ADMIN": "Receive device-administrator callbacks",
    "BIND_NOTIFICATION_LISTENER_SERVICE": "Read all notifications",
    "QUERY_ALL_PACKAGES": "Enumerate every installed app",
    "PACKAGE_USAGE_STATS": "Read which apps the user opens and for how long",
    "FOREGROUND_SERVICE": "Run a persistent foreground service",
    "RECEIVE_BOOT_COMPLETED": "Start automatically at device boot",
    "WAKE_LOCK": "Prevent the device from sleeping",
    "DISABLE_KEYGUARD": "Dismiss the lock screen",
    "SET_WALLPAPER": "Change the wallpaper",
    "NFC": "Use near-field communication",
    "CHANGE_WIFI_STATE": "Modify Wi-Fi configuration",
    "MODIFY_PHONE_STATE": "Change the phone radio state",
    "WRITE_SETTINGS": "Modify system settings",
    "WRITE_SECURE_SETTINGS": "Modify secure system settings",
    "DUMP": "Read system service state; signature-level",
}

#: Android protection levels for permissions where the distinction changes the
#: reading of a request.  Absent entries default to ``dangerous`` for
#: user-visible capabilities and ``normal`` for everything else.
PERMISSION_PROTECTION: Final[dict[str, str]] = {
    "INSTALL_PACKAGES": "signature",
    "DELETE_PACKAGES": "signature",
    "BIND_ACCESSIBILITY_SERVICE": "signature",
    "BIND_DEVICE_ADMIN": "signature",
    "BIND_NOTIFICATION_LISTENER_SERVICE": "signature",
    "DUMP": "signature",
    "WRITE_SECURE_SETTINGS": "signature|privileged",
    "MODIFY_PHONE_STATE": "signature|privileged",
    "QUERY_ALL_PACKAGES": "normal",
    "INTERNET": "normal",
    "VIBRATE": "normal",
}

#: Capability-level risk used to weight a permission request.  These are
#: deliberately not all equal: reading contacts is far more commonly legitimate
#: than intercepting SMS, and an app requesting both together is the signal.
PERMISSION_RISK: Final[dict[str, float]] = {
    "RECEIVE_SMS": 12.0,
    "READ_SMS": 10.0,
    "SEND_SMS": 10.0,
    "INTERNET": 6.0,
    "READ_PHONE_STATE": 8.0,
    "READ_CONTACTS": 6.0,
    "CALL_PHONE": 9.0,
    "RECORD_AUDIO": 8.0,
    "CAMERA": 6.0,
    "ACCESS_FINE_LOCATION": 8.0,
    "ACCESS_BACKGROUND_LOCATION": 8.0,
    "BIND_ACCESSIBILITY_SERVICE": 12.0,
    "SYSTEM_ALERT_WINDOW": 9.0,
    "REQUEST_INSTALL_PACKAGES": 9.0,
    "INSTALL_PACKAGES": 14.0,
    "BIND_DEVICE_ADMIN": 12.0,
    "QUERY_ALL_PACKAGES": 8.0,
    "PACKAGE_USAGE_STATS": 6.0,
    "DISABLE_KEYGUARD": 8.0,
    "WRITE_SECURE_SETTINGS": 10.0,
    "BODY_SENSORS": 5.0,
    "GET_ACCOUNTS": 5.0,
    "MANAGE_ACCOUNTS": 6.0,
    "ACTIVITY_RECOGNITION": 4.0,
    "READ_CALL_LOG": 6.0,
    "WRITE_CALL_LOG": 8.0,
    "AUTHENTICATE_ACCOUNTS": 9.0,
    "USE_CREDENTIALS": 9.0,
    "MODIFY_PHONE_STATE": 8.0,
    "REQUEST_DELETE_PACKAGES": 6.0,
    "BIND_NOTIFICATION_LISTENER_SERVICE": 8.0,
}

SMS_PERMISSIONS: Final[frozenset[str]] = frozenset(
    {"READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CELL_BROADCASTS"}
)

DANGEROUS_PERMISSION_GROUPS: Final[dict[str, frozenset[str]]] = {
    "sms": SMS_PERMISSIONS,
    "location": frozenset(
        {"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION"}
    ),
    "contacts": frozenset({"READ_CONTACTS", "WRITE_CONTACTS"}),
    "microphone": frozenset({"RECORD_AUDIO"}),
    "camera": frozenset({"CAMERA"}),
    "phone_state": frozenset(
        {"READ_PHONE_STATE", "CALL_PHONE", "ANSWER_PHONE_CALLS", "READ_CALL_LOG"}
    ),
    "storage": frozenset({"READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"}),
    "accounts": frozenset({"GET_ACCOUNTS", "MANAGE_ACCOUNTS", "AUTHENTICATE_ACCOUNTS"}),
}

OVERLAY_PERMISSIONS: Final[frozenset[str]] = frozenset({"SYSTEM_ALERT_WINDOW"})

DEVICE_ADMIN_PERMISSIONS: Final[frozenset[str]] = frozenset({"BIND_DEVICE_ADMIN"})

ACCESSIBILITY_SERVICE_PERMISSION: Final[str] = "BIND_ACCESSIBILITY_SERVICE"

PACKAGE_INSTALL_PERMISSIONS: Final[frozenset[str]] = frozenset(
    {"INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES", "DELETE_PACKAGES", "REQUEST_DELETE_PACKAGES"}
)

#: Java APIs that load code at runtime.  Legitimate apps use these for
#: reflection and plugins; malware uses them to load a payload the store's
#: scanner never saw.
DYNAMIC_LOADING_APIS: Final[tuple[str, ...]] = (
    "DexClassLoader",
    "PathClassLoader",
    "InMemoryDexClassLoader",
    "BaseDexClassLoader",
    "dalvik.system.DexClassLoader",
    "dalvik.system.PathClassLoader",
    "dalvik.system.InMemoryDexClassLoader",
    "dalvik.system.DexFile",
    "System.loadLibrary",
    "System.load",
    "Runtime.getRuntime().exec",
    "java.lang.reflect.Method",
    "ClassLoader.defineClass",
)

#: Reflection entry points, tracked separately from dynamic loading because a
#: crash reporter or an analytics SDK legitimately reflects on its own classes.
REFLECTION_APIS: Final[tuple[str, ...]] = (
    "java.lang.reflect.Method",
    "java.lang.reflect.Constructor",
    "java.lang.reflect.Field",
    "java.lang.Class.forName",
    "Class.getMethod",
    "Class.getDeclaredMethod",
    "Class.getField",
    "setAccessible",
    "java.lang.invoke.MethodHandle",
)

OBFUSCATION_INDICATORS: Final[tuple[str, ...]] = (
    "Lcom/google/gson/",
    "kotlinx.serialization",
    "org/apache/commons/io",
    "java/security/KeyStore",
    "javax/crypto/Cipher",
)

#: Files and directories whose presence implies a packer or a protection tool.
PACKER_INDICATORS: Final[tuple[str, ...]] = (
    "libjiagu.so",
    "libjiagu_art.so",
    "libexec.so",
    "libexecmain.so",
    "libDexHelper.so",
    "libshell.so",
    "libprotect.so",
    "libnesec.so",
    "libsecexe.so",
    "libsecmain.so",
    "libBugly.so",
    "libtup.so",
    "libshield.so",
    "libbaiduprotect.so",
    "assets/af.bin",
    "assets/dynDex",
    "assets/driver.dex",
    "assets/ijiami.dat",
    "assets/x0.cfg",
)

#: APIs used to check for root.  Not malicious by itself - plenty of banking and
#: DRM apps do it - but it matters in combination with other signals.
ROOT_DETECTION_APIS: Final[tuple[str, ...]] = (
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "su -c",
    "test-keys",
    "ro.build.tags",
    "com.noshufou.android.su",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "magisk",
    "/dev/__magisk__",
)

ROOT_HINT_PATHS: Final[tuple[str, ...]] = (
    "/system/xbin/su",
    "/system/app/Superuser.apk",
    "/system/bin/.ext/.su",
    "/sbin/.su",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/su/bin",
    "/system/sd/xbin/su",
)

#: Emulator-detection strings.  Malware uses these to stay dormant in analysis
#: sandboxes; a developer build may legitimately reference them too.
EMULATOR_DETECTION_APIS: Final[tuple[str, ...]] = (
    "ro.kernel.qemu",
    "ro.hardware",
    "ro.product.model",
    "ro.product.device",
    "goldfish",
    "ranchu",
    "generic",
    "sdk_gphone",
    "google_sdk",
    "Emulator",
    "Android SDK built for x86",
    "/dev/qemu_pipe",
    "15555215554",
    "0000000000000000e",
)

#: Package-name fragments typical of impersonation, typosquatting and packer
#: output.  Matched against the full package name.
SUSPICIOUS_PACKAGE_TOKENS: Final[tuple[str, ...]] = (
    "systemui.secure",
    "android.system.update",
    "security.patch",
    "android.updateservice",
    "com.android.server",
    "com.android.system",
    "apk.update",
    "app.installer",
    "free.gift",
    "cheap.deal",
    "win.prize",
    "claim.reward",
    "bank.login.secure",
    "secure.account.verify",
    "verify.identity.now",
    "sms.read.service",
    "hidden.config",
    "devmode.debug",
)

#: Brands an app may plausibly impersonate.  Deliberately a short list of
#: system-level names where the abuse is severe, rather than every bank.
COUNTERFEIT_BRANDS: Final[dict[str, tuple[str, ...]]] = {
    "android": ("com.android.",),
    "google": ("com.google.android.",),
    "microsoft": ("com.microsoft.",),
    "samsung": ("com.samsung.android.", "com.samsung."),
    "whatsapp": ("com.whatsapp",),
    "telegram": ("org.telegram.", "ru.org.telegram."),
    "paypal": ("com.paypal.",),
    "metamask": ("io.metamask.",),
    "binance": ("com.binance.",),
    "coinbase": ("com.coinbase.",),
}

#: Credential shapes issued by a named vendor.  These are deterministic: a
#: string matching ``AKIA`` plus 16 uppercase alphanumerics is an AWS key id, not
#: a coincidence, so they are reported with high reliability.  They are still not
#: proof that the credential works - CyberShield never tests it - only proof that
#: one is present in a file every downloader can read.
NAMED_CREDENTIAL_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (r"(?i)\bAIza[0-9A-Za-z_\-]{35}\b", "Google API key"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id"),
    (r"\bghp_[A-Za-z0-9]{36}\b", "GitHub personal access token"),
    (r"\bgithub_pat_[A-Za-z0-9_]{60,}\b", "GitHub fine-grained token"),
    (r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b", "Slack token"),
    (r"\bsk-[A-Za-z0-9]{20,}\b", "OpenAI-style API key"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "embedded private key"),
)

#: Generic opaque-value patterns.  These have a real false-positive rate - long
#: base64 constants, packed resource blobs and compiled constants all match -
#: so they are reported separately and at a much lower weight.
GENERIC_SECRET_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (r"(?i)\b(?:aws_secret_access_key|api[_-]?secret|client[_-]?secret|password)\b\s*[:=]",
     "credential assignment in code"),
    # The class spells out A-Z rather than relying on a case-insensitive flag:
    # base64 is case-*sensitive*, so an upper-case-heavy blob (which is most of
    # them) would otherwise be missed, and the patterns are compiled against
    # bytes without the ``(?i)`` flag being honoured for the second table.
    (r"\b[A-Za-z0-9+/]{60,}={0,2}\b", "long opaque constant"),
)

#: Both tables, for callers that only need to sweep for anything secret-shaped.
SENSITIVE_STRING_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    NAMED_CREDENTIAL_PATTERNS + GENERIC_SECRET_PATTERNS
)

#: Cryptography and network APIs that together suggest exfiltration.
CRYPTO_AND_EXFIL_APIS: Final[tuple[str, ...]] = (
    "javax.crypto.Cipher",
    "java.security.KeyStore",
    "Base64.encodeToString",
    "java.net.URL",
    "HttpURLConnection",
    "okhttp3.OkHttpClient",
    "org.apache.http.client",
)