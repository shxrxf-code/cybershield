package com.shieldguard.ai.domain.model

enum class ThreatLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

enum class Verdict {
    SAFE,
    SUSPICIOUS,
    MALICIOUS
}

enum class ModuleType {
    URL,
    APK,
    DOCUMENT,
    NOTIFICATION,
    SMS,
    EMAIL,
    NETWORK,
    DEVICE
}
