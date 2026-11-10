# ShieldGuard AI - Enterprise Cybersecurity Platform
## System Architecture & Technical Specifications

---

## 1. System Architecture Diagram

```mermaid
flowchart TD
    subgraph MobileEndpoint["Android Client Device (ShieldGuard AI App)"]
        UI["Material 3 Jetpack Compose UI<br/>(Dashboard, Scanners, Alerts)"]
        VM["MVVM ViewModels & Coroutines/Flow"]
        UC["Domain Use Cases (Clean Architecture)"]

        subgraph SecurityEngines["On-Device Detection Core"]
            NLS["NotificationListenerService<br/>(WhatsApp, Telegram, SMS, Gmail)"]
            VPN["VpnService Packet Filter<br/>(DNS Hijack & MITM Defense)"]
            APKScan["Static APK & Permission Auditor"]
            DocScan["Document Macro / Exploit Scanner"]
            RootDetect["Root, Magisk & Tamper Detection"]
            DeviceAudit["Device Integrity Auditor"]
        end

        subgraph LocalData["Secure Local Storage"]
            RoomDB[("Encrypted Room Database<br/>(Threats, History, Telemetry)")]
            EncPrefs["Android Keystore +<br/>EncryptedSharedPreferences"]
        end

        UI --> VM
        VM --> UC
        NLS --> UC
        VPN --> UC
        APKScan --> UC
        DocScan --> UC
        RootDetect --> DeviceAudit
        DeviceAudit --> UC
        UC --> RoomDB
        UC --> EncPrefs
    end

    subgraph NetworkTransport["Encrypted Transport"]
        Retrofit["Retrofit + OkHttp Client<br/>(TLS 1.3 + Certificate Pinning)"]
        UC --> Retrofit
    end

    subgraph CloudBackend["FastAPI Enterprise Security Cloud"]
        APIGateway["FastAPI REST API Gateway<br/>(HSTS, CSP, Rate Limiting, API Auth)"]
        
        subgraph MLEngines["AI / ML Threat Detection Engines"]
            URLClf["URL Phishing Classifier<br/>(Random Forest / XGBoost)"]
            NLPClf["Smishing & Social Eng. NLP<br/>(TF-IDF + Logistic Reg / Transformer)"]
            EmailClf["Email Security & Auth Validator<br/>(SPF / DKIM / DMARC Engine)"]
            APKHeur["APK Static & Behavioral Engine"]
            DocHeur["Document Macro & PDF Exploit Engine"]
        end

        subgraph ThreatIntelFeeds["Aggregated Threat Intelligence (L1 Cache)"]
            VT["VirusTotal API v3"]
            AbuseIP["AbuseIPDB API v2"]
            PT["PhishTank Real-Time Feed"]
            OP["OpenPhish Zero-Day Feed"]
            OTX["AlienVault OTX Pulses"]
            RedisCache[("Redis Distributed Cache<br/>(TTL 24h)")]
        end

        subgraph PersistentDB["Data Persistence"]
            Postgres[("PostgreSQL 16 Enterprise<br/>(Partitioned Threat Logs & Signatures)")]
        end

        Retrofit --> APIGateway
        APIGateway --> MLEngines
        MLEngines --> ThreatIntelFeeds
        ThreatIntelFeeds --> RedisCache
        APIGateway --> Postgres
    end
```

---

## 2. Database Entity-Relationship (ER) Diagram

```mermaid
erDiagram
    DEVICES ||--o{ THREAT_LOGS : "logs"
    DEVICES ||--o{ SCAN_RECORDS : "initiates"
    DEVICES ||--o{ SECURITY_REPORTS : "receives"

    DEVICES {
        uuid id PK
        string device_uuid UK
        string device_model
        string os_version
        string app_version
        boolean is_rooted
        boolean developer_mode_enabled
        boolean usb_debugging_enabled
        int security_score
        timestamp last_seen_at
        timestamp created_at
    }

    THREAT_LOGS {
        uuid id PK
        uuid device_id FK
        string module_type
        string threat_level
        string verdict
        int risk_score
        string title
        text description
        string action_taken
        jsonb indicators
        text raw_payload
        timestamp created_at
    }

    SCAN_RECORDS {
        uuid id PK
        uuid device_id FK
        string scan_type
        string status
        int risk_score
        int findings_count
        int scanned_items_count
        jsonb details
        int duration_ms
        timestamp created_at
    }

    PHISHING_DOMAINS {
        uuid id PK
        string domain UK
        string source
        int confidence_score
        boolean is_active
        jsonb metadata_info
        timestamp created_at
    }

    MALWARE_SIGNATURES {
        uuid id PK
        string sha256_hash UK
        string package_name
        string malware_family
        int risk_score
        jsonb detection_rule
        timestamp created_at
    }

    SECURITY_REPORTS {
        uuid id PK
        uuid device_id FK
        string period
        int security_score
        int threats_blocked
        int scans_conducted
        jsonb summary_json
        timestamp created_at
    }
```

---

## 3. OWASP Mobile Top 10 Mitigation Matrix

| OWASP Mobile Risk | Attack Vector | ShieldGuard AI Countermeasure |
|---|---|---|
| **M1: Improper Credential Usage** | Stolen hardcoded API keys | Keystore-backed `EncryptedSharedPreferences`, dynamic HMAC payload signing. |
| **M2: Inadequate Supply Chain Security** | Malicious third-party dependencies | Dependency vulnerability scanning, strict multi-stage docker builds. |
| **M3: Insecure Authentication / Authorization** | Device impersonation / unauthorized queries | Device UUID cryptographically bound to token, strict server API validation. |
| **M4: Insufficient Input/Output Validation** | Malicious intent injection & path traversal | Strict Pydantic v2 data schemas, sanitized file paths, URI validation. |
| **M5: Insecure Communication** | Man-in-the-Middle (MITM) & SSL Stripping | OkHttp `CertificatePinner`, strict TLS 1.3, ARP anomaly detection, VPN DNS guard. |
| **M6: Inadequate Privacy Controls** | Leaking sensitive user notifications | On-device NLP preprocessing; raw chat notifications never sent to server. |
| **M7: Insufficient Binary Protection** | Reverse engineering, Frida tampering | ProGuard / R8 bytecode obfuscation, `RootDetectionEngine` detecting Frida/Magisk. |
| **M8: Security Misconfiguration** | ADB, USB debugging, Unknown Sources | `DeviceIntegrityAuditor` continuous audit with dynamic security score penalty. |
| **M9: Insecure Data Storage** | World-readable database storage | SQLite/Room cipher encryption, internal private app storage only. |
| **M10: Insufficient Cryptography** | Weak SHA-1 or MD5 algorithms | AES-256-GCM, SHA-256 signatures, RSA-4096 / ECC certificate verification. |

---

## 4. Threat Intelligence Aggregation Pipeline

1. **Client URL Interception**: Intercepted from SMS, WhatsApp, Telegram, or Safe Browser.
2. **Local Bloom Filter / LRU Check**: Checked locally against common high-risk signatures.
3. **Backend Redis L1 Cache Lookup**: Immediate sub-millisecond retrieval of cached reputation.
4. **Asynchronous Multi-Source Fanout**:
   - **OpenPhish**: Checks live zero-day active phishing URLs.
   - **PhishTank**: Queries community-verified phishing lists.
   - **VirusTotal v3**: Retrieves multi-vendor malware and malicious URL consensus.
   - **AbuseIPDB v2**: Inspects domain registrar IP abuse confidence score.
   - **AlienVault OTX**: Matches threat pulses and known adversarial infrastructure.
5. **Ensemble Risk Aggregation**: Blends threat feeds with the on-premise XGBoost lexical classifier.

---

## 5. Deployment Guide

### A. Backend Containerized Deployment
```bash
# 1. Clone repository & configure environment variables
cp .env.example .env
nano .env

# 2. Build & launch stack with Docker Compose
docker compose up -d --build

# 3. Verify healthcheck status
curl http://localhost:8000/health
```

### B. Production Kubernetes Deployment
A production deployment should utilize horizontal pod autoscalers (HPA) targeting 70% CPU/Memory utilization, backed by AWS RDS PostgreSQL and AWS ElastiCache Redis.

### C. Android Release Build & Signing
```bash
cd android

# Generate production signed bundle
./gradlew bundleRelease

# Verify ProGuard R8 obfuscation
./gradlew checkReleaseDuplicateClasses
```
