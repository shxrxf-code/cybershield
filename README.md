# 🛡️ ShieldGuard AI - Enterprise Android Cybersecurity Platform

[![CI/CD Pipeline](https://github.com/cybershield/shieldguard-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/cybershield/shieldguard-ai/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)
[![Android](https://img.shields.io/badge/Android-Target%20SDK%2035-3DDC84.svg)](https://developer.android.com)
[![Kotlin](https://img.shields.io/badge/Kotlin-1.9+-7F52FF.svg)](https://kotlinlang.org)

**ShieldGuard AI** is a production-ready, autonomous cybersecurity platform designed to protect Android endpoints against multi-vector threats, advanced malware campaigns, social engineering, smishing, network exploitation, and rogue applications.

---

## 🎯 19-Point Threat Matrix Protection

1. **Phishing Links**: Real-time lexical analysis, typosquatting & homograph detection.
2. **Malicious Websites**: Live categorization & automated blocking via Safe DNS.
3. **Malicious APK Files**: Static permissions, native payload & behavioral signature audit.
4. **Malware Documents**: Active macro (`vbaProject.bin`) & PDF exploit stream scanning (`/Launch`, `/JS`).
5. **SMS Phishing (Smishing)**: NLP classification for toll scams, fake deliveries, & banking fraud.
6. **Email Phishing**: SPF, DKIM, and DMARC verification with spoofing detection.
7. **Notification Scams**: `NotificationListenerService` monitoring WhatsApp, Telegram, Instagram, & SMS.
8. **Fake Banking Apps**: Accessibility + Screen Overlay + SMS interception combination detection.
9. **Trojan Applications**: Heuristic payload analysis and unverified origins auditing.
10. **Spyware**: Ambient sensory harvesting detection (Microphone, Camera, Contacts, Location).
11. **Ransomware**: Device Administrator binding & screen locker detection.
12. **Harmful Downloads**: Storage directory monitoring and automatic threat quarantine.
13. **Dangerous Permissions**: Comprehensive privilege matrix scoring.
14. **QR Code Attacks**: Pre-execution URL inspection before opening in browsers.
15. **Clipboard Hijacking**: Real-time monitoring of crypto address manipulation.
16. **Network Attacks**: ARP poisoning and MITM packet detection.
17. **Public WiFi Threats**: Rogue gateway identification and automated encryption enforcement.
18. **Browser Threats**: Built-in safe web navigation with ad, tracker, and malicious host blocking.
19. **Social Engineering Messages**: NLP urgency and credential harvest detection.

---

## 🏗️ Repository Architecture

```
cybershield/
├── .github/
│   └── workflows/ci.yml              # Automated CI/CD (Linting, Tests, Docker Build)
├── backend/
│   ├── ai_models/                    # Machine Learning training pipelines (XGBoost, NLP)
│   ├── app/
│   │   ├── api/v1/                   # REST API Routers (URLs, APKs, Docs, SMS, Devices)
│   │   ├── core/                     # Config, Database, Redis, Security
│   │   ├── models/                   # SQLAlchemy PostgreSQL Models
│   │   ├── schemas/                  # Pydantic v2 Request & Response Schemas
│   │   └── services/
│   │       ├── ml_engine/            # Lexical, NLP & Behavioral Classifiers
│   │       ├── scanner/              # APK & Document Static Analysis Engines
│   │       ├── threat_intel/         # VirusTotal, AbuseIPDB, PhishTank, AlienVault
│   │       └── report_generator/     # PDF & CSV Executive Reporting Engine
│   ├── tests/                        # Comprehensive Pytest Suite
│   ├── Dockerfile                    # Hardened Multi-Stage Production Container
│   └── requirements.txt
├── android/
│   ├── app/
│   │   ├── src/main/
│   │   │   ├── AndroidManifest.xml   # Permissions, NotificationListener, VpnService
│   │   │   └── java/com/shieldguard/ai/
│   │   │       ├── data/             # Room DB, Retrofit API, EncryptedSharedPreferences
│   │   │       ├── di/               # Dagger-Hilt Dependency Injection Modules
│   │   │       ├── domain/           # Clean Architecture Use Cases & Models
│   │   │       ├── scanner/          # Root, APK & Document Scanner Engines
│   │   │       ├── service/          # NotificationMonitorService, ShieldGuardVpnService
│   │   │       └── ui/               # Material 3 Jetpack Compose UI (Dashboard, Scanners)
│   │   └── build.gradle.kts
│   └── build.gradle.kts
├── docs/
│   ├── architecture.md               # Architecture Diagrams, Threat Models, Deploy Guides
│   └── schema.sql                    # Production PostgreSQL DDL Script
└── docker-compose.yml                # Multi-service stack (FastAPI, PostgreSQL, Redis)
```

---

## 🚀 Quickstart Guide

### 1. Launching the Backend Cloud & Threat Feeds
```bash
# Clone the repository
git clone https://github.com/cybershield/shieldguard-ai.git
cd shieldguard-ai

# Start backend services using Docker Compose
docker compose up -d --build

# Verify API status
curl http://localhost:8000/health
```

The interactive OpenAPI Swagger UI will be accessible at `http://localhost:8000/docs`.

### 2. Running Backend Engine Unit Tests
```bash
python backend/tests/run_tests.py
```

### 3. Building the Android Client
Open the `android/` directory in Android Studio (Giraffe or newer):
```bash
cd android
./gradlew assembleDebug
```

---

## 🔒 Security & Compliance
- **OWASP Mobile Top 10 Compliant**
- **Hardware-Backed Keystore Encryption (AES-256-GCM)**
- **Strict Network Certificate Pinning**
- **Zero Privacy Violation**: Chat contents are processed on-device and never exfiltrated.
