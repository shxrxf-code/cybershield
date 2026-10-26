# CyberShield System Architecture Documentation

## 1. Executive Summary
**CyberShield** is a universal AI-powered cross-platform cybersecurity and endpoint device protection platform designed to protect users against evolving cyber threats across Android, iOS, Windows, macOS, Linux, and modern web browsers.

The platform provides real-time threat detection, malware scanning, phishing prevention, network monitoring, application permission monitoring, email security, browser protection, and automated threat response.

```
+-----------------------------------------------------------------------------------+
|                           CYBERSHIELD UNIFIED PLATFORM                            |
+-----------------------------------------------------------------------------------+
|  ENDPOINT AGENTS                                                                  |
|  [Android - Kotlin]   [iOS - Swift]   [Linux - Rust]   [Windows - Rust/C#]       |
|  [macOS - Swift/Rust] [Web Extensions - TypeScript (Chrome/Edge/Firefox)]         |
+-----------------------------------------------------------------------------------+
                                         | REST / WebSocket API
+-----------------------------------------------------------------------------------+
|  BACKEND SERVICES (FastAPI, Python 3.13, Async Workers)                           |
|  - Auth & RBAC Service         - Device Management Service                        |
|  - URL Intelligence Service    - Malware & EICAR Scanning Service (ClamAV/YARA)   |
|  - APK Static Analysis Engine  - Network Shield & DNS Filter                      |
|  - Email Phishing & BEC Engine - Ransomware Canary & Shannon Entropy Service      |
|  - Vulnerability Scanner       - Quarantine AES-256 GCM Vault                     |
|  - AI Threat Inference Service - Tamper-Evident SHA256 Chained Audit Logging      |
+-----------------------------------------------------------------------------------+
                                         |
+-----------------------------------------------------------------------------------+
|  PERSISTENCE & THREAT INTEL                                                       |
|  - PostgreSQL / SQLite (21 Normalized Security Tables)                            |
|  - ClamAV Signature DB / YARA Rule Sets                                           |
|  - IoC Threat Intelligence Feeds (Abuse.ch, CISA, VirusTotal)                     |
+-----------------------------------------------------------------------------------+
```

## 2. Core Architectural Principles
1. **Functional Security Capabilities Over Superficial UI**: Every dashboard action connects to real backend APIs and detection routines.
2. **Platform Sandbox Respect**: Adheres to OS security boundaries (e.g., does not claim unrestricted full-disk access on iOS/Android where forbidden by mobile sandboxes).
3. **Defense in Depth**: Combines deterministic signature matching, heuristic static analysis, behavioral monitoring, and machine-learning threat scoring.
4. **Explainable AI (XAI)**: Generates transparent risk scores (0–100) with contributing factor breakdowns rather than opaque black-box verdicts.
5. **Safe Quarantine & Recovery**: Threat files are encrypted (AES-256) into an isolated vault; reversible without permanent data destruction unless explicitly confirmed.
