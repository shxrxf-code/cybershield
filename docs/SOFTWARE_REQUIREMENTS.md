# CyberShield Software Requirements Specification (SRS)

## 1. Introduction
This document defines the functional and non-functional requirements for the **CyberShield** cross-platform cybersecurity platform.

## 2. Functional Requirements

### FR-01: Real-Time URL & Phishing Protection (Module A)
- System shall detect malicious domains, brand impersonation, and credential-harvesting keywords.
- System shall detect IDN / Punycode homograph attacks (e.g. `xn--...`).
- System shall evaluate newly registered domain indicators and domain entropy.
- System shall provide user warnings containing URL, threat category, severity, and recommended action.

### FR-02: Full Device & File Scanner (Module B)
- System shall support Quick Scan, Full Scan, and Custom Path Scans.
- System shall calculate SHA256 and MD5 hashes and verify against threat databases.
- System shall integrate ClamAV (`clamscan`) and YARA rule matchers where available.
- System shall detect standard EICAR test files without false negatives.
- System shall manage an encrypted quarantine vault for isolated payloads.

### FR-03: APK Security Scanner (Module C)
- System shall extract Android package metadata, version, and signing certificates.
- System shall identify dangerous permission combinations (e.g., SMS + Accessibility + Background).
- System shall detect embedded hardcoded secrets, suspicious C2 URLs, and native binary libraries.
- System shall output an explainable threat score from 0 to 100.

### FR-04: Application Permission Monitor (Module D)
- System shall monitor high-impact permissions: Camera, Microphone, Location, Contacts, SMS, Storage, Accessibility, Notification Listener.
- System shall flag excessive permissions and unusual background access.
- System shall provide real-time running process enumeration, resource monitoring, and authorized process termination/isolation.

### FR-05: Network Security & Monitoring (Module E)
- System shall monitor outbound DNS queries and flag malicious destination IPs.
- System shall detect ARP spoofing indicators and unencrypted cleartext protocols.
- System shall support Suricata IDS/IPS log ingestion and threat-based domain blocking.
- System shall provide whitelist and blacklist customization with immediate rule enforcement.

### FR-06: Browser Security (Module F)
- System shall provide cross-browser Manifest V3 extensions (Chrome, Edge, Firefox).
- System shall intercept page navigations and query the backend URL threat engine.
- System shall display in-page security banners when insecure login forms or homographs are detected.
- System shall pre-scan downloads for double extensions and dangerous executable formats.

### FR-07: Email Security (Module G)
- System shall analyze email headers for SPF, DKIM, and DMARC alignment.
- System shall detect Business Email Compromise (BEC) and sender spoofing indicators.
- System shall inspect email attachments and embedded links for phishing signatures.

### FR-08: Ransomware Protection (Module H)
- System shall deploy and monitor decoy honeypot canary tokens in sensitive folders.
- System shall detect anomalous Shannon entropy jumps (>7.2 bits/byte) indicative of file encryption.
- System shall monitor mass file alteration frequency and provide emergency process suspension.

### FR-09: System Vulnerability Scanner (Module J)
- System shall audit listening TCP/UDP ports and public interface exposure (`0.0.0.0`).
- System shall check for weak operating system configurations (e.g. `/etc/shadow` permissions, SSH root login).
- System shall compute a 0–100 system security posture score with actionable remediations.

### FR-10: User Control & Security Modes (Section 5)
- System shall provide six operational protection modes: Smart Protection, Deep Scan, Network Shield, Privacy Mode, Gaming Mode, and Manual Control.
- System shall allow fine-grained category toggles and configurable scan schedules.

## 3. Non-Functional Requirements
- **Performance**: Scanning routines must operate with resource awareness without causing high CPU spikes during idle mode.
- **Privacy**: No plaintext credentials, keystrokes, or private messages shall be collected or stored.
- **Data Integrity**: Audit logs shall be chained using SHA-256 hashes to guarantee tamper evidence.
- **Reliability**: Graceful fallback to heuristic signatures when external tools (e.g. ClamAV daemon) are offline.
