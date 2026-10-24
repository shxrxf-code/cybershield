# SENTINEL X Architecture

## System Overview
SENTINEL X is a unified, modular cybersecurity platform with shared core engine, backend API, web dashboard, platform agents, and browser extensions.

## Components
- **Core Engine** (`core/`): Shared detectors (URL/phishing), risk scoring, schemas, intel hooks. Language-agnostic logic.
- **Backend API** (`backend/`): FastAPI microservices-style modules (auth, devices, threats, scan, network, email, AI, quarantine, audit, reports). PostgreSQL/SQLite + Redis.
- **Frontend Dashboard** (`frontend/`): React + TypeScript + Tailwind, dark-first, 16 modules.
- **Platform Agents** (`agents/`): Linux (Rust functional), Android (Kotlin scaffold), iOS (Swift scaffold), Windows/macOS (scaffolds with documented limits).
- **Browser Extensions** (`extensions/`): Manifest V3 for Chrome/Edge/Firefox/Safari with real URL checks via API.
- **Integrations**: ClamAV, YARA (hooks), Suricata, Zeek, VirusTotal, MobSF, osquery, Wazuh, Falco (adapters).

## Data Flow
1. Agent/Extension detects event -> Backend API
2. Core engine analyzes -> Risk scoring (0-100) with explainability
3. Response engine applies policy (allow/warn/block/quarantine/isolate) with approvals
4. Audit log recorded, notifications sent
5. Dashboard displays real-time status

## Security Principles
- Least privilege, explicit consent
- No covert surveillance, no credential collection
- Encrypted transit/storage
- Safe quarantine, false-positive recovery
- AI predictions never trigger irreversible actions alone
- Platform restrictions honored

## Deployment
Docker-ready, supports local/offline modes with cached signatures.
