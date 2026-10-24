# SENTINEL X

Universal AI-Powered Cross-Platform Cybersecurity & Device Protection Platform.

## Overview
SENTINEL X is a modular security ecosystem providing real-time threat detection, malware scanning, phishing prevention, network monitoring, application permission monitoring, email security, browser protection, and automated threat response across Android, iOS, Windows, macOS, Linux, and browser extensions. A shared core prioritizes functional security over UI polish.

## Architecture
- `core/`: Shared security engine (detectors, scoring, intel, schemas, models) designed to be reusable by agents and backend.
- `backend/`: FastAPI backend (auth, devices, threats, scanning, network, AI, quarantine, audit, reporting).
- `frontend/`: React + TypeScript + Tailwind dashboard.
- `agents/`: Platform-specific endpoint agents (Linux functional where possible; others documented with limitations).
- `extensions/`: Browser extensions (TypeScript) for URL/phishing protection.
- `docs/`: Architecture, SRS, schema, API, guides, reports.
- `infra/`: Docker/CI/deployment.
- `scripts/`: Setup/test helpers.

## Core Features
Real-time URL/phishing, full device/file scanning (ClamAV/YARA aware), APK analysis scaffolding, permission monitoring, network/DNS/blocking, browser protection, email security (OAuth), ransomware/behavioral detection, download protection, vulnerability scanning, USB/external device checks, AI threat intelligence with explainable scoring, automated response engine with approvals/quarantine, protection modes, and full audit logging.

## Quick Start
### Backend
```bash
pip install -r backend/requirements.txt  # or use system packages
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
### Frontend
```bash
cd frontend && npm install && npm run dev
```
### Linux agent (functional prototype)
```bash
cd agents/linux && cargo test  # if Rust available
```

## Security & Privacy
Explicit consent, least privilege, encrypted storage/transit, no credential collection, no covert surveillance, audit logs, safe quarantine, false-positive recovery. Features unavailable due to OS restrictions are clearly indicated.

## License
Proprietary - for educational/project use.
