# Mobile ThreatGuard

AI-assisted Android antivirus and cyber-threat detection system.

Mobile ThreatGuard is a privacy-first, permission-based Android security app. It
inspects **URLs**, **files** (PDF / images / APK / documents) and the
**notification text that Android actually exposes** to detect phishing, scams and
malicious content. It never executes, opens or uploads a suspect artefact
without explicit user consent, and it never reports an unknown result as "safe".

> This is a final-year academic project. It is a **real, working** application,
> not a mock-up: every screen is backed by live scanner data, the detection
> logic runs for real, and the native Android integrations use the platform APIs
> they are designed for. Where Android forbids something, the app says so and
> implements the closest legitimate alternative instead of pretending.

---

## Repository layout

| Path | Contents |
|------|----------|
| `mobile/` | React Native CLI app (TypeScript). UI, navigation, state, local database, and the typed bridge to the native layer. |
| `mobile/android/` | Kotlin native modules: notification listener, background workers, SAF/MediaStore access, hashing, package inspection. |
| `backend/` | Node.js + Express + TypeScript REST API. Threat-intelligence aggregation, caching, rate limiting, persistence. |
| `docs/` | Architecture, API reference, database schema, threat model, testing and the final-year project report. |

## Documentation

- [Architecture](docs/architecture/README.md)
- [Roadmap & phase status](docs/roadmap.md)
- [API reference](docs/api/README.md)
- [Database schema](docs/database/README.md)
- [Security & threat model](docs/security/README.md)

## Getting started

See [docs/development.md](docs/development.md) for the full environment setup,
then:

```bash
# Backend (Node 20+)
cd backend
cp .env.example .env
npm install
npm run dev          # http://localhost:8000

# Mobile (React Native CLI + JDK 17 + Android SDK)
cd mobile
npm install
npm run android      # builds and installs on a connected device / emulator
```

## Security posture (summary)

- Third-party API keys live **only** on the backend. The mobile app ships none.
- All analysis is **static**. Suspect files are read as bytes; nothing is run.
- Notification content is analysed transiently. Only a redacted reason, a hash
  and metadata are persisted — never the full message body.
- Risk language is deliberately honest: `SAFE`, `SUSPICIOUS`, `MALICIOUS`,
  `UNKNOWN`, with the reason, source and confidence behind each verdict.
- `UNKNOWN` is never presented as `SAFE`.
