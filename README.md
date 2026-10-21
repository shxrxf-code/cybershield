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
| `mobile/` | **Expo** app (TypeScript, SDK 58 / React Native 0.88). UI, navigation, state, local database, and the typed bridge to the native layer. |
| `mobile/android/` | Java/Kotlin native modules: notification listener, background workers, SAF/MediaStore access, hashing, package inspection. |
| `mobile/plugins/` | Expo config plugin that re-applies the hand-written native customisations across `expo prebuild`. |
| `backend/` | Node.js + Express + TypeScript REST API. Threat-intelligence aggregation, caching, rate limiting, persistence. |
| `docs/` | Architecture, migration, device testing and the roadmap. |
| `scripts/` | Local toolchain helpers (Android SDK setup, downloader, dev environment). |

## Documentation

- [Architecture](docs/architecture/README.md)
- [Expo migration report](docs/migration/expo-migration-report.md)
- [Roadmap & phase status](docs/roadmap.md)
- [Device test plan](docs/testing/device-test-plan.md)

## Getting started

### Prerequisites

The Android toolchain is not on the default `PATH` on a fresh machine. Install
it once and then source the environment before any Gradle/adb/Expo command:

```bash
./scripts/setup-android-toolchain.sh
source scripts/dev-env.sh
```

### Backend (Node 20+)

```bash
cd backend
cp .env.example .env
npm install
npm run gen:key            # prints an API key and its hash; add the hash to
                           # API_KEY_HASHES in .env
npm run dev                # http://localhost:8000
```

### Mobile (Expo, JDK 17 + Android SDK)

```bash
cd mobile
npm install

# Development build on a connected device or emulator.
# This is required — the custom native modules (file scanner, notification
# listener, app inspection) do NOT work in Expo Go.
npx expo run:android
```

To run the dev server on its own (for an already-installed development build):

```bash
cd mobile
npx expo start --dev-client
```

The app talks to the backend at `http://10.0.2.2:8000` in development (the
emulator's alias for the host). On a physical device, forward the port instead:

```bash
adb reverse tcp:8000 tcp:8000
```

## Security posture (summary)

- Third-party API keys live **only** on the backend. The mobile app ships none.
- All analysis is **static**. Suspect files are read as bytes; nothing is run.
- Notification content is analysed transiently. Only a redacted reason, a hash
  and metadata are persisted — never the full message body.
- Risk language is deliberately honest: `SAFE`, `SUSPICIOUS`, `MALICIOUS`,
  `UNKNOWN`, with the reason, source and confidence behind each verdict.
- `UNKNOWN` is never presented as `SAFE`.
