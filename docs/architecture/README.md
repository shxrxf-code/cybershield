# Architecture

Mobile ThreatGuard is a three-tier system: a **React Native (TypeScript)**
application, a **Kotlin** native layer that owns every Android-specific
capability, and a **Node.js/Express** backend that aggregates third-party threat
intelligence behind a single authenticated API.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          Android device (app process)                    │
│                                                                          │
│  React Native / TypeScript (UI + domain)                                 │
│  ┌────────────┐ ┌────────────┐ ┌──────────────┐ ┌──────────────────┐     │
│  │  screens/  │ │ navigation │ │  services/   │ │ store/ hooks/    │     │
│  └─────┬──────┘ └─────┬──────┘ └──────┬───────┘ └────────┬─────────┘     │
│        │              │               │                   │              │
│        └──────────────┴───────┬───────┴───────────────────┘              │
│                               │  typed NativeModules bridge (TS)          │
│  ┌────────────────────────────▼─────────────────────────────────────┐    │
│  │              Kotlin native layer (isolated modules)              │    │
│  │  NotificationMonitorService  FileInspection  Sha256Stream        │    │
│  │  BackgroundWorkers (WorkManager)  BootReceiver  SafeFileAccess   │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                               │                                          │
│  ┌────────────────────────────▼─────────────────────────────────────┐    │
│  │  SQLite (local)  —  scan_history · threat_alerts · settings      │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │  HTTPS  ·  X-API-Key  ·  JSON
┌───────────────────────────────▼──────────────────────────────────────────┐
│                        Backend (Node.js + Express + TS)                  │
│                                                                          │
│  routes → controllers → services → threat-intel adapters                 │
│  middleware: auth · rate-limit · validation(Zod) · error envelope        │
│                                                                          │
│  ThreatIntel providers (server-side keys only):                          │
│    GoogleSafeBrowsing   URLhaus   VirusTotal   (＋ local signature DB)    │
│                                                                          │
│  Cache (TTL)  ──►  prevents duplicate lookups & external rate pressure    │
│  Persistence: SQLite (dev)  ·  PostgreSQL-ready (prod)                    │
└──────────────────────────────────────────────────────────────────────────┘
```

## Layering rules

1. **The mobile app never holds a third-party API key.** All reputation lookups
   go through our backend, which injects the keys server-side.
2. **Android-specific capability lives only in Kotlin.** TypeScript calls it
   through one typed bridge module (`ThreatGuardNative`). No JS reads a file or
   a notification directly.
3. **Services are pure where possible.** URL syntax/domain/entropy logic and
   notification scam heuristics are deterministic functions, unit-tested without
   a device.
4. **The database is behind repositories.** UI code never issues SQL; it reads
   through `database/repositories/*`, so the store can be swapped.
5. **Honest verdicts.** A verdict carries a status, a confidence and a list of
   reasons. Absence of evidence is `UNKNOWN`, never `SAFE`.

## Mobile module map

```
mobile/src/
├── components/     reusable, presentational (cards, badges, charts…)
├── screens/        one folder per screen; containers own data, children don't
├── navigation/     navigators, typed route params, deep links
├── services/       api client, url scanner, file scanner, notif analyzer, alerts
├── hooks/          useScan, useUrlScan, useThreatAlerts, usePermissions…
├── store/          Zustand stores (settings, session, scan state machine)
├── database/       SQLite bootstrap + repositories
├── utils/          url parsing, formatting, hashing helpers, validation
├── constants/      package allow-lists, severity maps, endpoints
├── types/          shared domain types & enums
└── theme/          design tokens (colors, spacing, typography, radii)
```

## Native module map (Kotlin)

```
mobile/android/app/src/main/java/com/threatguard/mobile/
├── ThreatGuardModule.kt        NativeModule: JS-callable entry points
├── ThreatGuardPackage.kt       ReactPackage registration
├── notification/
│   ├── NotificationMonitorService.kt   NotificationListenerService
│   └── NotificationAnalyzer.kt         scam/phishing heuristics (pure, tested)
├── files/
│   ├── FileInspector.kt        signatures, MIME, size, EXIF, PDF structure
│   ├── Sha256Stream.kt         streaming digest (no full-file buffering)
│   └── SafeFileAccess.kt       SAF / MediaStore helpers
├── packages/
│   └── ApkInspector.kt         PackageManager metadata, permissions, signing
├── background/
│   ├── BackgroundProtectionWorker.kt   WorkManager job
│   ├── BootReceiver.kt                 re-schedule after reboot
│   └── ScanForegroundService.kt        user-initiated long scans
└── alerts/
    └── AlertNotifier.kt        NotificationManager, dedupe, channels
```

## Backend module map

```
backend/src/
├── app.ts / server.ts      express wiring & bootstrap
├── routes/                 URL → controller mapping
├── controllers/            HTTP shape only
├── services/               url-reputation, file-analysis, notifications, history
├── providers/              one adapter per external API + a composite aggregator
├── middleware/             apiKeyAuth, rateLimit, validate, errorHandler, requestId
├── database/               connection, migrations, repositories
├── validators/             Zod schemas
└── utils/                  http client (timeout/retry), hashing, logger, cache
```
