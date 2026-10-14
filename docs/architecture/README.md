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
│  │              Native layer (isolated modules)                      │    │
│  │  scanner/ (FileScannerModule · FileScanner · HashScanner ·        │    │
│  │            SignatureScanner · ScanResult)                          │    │
│  │  planned: NotificationMonitorService · BackgroundWorkers ·         │    │
│  │           BootReceiver · ApkInspector                              │    │
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
2. **Android-specific capability lives only in the native layer.** TypeScript calls
   it through one typed bridge module per capability (`FileScanner`). No JS reads a
   file or a notification directly.
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
├── api/            backend client (URL + file-hash reputation lookups)
├── native/         typed bridges to native modules (FileScanner*)
├── hooks/          useFileScanner, useUrlScan, useThreatAlerts…
├── store/          Zustand stores (settings, scans, alerts)
├── db/             SQLite bootstrap + repositories + migrations
├── domain/         verdict/threat mapping & types (pure, tested)
├── utils/          url parsing, formatting, validation
└── theme/          design tokens (colors, spacing, typography, radii)
```

## Native module map

### Implemented — file-scanning engine (`com.threatguard.mobile.scanner`)

A legacy React Native module (works with both architectures), written in Java
because it uses only `java.io` (the `java.nio.file` API is API 26+ and would
crash below that; the app's `minSdkVersion` is 24).

```
mobile/android/app/src/main/java/com/threatguard/mobile/scanner/
├── FileScannerModule.java     RN bridge: pickFile, scanFile, computeFileHash,
│                              cancelScan, clearCache, getConstants, progress events
├── FileScanner.java           orchestration: size/MIME validation, engine options
├── HashScanner.java           streaming SHA-256 with progress + cancellation
├── SignatureScanner.java      magic-byte family detection, extension↔content
│                              consistency, streaming signatures, APK structure
├── ScanResult.java            status + severity-tagged findings → WritableMap
└── ScanCancelledException.java
```

Registration: `FileScannerPackage` is added in `MainApplication.kt`. File access
goes through the **Storage Access Framework** (`ACTION_OPEN_DOCUMENT`), so the
manifest requests only `INTERNET` — no storage permission at all. Scan work runs
on a single-thread executor; progress is delivered with `emitDeviceEvent`
(bridgeless-safe).

### Implemented — notification monitoring (`com.threatguard.mobile.notification`)

The notification listener is a thin Kotlin service that only reads the text Android exposes for each posting notification (title/text/subText/bigText/sumText where present), the package name and app label. Nothing is persisted; everything else is scored in pure TypeScript (`src/domain/notificationAnalyzer`) so it is unit-testable.

```
mobile/android/app/src/main/java/com/threatguard/mobile/notification/
├── NotificationPrefs.kt           SharedPreferences: monitoring enabled, ignored packages, seen sources
├── NotificationBridge.kt         Static weak ReactContext for event emission
├── NotificationMonitorService.kt NotificationListenerService (reads exposed text, filters by prefs, emits capped payloads)
├── NotificationMonitorModule.kt  RN bridge: access, connected, open settings, mirror prefs, getSeenSources, hasNotificationPermission, postThreatAlert
└── NotificationMonitorPackage.kt Package registration
```

Registration: `NotificationMonitorPackage()` added to `MainApplication.kt`. Manifest declares the service with `android:exported="false"`, `android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"` and the required intent-filter. Manifest also declares `POST_NOTIFICATIONS` (Android 13+).

### Planned (later phases)

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
