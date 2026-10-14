# Roadmap & phase status

Each phase ends with an explicit verification step. A phase is only marked
**Done** when its build/typecheck/tests actually pass in this repository — no
feature is declared complete on the strength of it "looking right".

Legend: ✅ done & verified · 🟡 in progress · ⬜ not started · ⚠️ blocked by environment

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | Toolchain + monorepo scaffolding | ✅ |
| 1 | Design system, theme, navigation, 16 screens | ✅ |
| 2 | Local SQLite data layer + repositories + stores | ✅ |
| 3 | Backend API (Express + TS + DB + providers + tests) | ✅ |
| 4 | URL scanner end-to-end | 🟡 |
| 5 | File scanner (PDF / image / APK) + native access | 🟡 |
| 6 | Kotlin notification monitoring + analyzer | ⬜ |
| 7 | Real-time alert system | ⬜ |
| 8 | Full device scan + WorkManager background protection | ⬜ |
| 9 | History, reports, permissions, settings, about | ⬜ |
| 10 | Security/perf hardening, docs, APK build + device test | ⬜ |

### Phase 0 — Toolchain + scaffolding
- [x] Environment audit
- [x] Monorepo layout, `.gitignore`, `.editorconfig`, base `tsconfig`
- [x] Local JDK 17 (Temurin) installed & pinned
- [x] React Native project generated under `mobile/`
- [x] Backend project generated under `backend/`
- [x] Verified: `tsc --noEmit` in both packages (backend ✅, mobile ✅)
- [ ] Android APK build verified on device (moved to Phase 10)

### Phase 1 — Design system & navigation
- [x] Design tokens (colour, spacing, radius, typography, elevation)
- [x] Themed components (Card, Button, Badge, Gauge, StatTile, ListRow…)
- [x] React Navigation (native stack + bottom tabs) with typed params
- [x] All 16 screens present with honest loading / empty / error states
- [x] Verified: `tsc --noEmit` clean, `eslint` 0 errors, Jest renders the app tree

> **Note on honesty:** native-dependent screens (device/file/app scan, message
> monitoring, URL reputation) render their real interface but keep their action
> disabled and state plainly that the capability is not in this build. Nothing
> is simulated and no verdict, score or row is invented. The single switchboard
> for this is `mobile/src/capabilities.ts`.

### Phase 2 — Local data layer
- [x] SQLite schema (scans, alerts, settings) with migration framework
- [x] op-sqlite service wrapper with migrations, transactions, reactive queries
- [x] Scan repository (CRUD, API sync, recent/by-type/by-hash queries)
- [x] Alert repository (CRUD, read/unread, unread count, recent)
- [x] Settings repository (key-value with JSON, privacy prefs, onboarding flag)
- [x] Stores migrated to repositories (async, persisted, refresh on boot)
- [x] App initializes DB on startup, loads settings, handles 'system' theme
- [x] Verified: `tsc --noEmit` clean, `eslint` 0 errors, Jest 53/53 pass

### Phase 4 — URL scanner end-to-end
- [x] Local URL syntax parser (`src/utils/url.ts`) with 13 unit tests
- [x] API client (`src/api/client.ts`) with `scanUrl` and health check
- [x] Screen integration (`UrlScannerScreen`) calls backend when capability enabled
- [x] No fake verdicts — returns "Unverified" until reputation confirms

### Phase 5 — File scanner (PDF / image / APK) + native access
- [x] API client `scanFileHash` endpoint integration
- [x] Screen integration (`FileScannerScreen`) with fingerprint lookup flow
- [ ] Native file picker + SHA-256 streaming hash (needs SAF / MediaStore)
- [ ] PDF text extraction, image OCR, APK analysis (Phase 5+6)

### Phase 2 — Local data layer
- [ ] SQLite bootstrap + migrations
- [ ] Repositories: scans, alerts, settings
- [ ] Zustand stores wired to repositories

### Phase 3 — Backend
- [x] Express app, error envelope, request-id, logger
- [x] API-key auth, rate limiting, Zod validation
- [x] Providers: Google Safe Browsing, URLhaus, VirusTotal (+ composite)
- [x] TTL cache + timeout/retry + graceful degradation
- [x] SQLite dev / Postgres-ready schema
- [x] Jest + supertest suite (97 tests: unit `tsc --noEmit` clean + app-level integration)
- [x] `createApp`/`server.ts` wiring: helmet, CORS, JSON cap, graceful shutdown

### Phase 4 — URL scanner
- [ ] Local syntax/domain/entropy analysis (device-side, offline-capable)
- [ ] Backend reputation request + verdict merge
- [ ] URL Scanner screen, clipboard consent, result cards

### Phase 5 — File scanner
- [ ] SAF/MediaStore pickers (native)
- [ ] Signature + MIME + size validation, streaming SHA-256
- [ ] PDF structural analysis, EXIF inspection, APK inspection
- [ ] VirusTotal hash lookup via backend (consent-gated)

### Phase 6 — Notification monitoring
- [ ] `NotificationListenerService` (Kotlin)
- [ ] Scam/phishing heuristic engine + unit tests
- [ ] Social-protection screen with per-app toggles

### Phase 7 — Alerts
- [ ] `AlertNotifier` with channels + dedupe
- [ ] Alerts screen, read/unread, severity filters

### Phase 8 — Background protection
- [ ] WorkManager periodic job + constraints
- [ ] `BootReceiver` rescheduling
- [ ] Foreground service for user-initiated long scans
- [ ] Battery-aware status surface

### Phase 9 — History / reports / permissions / settings
- [ ] Scan history with search + filters
- [ ] Threat detail + security report screens
- [ ] Permission management with rationale + settings deep-links

### Phase 10 — Hardening & delivery
- [ ] Security review (no key leakage, no private-data access)
- [ ] Performance pass (streaming, cancellation, caching)
- [ ] Full docs set + APK build + on-device test
