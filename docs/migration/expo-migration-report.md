# Expo Migration Report — Mobile ThreatGuard

**Date:** 2026-10-21
**Baseline commit:** `33f97b5` — _feat: implement on-device app inspection module for Android_
**Backup:** tag `pre-expo-migration` (clean tree, `git status` empty at time of report)
**Method:** static inspection of the repository, comparison against the upstream
React Native `0.87.1` / `0.88.0` templates and the Expo SDK 58
`expo-template-bare-minimum` template, plus registry look-ups for version
compatibility.

---

## 1. Current stack (as inspected)

| Area | Value |
| --- | --- |
| Project type | React Native **CLI** (bare), not Expo |
| React Native | **0.87.1** (`@react-native/*` dev deps pinned 0.87.1) |
| React | 19.2.3 |
| TypeScript | ^6.0.3, extends `@react-native/typescript-config` |
| Entry point | `index.js` → `AppRegistry.registerComponent(name from app.json)` |
| `app.json` | **Non-Expo shape**: `{ "name", "displayName" }` — no `expo` key |
| JS engine | Hermes (`hermesEnabled=true`) |
| New Architecture | enabled (`newArchEnabled=true`) |
| Android min/target/compile SDK | 24 / 36 / 37, build-tools 37.0.0, NDK 27.1.12297006, Kotlin 2.2.0 |
| Edge-to-edge | enabled (`edgeToEdgeEnabled=true`) |
| Local database | `@op-engineering/op-sqlite` 18.2.5, DB `threatguard.db` |
| Navigation | React Navigation v7 (native-stack + bottom-tabs) |
| State | Zustand 5 |
| Icons | lucide-react-native + react-native-svg |
| Tests | Jest 29 with `@react-native/jest-preset` |
| Backend | separate Express service (`../backend`), API-key auth |

## 2. Native Android inventory (must be preserved)

All Kotlin/Java sources live under `android/app/src/main/java/com/threatguard/mobile/`.
They are **not** autolinked libraries — they are hand-registered in `MainApplication.kt`.

| Module (JS name) | Sources | Registration | Manifest dependencies |
| --- | --- | --- | --- |
| `FileScanner` | `scanner/FileScanner{Module,Package}.java`, `FileScanner.java`, `HashScanner.java`, `SignatureScanner.java`, `ScanResult.java`, `ScanCancelledException.java` | `add(FileScannerPackage())` | none (Storage Access Framework; no storage permission) |
| `NotificationMonitor` | `notification/NotificationMonitor{Module,Package}.kt`, `NotificationMonitorService.kt`, `NotificationBridge.kt`, `NotificationPrefs.kt` | `add(NotificationMonitorPackage())` | `<service>` with `BIND_NOTIFICATION_LISTENER_SERVICE`; `POST_NOTIFICATIONS` runtime permission |
| `AppInspection` | `appinspection/AppInspection{Module,Package}.kt`, `AppRiskAnalyzer.kt` | `add(AppInspectionPackage())` | `<queries>` block (package visibility, Android 11+) |

### Deviations of `android/` from the upstream RN 0.87.1 template

Diffed file-by-file against `@react-native-community/template@0.87.1`:

1. **`android/build.gradle`** — extra `subprojects { … }` block that adds a
   `debug` build type to `op-engineering_op-sqlite` (the library only ships a
   `release` build type; the debug variant needs its prefab). **Custom; keep.**
2. **`MainApplication.kt`** — three manual `add(…Package())` calls.
   **Custom; keep.**
3. **`AndroidManifest.xml`** — `POST_NOTIFICATIONS` permission, the whole
   `<queries>` package-visibility block, and the notification-listener
   `<service>` element. **Custom; keep.**
4. **`MainActivity.kt`** — package + `getMainComponentName() = "MobileThreatGuard"`.
   Component name changes to `"main"` under Expo (see §6).
5. **`settings.gradle` / `app/build.gradle`** — only `rootProject.name`,
   `namespace` and `applicationId` differ from stock.
6. **`gradle.properties`** — byte-identical to the RN 0.87.1 template.
7. **`res/values/strings.xml`** — `app_name = MobileThreatGuard`. Launcher
   icons are PNGs (upstream template uses the same layout).

`debug.keystore`, `proguard-rules.pro`, `rn_edit_text_material.xml` and
`styles.xml` are stock.

**Conclusion:** the entire custom native surface is small, well-isolated and
fully listable — 3 file-level customizations plus one component-name change.
This is what the migration must guarantee survives.

## 3. Dependency compatibility assessment

### Compatible as-is (no change needed)
`@op-engineering/op-sqlite@18.2.5` (new-architecture compatible; not listed in
Expo's `bundledNativeModules.json`, so it is user-managed — it autolinks through
the React Native CLI config that Expo's autolinking also consumes),
`@react-navigation/*` v7, `zustand`, `lucide-react-native`, `react-native-svg`,
`react-native-safe-area-context`, `react-native-screens`.

### Must be aligned to Expo SDK 58
| Package | Now | Target | Why |
| --- | --- | --- | --- |
| `react-native` | 0.87.1 | **0.88.0** | SDK 58's bundled RN |
| `react` | 19.2.3 | **19.3.0** | SDK 58's bundled React |
| `@react-native/babel-preset` | 0.87.1 | 0.88.0 | RN version lockstep |
| `@react-native/metro-config` | 0.87.1 | 0.88.0 | idem |
| `@react-native/typescript-config` | 0.87.1 | 0.88.0 | idem |
| `@react-native/jest-preset` | 0.87.1 | 0.88.0 | idem |
| `@react-native/eslint-config` | 0.87.1 | 0.88.0 | idem |

**Why not stay on RN 0.87.1:** no Expo SDK ever shipped RN 0.87.x —
0.87 was skipped (SDK 57 → RN 0.86.3, SDK 58 → RN 0.88.0). `expo-doctor`
validates against `expo/bundledNativeModules.json`, and the dev client's native
layer is compiled against the SDK's RN. Keeping 0.87.1 would leave the project
in a permanently unsupported state, so the migration moves one minor version up
to exactly what the SDK pins (the documented `npx expo install --fix` path).

### Added
| Package | Version | Why |
| --- | --- | --- |
| `expo` | ~58.0.x | SDK core (also provides `expo/metro-config`, `expo/scripts/resolveAppEntry`, config-plugins) |
| `expo-dev-client` | ~58.0.x | native development build / dev launcher (replaces Expo Go) |
| `babel-preset-expo` | SDK-matched | required by `babel.config.js` under Expo |

### Removed
| Package | Why |
| --- | --- |
| `@react-native/new-app-screen` | RN template demo screen — **verified unused** (`grep` over `src/`, `App.tsx`, `index.js`, `__tests__/` finds no import) |
| `@react-native-community/cli`, `cli-platform-android`, `cli-platform-ios` | Expo drives builds/dev-server through `@expo/cli` (`npx expo run:android`, `expo start --dev-client`); the RN CLI packages are dev-dependencies of the bare workflow only. Autolinking still runs via `npx react-native config` **through** Expo's autolinking wrapper, which invokes the CLI that ships inside `expo`/`@react-native-community/cli` transitively — verified during the build stage. |

### Config files that must change
* `babel.config.js`: `module:@react-native/babel-preset` → `babel-preset-expo`
* `metro.config.js`: `@react-native/metro-config` → `expo/metro-config`
* `tsconfig.json`: `@react-native/typescript-config` → `expo/tsconfig.base`
* `package.json`: add `"main": "index.js"`, Expo scripts (`start` →
  `expo start --dev-client`, `android` → `expo run:android`, plus `prebuild`,
  `typecheck`)
* `app.json`: non-Expo shape → full `expo` config (name, slug, version,
  `android.package`, permissions, splash, icon)
* `index.js`: `AppRegistry.registerComponent(name)` → `registerRootComponent(App)`
  (the file stays the entry point; Expo reads the component name from the
  runtime, which is why the bare `import { name } from './app.json'` must go)

## 4. Findings against the task's feature list

The task lists features that must "continue working". Verified against the
actual tree:

| Listed feature | Status in source |
| --- | --- |
| Security dashboard | ✅ `src/screens/DashboardScreen.tsx` |
| File scanning | ✅ `FileScannerScreen` + Kotlin engine |
| App inspection | ✅ `AppScannerScreen` + `AppInspectionModule.kt` |
| Phishing URL checker | ✅ `UrlScannerScreen` + backend reputation API |
| Notification monitoring | ✅ `NotificationMonitorService.kt` + `NotificationProtectionScreen` |
| Permission management | ✅ `PermissionsScreen` |
| Scan history | ✅ `HistoryScreen` + SQLite |
| Settings | ✅ `SettingsScreen` |
| **Device security audit** | ❌ **absent** — no screen, no module |
| **Security Tools** | ❌ **absent** — no `src/features/`, no tool screens |
| **`DeviceSecurityModule.kt`** | ❌ **absent** — file does not exist |

These three items were never implemented at the baseline commit (the tree is
clean; nothing was deleted by this migration). They are **out of scope** for a
migration that must not invent functionality, and are recorded here as pending
product work, not migration work.

## 5. Migration strategy

**Bare-first, non-destructive.** The existing `android/` directory stays the
source of truth and is *edited in place* — it is **never regenerated** by
`npx expo prebuild`, because prebuild syncs template-managed files
(`MainApplication.kt`, `MainActivity.kt`, `AndroidManifest.xml`, Gradle files)
and would wipe the three customizations listed in §2 unless a config plugin
reproduced them byte-for-byte.

* `npx expo run:android` / `expo start --dev-client` build the **checked-in**
  `android/` project, which gains Expo Modules autolinking (settings.gradle /
  build.gradle glue from `expo-template-bare-minimum@58`) while keeping every
  Kotlin file untouched.
* A **config plugin** (`plugins/withThreatGuardNative.js`) is still authored so
  the customizations *would* survive a future prebuild (e.g. EAS cloud builds
  that regenerate the native project). Its fidelity is verified by running
  prebuild on a throw-away copy and diffing the result against `android/`.
* `eas.json` is added with development / preview / production profiles. Because
  `android/` is committed, EAS builds the checked-in native project rather than
  running prebuild, so cloud builds see exactly the same native code as local
  ones.

## 6. Behaviour changes accepted

1. `MainActivity.getMainComponentName()` becomes `"main"` and `index.js` uses
   `registerRootComponent(App)` — required by Expo's runtime; the app root,
   navigation, and all screens are untouched.
2. Activity theme becomes `Theme.App.SplashScreen` (dark `#070C16` background,
   matching the app's design system) so a splash is shown during startup; JS
   boot logic is unchanged.
3. Release builds continue to use the existing debug-keystore signing config
   exactly as before (unchanged behaviour, flagged as production debt).

## 7. Stage plan

| Stage | Content | Gate |
| --- | --- | --- |
| 0 | Toolchain bootstrap (`scripts/setup-android-toolchain.sh`), dependency + config alignment | `npm install`, `npx tsc --noEmit` |
| 1 | Expo native integration in `android/` (autolinking glue, `MainActivity`/`MainApplication`, splash, `app.json`, `eas.json`, config plugin) | `npx expo-doctor`, `./gradlew assembleDebug` |
| 2 | Verification: dev build, SQLite, native modules registered, prebuild-fidelity diff | build log + report |

## 7a. Stage 1 results

Executed and verified:

| Check | Result |
| --- | --- |
| `npm install` | 947 packages; resolved `expo 58.0.16`, `react-native 0.88.0`, `react 19.3.0` |
| `npx tsc --noEmit` | **0 errors** (198 test-globals errors were fixed by setting `compilerOptions.types` in `tsconfig.json`) |
| `npx jest` | **113/113 tests pass**, 9 suites, including the App render test under `babel-preset-expo` |
| `npx expo-doctor` | **19/20**. The single remaining check is informational: it flags that `app.json` native fields are not synced because `android/` is committed — the intended bare-first design. |

### Config-plugin fidelity (proven, not assumed)

`npx expo prebuild --platform android --no-install` was run against a
**throw-away copy** of the project (the real `android/` is never regenerated),
and the output was diffed against the hand-maintained project. Verified present
in the generated project:

* all three native package registrations in `MainApplication.kt`
  (`FileScannerPackage`, `NotificationMonitorPackage`, `AppInspectionPackage`);
* `POST_NOTIFICATIONS`;
* **all five** `<queries>` intents (MAIN/LAUNCHER, VIEW/https, SEND/text-plain,
  SENDTO/mailto, DIAL);
* the notification-listener service with `BIND_NOTIFICATION_LISTENER_SERVICE`;
* the op-sqlite `debug` build-type patch in `build.gradle`;
* the dark splash (`#070C16`) with the logo drawable intact;
* the `threatguard` deep-link intent filter on `MainActivity` (Android) and
  `CFBundleURLSchemes=threatguard` (iOS) — the expo-dev-client scheme;
* `getMainComponentName() = "main"` and `applicationId com.threatguard.mobile`;
* Expo autolinking (`expoAutolinking.useExpoModules`, `useExpoVersionCatalog`)
  resolving `expo-dev-client`, `expo-dev-launcher`, `expo-dev-menu`,
  `expo-modules-core`.

The exercise caught two defects that would otherwise have shipped silently:

1. **`<queries>` was dropped.** Prebuild emits its own `<queries>` (one
   VIEW/https intent), so an "add only if absent" guard skipped ThreatGuard's
   block entirely — package enumeration would have broken at runtime on any
   prebuild. Fixed by merging intents.
2. **The splash reverted to white.** Expo's splash generation hard-codes
   `#FFFFFF`; SDK 58 ships splash handling inside `expo` (there is no
   `expo-splash-screen` config plugin in this project). Fixed by overriding the
   colour and asserting the final value, so template drift fails loudly.

## 7b. Stage 2 results

Focus: getting the dev client actually running and the native build off the
ground.

| Check | Result |
| --- | --- |
| `npx expo start --dev-client` | Metro serves at `http://localhost:8081` (`packager-status:running`) |
| shared URI scheme warning | **gone** after the fixes below (was present on first start) |
| `npx tsc --noEmit` | **0 errors** (re-run after every change) |
| `npx jest` | **113/113 pass**, 9 suites (re-run after every change) |
| `npx expo prebuild` (sandbox, android + ios) | exit 0; all customizations + the scheme survive |

### Defects found and fixed in Stage 2

1. **No shared URI scheme.** The dev client start-up warned that the QR code /
   interstitial / terminal launch keys may not work. The scheme must be in
   **both** native projects — `expo start` intersects the iOS and Android scheme
   lists (`getOptionalDevClientSchemeAsync` → `intersecting(ios, android)`), and
   the Android half is only read from `singleTask` activities (which
   `MainActivity` is). Added `threatguard` to `app.json`, the Android intent
   filter, the iOS `Info.plist`, and the config plugin. Verified both extractors
   now return `["threatguard"]`.
2. **CRITICAL — malformed XML comment.** The comment accompanying the Android
   scheme filter contained the sequence `--dev-client`. A double hyphen is
   illegal inside an XML comment, which made **`AndroidManifest.xml`
   unparseable** — not just for Metro, but for `expo prebuild` and the Android
   build toolchain (`android:launchMode` was reported as `undefined`). Reworded
   and swept the file for other illegal sequences.
3. **Toolchain script could not install the SDK.**
   `scripts/setup-android-toolchain.sh` requested `platforms;android-37`, but
   Android 37 is published as `platforms;android-37.0`; it also detected
   "already installed" by grepping the whole `sdkmanager --list` output, which
   includes the *Installed packages* section, so nothing was ever installed.
   Both fixed; CMake now tracks the current stable (`4.1.2`), which satisfies
   the `cmake_minimum_required` of RN 0.88 and op-sqlite (3.13 / 3.9).

### Android SDK provisioning (network stalls)

The fixed package ids revealed a second, environmental problem: **long HTTPS
reads to `dl.google.com` stall without ever timing out.** `sdkmanager` sat at
30% of the NDK for 23 minutes and the Gradle wrapper died with an SSL
`Connection reset` after ~50 MiB. The transfer never failed from the server's
point of view, so no client-side timeout ever fired.

Worked around with `scripts/download-sdk-packages.sh`, which uses:

* `--speed-time 120 --speed-limit 1024` — abort a transfer that stops making
  progress (this is what `sdkmanager` and the wrapper both lack);
* `--retry 5 --retry-all-errors` — ride out transient network errors;
* `-C -` — resume the partial file instead of restarting it;
* URL resolution up front — `curl` drops the `Range` header when it follows a
  redirect, so a resumed transfer against the Gradle CDN restarted from zero
  until the final URL was resolved first.

The link is not bandwidth-capped per connection (~300 KiB/s each, ~950 KiB/s
aggregate), so the five packages download in parallel.

Two further details the script encodes:

* the archives do **not** use the package directory names — both
  `platform-37.0_r02.zip` and `build-tools_r37_linux.zip` contain a top-level
  `android-37.0/`, and the NDK archive contains `android-ndk-r27b/` — so the
  target directory and the archive's top-level name are both explicit;
* a stalled `sdkmanager` run leaves a **directory that exists but is empty**
  (`build-tools/37.0.0/` containing only `.installer/.installData`). Presence
  checks must count files, not just test `-d`, or a half-installed package
  looks installed.

The script also reproduces the Gradle wrapper's cache layout (zip + `.ok`
marker + extracted directory) so `./gradlew` uses the locally fetched
distribution instead of trying to download it again.

### Environment note

An unrelated stray Expo scaffold had been created in the **monorepo root**
(adding `expo`/`react-native` to the root manifest plus a root `android/`,
`app.json`, `tsconfig.json` and `node_modules`). It was not produced by this
migration, references no project code, and was removed; the tracked root
`package.json` and `package-lock.json` were restored unchanged.


## 7c. Full repository inspection (Phases 1, 3, 4, 6, 7 audit)

A second, independent pass over the whole repository — root, `backend/`,
`mobile/`, `docs/`, `scripts/` — was carried out after the migration, to
confirm the state of every area and to catch problems outside the Expo
migration itself.

### 1. Already migrated to Expo

| Area | State |
| --- | --- |
| `mobile/package.json` | Expo SDK 58.0.16, `expo-dev-client` 58.0.14, RN 0.88.0, React 19.3.0, `babel-preset-expo` |
| `mobile/app.json` | valid Expo config: `expo.scheme`, `expo.android.package`, `expo.ios.bundleIdentifier`, `expo.plugins` |
| `mobile/eas.json` | `development` (dev client, apk) / `preview` (apk) / `production` (aab) profiles |
| `mobile/babel.config.js` | `babel-preset-expo` only |
| `mobile/metro.config.js` | `getDefaultConfig` from `expo/metro-config` |
| `mobile/index.js` | `registerRootComponent(App)` — the Expo entry point |
| `mobile/android/` | Expo autolinking (`expoAutolinking.useExpoModules`, `useExpoVersionCatalog`), `ExpoReactHostFactory`, `ReactActivityDelegateWrapper`, `getMainComponentName() = "main"` |
| `mobile/plugins/withThreatGuardNative.js` | re-applies all four native customizations + the dev-client scheme |
| `mobile/.expo/` | present (Expo state) |

### 2. Remaining React Native CLI dependencies

**None.** The `@react-native-community/cli*` packages were removed in Stage 1
and no CLI-specific script remains. Four further dev dependencies were
superseded by their Expo equivalents and removed in this phase:
`@react-native/babel-preset`, `@react-native/metro-config`,
`@react-native/typescript-config`, `@babel/preset-env`.

Deliberately **kept**: `@react-native/eslint-config` (referenced by
`.eslintrc.js`), `react-test-renderer` (used by `__tests__/App.test.tsx`).

### 3. Unsupported Expo dependencies

None found. Every Expo-managed package in the tree was installed with
`expo install` and resolves to the SDK 58 compatible version. `npx expo-doctor`
reports **19/20**; the single remaining check is informational — it warns that
`app.json` native fields are not synced into the committed `android/`/`ios/`
directories, which is the intended bare-first design, and the config plugin
exists precisely to carry those values across a prebuild.

### 4. Native Kotlin/Java modules — method-level contract check

Every method named in the three TypeScript interfaces exists in the native
implementation, and the constants match:

| TS interface | Native source | Verified |
| --- | --- | --- |
| `src/native/FileScannerNative.ts` → `pickFile`, `computeFileHash`, `scanFile`, `cancelScan`, `clearCache`, `addListener`, `removeListeners` | `scanner/FileScannerModule.java` | all present |
| constants `MAX_FILE_SIZE`, `MAX_CONTENT_SCAN_BYTES`, `SUPPORTED_MIME_TYPES`, `ENGINE_VERSION` | same (`getConstants`) | all present |
| `src/native/AppInspectionNative.ts` → `inspectAllApps`, `inspectPackage`, `cancelInspection` | `appinspection/AppInspectionModule.kt` | all present |
| `src/native/NotificationMonitorNative.ts` → `isAccessGranted`, `isConnected`, `openNotificationSettings`, `setMonitoringEnabled`, `isMonitoringEnabled`, `getIgnoredPackages`, `setIgnoredPackages`, `getSeenSources`, `clearSeenSources`, `hasNotificationPermission`, `postThreatAlert` | `notification/NotificationMonitorModule.kt` | all 11 present |

Note: `FileScanner` is **Java**, not Kotlin (`scanner/FileScannerModule.java`,
`scanner/FileScannerPackage.java`); the other two modules are Kotlin. The
migration preserved both languages.

### 5. Database compatibility

* **Mobile** — `@op-engineering/op-sqlite` 18.2.5, unchanged. It is an
  Expo-compatible library (it ships an Android prefab and is consumed through
  the standard React Native autolinking path), so no replacement was
  necessary. The existing `debug` build-type patch in `android/build.gradle`
  is preserved, because the library publishes a `release` variant only.
* **Schema** — `src/db/schema.ts` (`SCHEMA_VERSION = 1`) creates `scans`,
  `alerts`, `settings` and 8 indexes plus 2 update triggers. Migrations are
  applied by `src/db/service.ts` from the same `MIGRATIONS` array. **Nothing was
  reset or deleted**; the existing `threatguard.db` and its rows are intact.
* **Backend** — a separate database (`backend/src/database/`), untouched. It
  uses Node's built-in `node:sqlite` for SQLite and `pg` for PostgreSQL behind
  one `Database` interface, with a single inline migration `001_init`. The two
  schemas are deliberately parallel but independent: `scan_history` ↔ `scans`,
  `threat_alerts` ↔ `alerts`. The mobile app never writes to the backend
  database.

### 6. Duplicate configurations

None inside `mobile/`. The root `package.json` is **not** an npm-workspaces
root (it has no `workspaces` key and delegates with `npm --prefix`); its
`package-lock.json` contains no dependencies, so it is a manifest pin rather
than a duplicate lockfile.

### 7. Broken or incomplete implementations

These were found by this inspection and have been fixed, except where noted.

| # | Finding | Status |
| --- | --- | --- |
| 1 | **The mobile API client and the backend did not agree on the wire format.** The client called `/api/v1/scan/url` and `/api/v1/scan/file` (the backend serves `/api/v1/scans/…`), sent `{ hash }` where the backend validates `sha256`, expected `GET /health` where the backend serves `GET /api/v1/health`, used port 3000 while the backend defaults to 8000, and expected a camelCase body where the backend emits snake_case. **Every reputation call from the app would have failed.** | **fixed** — the client now speaks the backend's contract and owns the snake_case → camelCase mapping; `__tests__/apiClient.test.ts` pins it |
| 2 | `backend/.env.example` documents `npm run --silent gen:key`, but no such script existed. | **fixed** — `backend/scripts/gen-key.js` added |
| 3 | `mobile/src/api/local-config.ts` (the file holding the dev API key) is documented as git-ignored, but no ignore rule matched it. | **fixed** — rule added to `mobile/.gitignore` |
| 4 | `backend/.env.example` sets `INTEL_CACHE_TTL_SECONDS`, which the schema declares but no code reads (the real TTLs are constants in `utils/cache.ts`). | open — harmless, but it misleads an operator into thinking the value has an effect |
| 5 | `pino-http` is a backend dependency that is never imported. | open — removal deferred so it is not mixed with functional changes |
| 6 | `README.md` links to `docs/api/README.md`, `docs/database/README.md` and `docs/security/README.md`, none of which exist. | **fixed** — links updated to the documents that do exist |
| 7 | Security Tools, Device Security Audit and `DeviceSecurityModule.kt` are named in the original brief but are **absent from the repository**. | not built — reported as missing, per instruction |

### 8. Files that can be safely removed after verification

Verified by checking the actual dependency graph and references, not by name:

* `mobile/@react-native/babel-preset`, `@react-native/metro-config`,
  `@react-native/typescript-config`, `@babel/preset-env` — removed (above).
* `mobile/index.js` — **must be kept.** It is the Expo entry point
  (`registerRootComponent`); removing it would break the app.
* `mobile/react-native.config.js` — already absent.
* `mobile/metro.config.js`, `mobile/babel.config.js` — **must be kept**, but
  they are now Expo-managed rather than RN CLI ones. There is no duplicate
  Babel/Metro configuration in the tree.
* `mobile/android/` and `mobile/ios/` — **must be kept.** The Android project
  carries the hand-written native modules, the manifest declarations and the
  Gradle customisations.
* `mobile/Gemfile`, `mobile/.watchmanconfig` — kept: the Gemfile is the
  standard Expo/RN iOS dependency entry point, and `.watchmanconfig` is
  still used by Metro on Linux.

---

## 8. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| RN 0.87 → 0.88 behavioural change | Single minor bump, all `@react-native/*` packages moved in lockstep; the upstream templates for 0.87.1 and 0.88.0 are file-identical except for the version, so native surface is unchanged. |
| op-sqlite prefab vs debug variant | Existing `subprojects` patch in `android/build.gradle` is preserved verbatim. |
| Prebuild wiping native code | Prebuild is never run against the real tree; config plugin verified on a sandbox copy. |
| No physical device attached to the dev machine | Debug APK is built locally; on-device verification is performed with `adb install` on a connected device and recorded as a separate checklist. |
| No Expo SDK for RN 0.87 | Resolved by moving to SDK 58 / RN 0.88.0 (see §3). |
| Release builds are signed with the debug keystore | **Pre-existing, carried over unchanged.** `android/app/build.gradle` still does `release { signingConfig signingConfigs.debug }`, exactly as the upstream RN template ships it (with the template's own "generate your own keystore" warning). The migration neither introduced nor resolved this; a production keystore must be configured before any store submission. |
