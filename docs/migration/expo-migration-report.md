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

## 8. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| RN 0.87 → 0.88 behavioural change | Single minor bump, all `@react-native/*` packages moved in lockstep; the upstream templates for 0.87.1 and 0.88.0 are file-identical except for the version, so native surface is unchanged. |
| op-sqlite prefab vs debug variant | Existing `subprojects` patch in `android/build.gradle` is preserved verbatim. |
| Prebuild wiping native code | Prebuild is never run against the real tree; config plugin verified on a sandbox copy. |
| No physical device attached to the dev machine | Debug APK is built locally; on-device verification is performed with `adb install` on a connected device and recorded as a separate checklist. |
| No Expo SDK for RN 0.87 | Resolved by moving to SDK 58 / RN 0.88.0 (see §3). |
