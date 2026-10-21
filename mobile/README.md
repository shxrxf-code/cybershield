# Mobile ThreatGuard — mobile app

The Android client of **Mobile ThreatGuard**: a privacy-first, permission-based
security app that inspects URLs, files and the notification text Android
actually exposes.

The app is an **Expo** application (Expo SDK 58, React Native 0.88, React 19.3,
TypeScript) built as a *bare* project: the `android/` directory is committed and
is the source of truth, because the app ships hand-written native modules that
a managed workflow cannot generate.

---

## Requirements

* Node 20+
* JDK 17 and the Android SDK (see `../scripts/setup-android-toolchain.sh`)
* An Android device or emulator running API 24+

On a machine where the toolchain is not on the default `PATH`:

```bash
source ../scripts/dev-env.sh
```

## Running the app

This app uses **custom native modules** — a file scanner, a
`NotificationListenerService` monitor and a `PackageManager` app inspector.
They are compiled into the app, so **Expo Go cannot run it**; a development
build is required.

```bash
npm install
npx expo run:android          # build, install and launch
```

`npx expo run:android` builds the debug APK, installs it on the connected
device or emulator and starts Metro. If the build is already installed and only
the JavaScript needs reloading:

```bash
npx expo start --dev-client
```

The dev client is reached over the `threatguard://` scheme.

## Backend

In development the app calls the backend at `http://10.0.2.2:8000`
(`10.0.2.2` is the emulator's alias for the host machine). For a physical
device, forward the port:

```bash
adb reverse tcp:8000 tcp:8000
```

The backend API key is read from `src/api/local-config.ts` (git-ignored; copy
`src/api/local-config.example.ts`) or from `THREATGUARD_API_KEY`. Generate a
key with `npm run --silent gen:key` in `../backend`.

Third-party intelligence keys (Google Safe Browsing, URLhaus, VirusTotal) are
**never** present in this app — they live only on the backend.

## Scripts

| Script | Purpose |
| --- | --- |
| `npm start` | `expo start --dev-client` — Metro with the dev launcher |
| `npm run android` | `expo run:android` — build, install and launch |
| `npm run ios` | `expo run:ios` |
| `npm run prebuild` | `expo prebuild` — regenerate the native projects |
| `npm test` | Jest |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run lint` | ESLint |
| `npm run format` | Prettier |

## Layout

| Path | Contents |
| --- | --- |
| `App.tsx` | Root component, providers, navigation host |
| `src/screens/` | The 16 application screens |
| `src/components/` | UI primitives and the theme-aware components |
| `src/native/` | Typed interfaces for the three native modules |
| `src/db/` | op-sqlite schema, migrations and repositories |
| `src/api/` | Backend client and configuration |
| `src/store/` | Zustand stores (scans, alerts, settings) |
| `src/theme/` | Design tokens and the theme provider |
| `android/app/src/main/java/` | The native modules (Java + Kotlin) |
| `plugins/` | Expo config plugin preserving the native customisations |

## Native customisations

Four things in `android/` are hand-written and would be lost by a
`npx expo prebuild`. `plugins/withThreatGuardNative.js` re-applies all of them
(and the dev-client deep-link scheme), so a regenerated project stays
equivalent:

1. the three native package registrations in `MainApplication.kt`;
2. the `AndroidManifest.xml` declarations — `POST_NOTIFICATIONS`, the Android
   11+ `<queries>` block, and the notification-listener service;
3. the op-sqlite `debug` build-type patch in `build.gradle`;
4. the dark splash screen theme.

The plugin has been verified against a real `expo prebuild` of both platforms.
