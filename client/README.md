# CyberShield client

Flutter GUI for the CyberShield detection API — scan device folders, files,
APKs, URLs, email and pasted text, then read verdicts, history, quarantine,
threat-intelligence reports and an installed-apps list. Targets Android, iOS,
Windows, Linux and macOS.

## Screens

Navigation is slightly different on desktop and mobile. Wide windows get an
antivirus-style `NavigationRail` with a brand header and every section; on
phones a 5-item bottom bar (Status, Scan, History, Quarantine, More) keeps the
secondary sections (Threat Intel, Apps, Profile) behind a **More** sheet so the
bar never crowds a small display.

- **Status** — an AV-style Security Center: a shield status hero with the
  engine state, big scan actions, a grid of scan shortcuts, metrics, verdict
  distribution, a 30-day activity chart and a static-analysis-only note.
- **Scan** — tabs: **Device** (default), URL, Email, Text, File, APK.
  - The Device tab scans a *folder you pick* (or a multi-selected set of files)
    file by file through the static-analysis API. It is honest by design: only
    the folder you grant is read, files over the upload limit are skipped, and
    the batch is paced to the backend's file-scan rate limit (10/min default;
    a `429` stops it with a clear message).
- **History / Quarantine / Threat Intel** — scan records, quarantined copies
  and third-party threat-intelligence output.
- **Apps** — informational installed-apps list (**Android only**): package
  name, version and *declared* permissions from the package manager. Nothing
  is read at runtime and nothing is uploaded. Other platforms show an honest
  "not available" card.
- **Profile** — account card, password/API-key management, admin users and
  (from the Profile page and the Status page) the sign-in sheet.

## Authentication

This build has **no login screen** — the app boots straight to the shell with
a splash, and authentication lives in an in-app **sign-in bottom sheet**
(`lib/features/auth/sign_in_sheet.dart`). The Status page shows a first-run
"Sign in to store scans" prompt whenever no session is stored; Profile offers
the same sheet.

- Supported modes: account **credentials** (`POST /api/v1/auth/login`, JWT with
  refresh rotation) or an **API key** (`X-API-Key`).
- Remembered sessions persist via `flutter_secure_storage`, so a signed-in
  device starts signed in. Until a session is started, API calls return `401`
  and the UI shows the sign-in prompt instead of pretending otherwise.

## API base URL

The client talks to the backend's REST API. The base URL is compiled in at
build time and **defaults to `http://localhost:8000`** (`lib/core/config.dart`).
Override it for any other host with a Dart define:

```sh
flutter run -d linux --dart-define=API_BASE_URL=http://10.0.0.5:8000
```

- Running the app on the **same machine** as the backend: the default works.
- **Android emulator / phone / another computer**: use the backend host's LAN/Wi‑Fi
  IP, e.g. `http://<host-ip>:8000`. The backend must be listening on that
  interface (uvicorn: `--host 0.0.0.0`).

## Run on Linux desktop

The `flutter_secure_storage` plugin needs the `libsecret-1` development files:

```sh
sudo apt install libsecret-1-dev   # Debian/Ubuntu
flutter run -d linux
```

`tool/run_linux.sh` is a wrapper for machines where that package is missing,
root is unavailable, or the display is a virtual one. It downloads and extracts
the dev package into a user-local tree when needed, silences an upstream
`json.hpp` `-Werror` deprecation in the same plugin, and forces the stable
Skia + Mesa software-rendering combo (Impeller disabled) for reliable rendering
on virtual displays:

```sh
API_BASE_URL=http://<host-ip>:8000 ./tool/run_linux.sh   # optional override
```

Only the compile-time include/link workarounds touch your machine; no project
source is modified.

## Other platforms

```sh
flutter run -d windows   # Windows desktop
flutter run -d macos     # macOS desktop (GPG/notarization not handled here)
flutter run              # with a connected Android device or emulator
flutter build apk        # Android release artifact
```

## Accounts

Accounts are created through the API (no self-registration, but this build's
in-app sign-in sheet accepts any existing account — see **Authentication**
above). For local development the backend ships `scripts/seed_dev.py`:

```sh
cd ../backend
../.venv/bin/python -m scripts.seed_dev
```

It creates `admin@cybershield.dev` (administrator) and
`analyst@cybershield.dev`, with fixed, clearly-marked dev-only passwords that
are printed by the script. Sign in with those credentials in the app's sign-in
sheet and the session is remembered on the device.

## Verify

```sh
flutter analyze   # zero issues
flutter test      # widget + integration-style tests (root gate, envelope decoding)
```

Verdict colors/score-band labels, the `{"error": {...}}` error envelope (never
raw JSON), `Retry-After` handling on 429, the shell-first boot paths
(unauthenticated → shell, authenticated → shell), the Sign-in sheet
credentials/API-key switching, and the first-run sign-in prompt on the Status
page are covered by the test suite.# Cyber-Shield
