# File-scanning engine — device test plan

This is the manual acceptance test for the on-device file-scanning engine
(`mobile/android/app/src/main/java/com/threatguard/mobile/scanner/`). It is the
counterpart to the automated unit tests (`npx jest` in `mobile/`) and must be run
on a **physical Android device** before the feature is considered done.

## 1. Build, install and prepare the device

```bash
# 1. Toolchain (JAVA_HOME + ANDROID_HOME for this machine)
source scripts/dev-env.sh

# 2. Build and install the development build.
#    The app has custom native modules, so it CANNOT run in Expo Go:
#    `npx expo run:android` builds a development build that contains them.
cd mobile
npx expo run:android
cd -

# 2b. To build the APK without installing it:
cd mobile/android && ./gradlew :app:assembleDebug && cd -

# 3. Install on the connected device
adb install -r mobile/android/app/build/outputs/apk/debug/app-debug.apk

# 4. Generate the fixtures and push them to the device
scripts/make-scan-fixtures.sh /tmp/threatguard-fixtures
adb push /tmp/threatguard-fixtures /sdcard/Download/threatguard-fixtures
```

The fixtures live in `Download/threatguard-fixtures` and are picked with the
system document picker inside **File Scanner** (single file) and **Full Scan**
(multiple files).

> The picker is the Storage Access Framework. It needs **no** runtime storage
> permission, and ThreatGuard never enumerates the whole device or another app's
> private storage.

### Reputation lookup (optional tests)

The hash reputation lookup goes through the backend. Start it and forward the
port so a physical device can reach it:

```bash
source scripts/dev-env.sh
npm run backend:dev                 # terminal 1
adb reverse tcp:8000 tcp:8000       # terminal 2
```

In the app, enable **Settings → Privacy → Share threat data**, or use the toggle
on the File Scanner screen. With it off, no hash ever leaves the device.

To test the "service unavailable" path, keep the toggle on but **stop the
backend** (Ctrl-C) before scanning.

## 2. Expected results

| # | Fixture | Steps | Expected result |
|---|---------|-------|-----------------|
| 1 | `valid.pdf` | File Scanner → pick → Scan | Scans to completion, SHA-256 shown, local result **No known signatures**, verdict **Unverified** (`UNKNOWN`), no findings |
| 2 | `valid.png` | Same | Same as #1 (no findings) |
| 3 | `valid.apk` | Same | Same as #1 — a structurally valid package raises no finding |
| 4 | `unsupported.xyz` | Same | **No crash**. Informational note "Unrecognised file type…", verdict **Unverified**. Never reported as malware |
| 5 | `empty.bin` | Same | **No crash**, "Empty file (0 bytes)" note, SHA-256 = `e3b0c442…`, verdict **Unverified** |
| 6 | `corrupted.pdf` | Same | **No crash**. Header looks like a PDF; no signatures match. Verdict **Unverified** |
| 7 | `mismatch.jpg` | Same | PNG bytes named `.jpg` → low-severity finding "contents do not match the extension", verdict **Suspicious** (never **Malicious**) |
| 8 | `pdf-with-js.pdf` | Same | Medium finding "Embedded JavaScript" (+ possibly "/OpenAction"), verdict **Suspicious**, **not** Malicious |
| 9 | `eicar.txt` | Same | High finding "EICAR anti-malware test signature", verdict **Malicious** |
| 10 | `oversized.bin` (optional) | `head -c 115000000 /dev/urandom > /tmp/threatguard-fixtures/oversized.bin`, push, pick | Rejected with "larger than the scan limit" — the app must not hang or OOM |
| 11 | Picker dismissal | File Scanner → Choose file → press **Back** | No error banner; the screen returns to its previous state (a dismissal is not an error) |
| 12 | Reputation unavailable | Enable the toggle, stop the backend, scan `valid.pdf` | Badge "Reputation service unavailable", verdict stays **Unverified** — never **Safe** |
| 13 | Reputation success | Backend running + `adb reverse`, toggle on, scan a file whose hash the backend knows | Badge "Reputation checked", verdict comes from the backend |
| 14 | Multiple files | Full Scan → Choose files → select #1–#9 → Scan | Each file scanned in turn with a "file N of M" progress label; the summary shows the correct count needing attention |
| 15 | Cancellation | Start a scan of `oversized.bin` (or a large file), tap **Cancel** | Scan stops promptly, no crash, no result card |
| 16 | Permission state | Permissions screen | "Files and media" says it is **not required** — the picker grants access per document |

## 3. SHA-256 correctness

The engine hashes the bytes exactly as they are on disk. Two reference values
let you confirm it end-to-end:

```bash
# Empty file — the canonical SHA-256 of zero bytes
printf '' | sha256sum
# -> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

1. Scan `empty.bin`; the SHA-256 row must read
   `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
2. For any fixture, compare the app's SHA-256 with `sha256sum <file>` on the
   host. They must match character for character (lower-case hex, 64 chars).

## 4. Packaging check (no device needed)

Confirm the engine really shipped inside the APK:

```bash
APK=mobile/android/app/build/outputs/apk/debug/app-debug.apk
for d in $(unzip -Z1 "$APK" 'classes*.dex'); do
  unzip -p "$APK" "$d" | strings | grep -o "Lcom/threatguard/mobile/scanner/[A-Za-z]*"
done | sort -u
# FileScanner, FileScannerModule, FileScannerPackage,
# HashScanner, ScanCancelledException, ScanResult, SignatureScanner
```

## 5. What the engine deliberately does not do

- It does **not** scan the whole device or other apps' private storage.
- It does **not** execute, open, modify or upload the file it inspects.
- It does **not** declare a file **Safe** on a local-only result — a clean local
  scan is **Unverified**. Only the reputation service can confirm safety.
- It does **not** treat an unusual extension or MIME type as malware; a mismatch
  is a low-severity finding at most.
