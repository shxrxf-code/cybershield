/**
 * API configuration. The dev values point at a local backend (reachable via
 * `adb reverse tcp:3000 tcp:3000` when the emulator/device is attached).
 *
 * In a production build the `DEFAULT_API_KEY` would be injected at build time
 * (e.g. via `process.env` in Metro or a Gradle `resValue`). It is intentionally
 * not committed to source control — see `.gitignore` for the local override
 * pattern.
 */

// Local dev backend URL. When the app runs on an Android emulator, `10.0.2.2`
// reaches the host machine. On a physical device you must run `adb reverse
// tcp:3000 tcp:3000` and keep the default.
export const API_BASE_URL = __DEV__
  ? 'http://10.0.2.2:3000'
  : 'https://api.threatguard.example'; // replace with real prod endpoint

/**
 * Client API key for the ThreatGuard backend. This is NOT a third-party secret
 * (Google Safe Browsing, URLhaus, VirusTotal keys never leave the server).
 *
 * For local development you can create a file at `mobile/src/api/local-config.ts`
 * exporting a `DEV_API_KEY` constant, or set it via an env var in Metro.
 * The file is git-ignored.
 */
let apiKey: string | undefined;

try {
  const local = require('./local-config');
  apiKey = local.DEV_API_KEY;
} catch {
  // no local override
}

// In Metro, process.env is not available; use globalThis
const envApiKey = (globalThis as unknown as { process?: { env?: Record<string, string> } }).process?.env?.THREATGUARD_API_KEY;

export const DEFAULT_API_KEY = apiKey ?? envApiKey ?? 'dev-key-change-me';