/**
 * Presentation and verdict helpers for the on-device file scanner.
 *
 * The single most important rule lives here: a purely local scan can never
 * declare a file *safe*. Local checks can prove that a known-bad signature
 * matched; their silence proves nothing. Only an authoritative reputation
 * lookup may lift a file to SAFE.
 */

import type { ThreatTone } from '../theme/theme';
import type { VerdictStatus } from './types';
import type { FindingSeverity, NativeScanStatus, ScanFinding } from '../native/FileScannerNative';

/** Where the reputation lookup got to for a given scan. */
export type ReputationState = 'checked' | 'unavailable' | 'skipped';

/**
 * Translate the native engine's local status into an app-level verdict.
 *
 * `clean` and `error` both map to UNKNOWN: the engine saw no known signature,
 * which is not the same as the file being known-good. This is why the UI never
 * shows "Safe" for a file that only passed a local heuristic check.
 */
export function localStatusToVerdict(status: NativeScanStatus): VerdictStatus {
  switch (status) {
    case 'threat':
      return 'MALICIOUS';
    case 'suspicious':
      return 'SUSPICIOUS';
    default:
      return 'UNKNOWN';
  }
}

/**
 * Combine the local verdict with the reputation service's.
 *
 * A concrete local finding (suspicious or malicious) always stands. Otherwise
 * the authoritative service decides — including when it says SAFE, which the
 * local engine is not allowed to say on its own.
 */
export function mergeVerdict(
  local: VerdictStatus,
  reputation: ReputationState,
  remote?: VerdictStatus,
): VerdictStatus {
  if (reputation !== 'checked' || !remote) {
    return local;
  }
  if (local === 'MALICIOUS' || local === 'SUSPICIOUS') {
    return local;
  }
  return remote;
}

const FINDING_LABELS: Record<string, string> = {
  EICAR_TEST_FILE: 'EICAR anti-malware test signature',
  PDF_JAVASCRIPT: 'Embedded JavaScript',
  PDF_EMBEDDED_FILES: 'Embedded files',
  PDF_LAUNCH_ACTION: 'Launch action',
  PDF_OPENACTION: 'Automatic open action',
  PDF_AUTO_ACTION: 'Automatic actions',
  EXTENSION_CONTENT_MISMATCH: 'Contents do not match the extension',
  APK_MISSING_MANIFEST: 'Missing AndroidManifest.xml',
  APK_MISSING_DEX: 'No DEX bytecode',
  APK_PATH_TRAVERSAL: 'Unsafe archive entry',
  APK_UNREADABLE: 'Archive could not be read',
  EMPTY_FILE: 'Empty file',
  UNRECOGNISED_TYPE: 'Unrecognised file type',
};

export function findingLabel(finding: ScanFinding): string {
  return FINDING_LABELS[finding.code] ?? finding.message;
}

export function findingTone(severity: FindingSeverity): ThreatTone {
  switch (severity) {
    case 'high':
      return 'malicious';
    case 'medium':
      return 'suspicious';
    case 'low':
      return 'info';
    default:
      return 'unknown';
  }
}

/**
 * The tone for the native engine's status badge. `clean` is deliberately NOT
 * green: "no known signature" is a neutral result, not a clean bill of health.
 */
export function scanStatusTone(status: NativeScanStatus): ThreatTone {
  switch (status) {
    case 'threat':
      return 'malicious';
    case 'suspicious':
      return 'suspicious';
    case 'error':
      return 'info';
    default:
      return 'unknown';
  }
}

const SCAN_STATUS_LABELS: Record<NativeScanStatus, string> = {
  clean: 'No known signatures',
  suspicious: 'Suspicious',
  threat: 'Threat detected',
  error: 'Could not scan',
};

export function scanStatusLabel(status: NativeScanStatus): string {
  return SCAN_STATUS_LABELS[status];
}

export function reputationLabel(state: ReputationState): string {
  switch (state) {
    case 'checked':
      return 'Reputation checked';
    case 'unavailable':
      return 'Reputation service unavailable';
    default:
      return 'Reputation check off';
  }
}

export function reputationTone(state: ReputationState): ThreatTone {
  switch (state) {
    case 'checked':
      return 'info';
    case 'unavailable':
      return 'suspicious';
    default:
      return 'unknown';
  }
}
