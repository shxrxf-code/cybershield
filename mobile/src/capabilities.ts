/**
 * Which on-device capabilities are actually available in this build.
 *
 * Mobile ThreatGuard is assembled in phases. Each native capability — the
 * device scanning engine, file access, installed-app inspection and the
 * notification listener — is wired up in a phase. Screens read these flags so
 * they never offer an action that cannot yet produce a real result: a control
 * that is not backed by an implementation is shown as unavailable, never as a
 * working button that silently does nothing.
 *
 * When a capability lands, flip its flag here and the corresponding screen
 * enables its real path.
 */

export interface Capabilities {
  /** Enumerating the whole device (installed apps and shared storage). Not implemented. */
  deviceScan: boolean;
  /** Scanning a user-selected file with the on-device engine (SAF + SHA-256 + signatures). */
  fileScan: boolean;
  /** Enumerating installed apps and their permissions (Phase 5). */
  appScan: boolean;
  /** The Android notification listener service (Phase 6). */
  notificationListener: boolean;
  /** Backend reputation lookups: Google Safe Browsing / URLhaus / VirusTotal (Phase 4). */
  urlReputation: boolean;
}

/**
 * Capability flags. Each flag is only true when the backing implementation
 * actually exists in this build, so screens never offer an action that cannot
 * produce a real result.
 */
export const capabilities: Capabilities = {
  deviceScan: false,     // Full-device enumeration not implemented yet
  fileScan: true,        // On-device FileScanner engine (SAF + SHA-256 + signatures)
  appScan: false,        // Not yet implemented
  notificationListener: true, // Android NotificationListenerService + on-device scam analyser
  urlReputation: true,   // Backend reputation API is available
};
