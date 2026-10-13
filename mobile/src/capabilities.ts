/**
 * Which on-device capabilities are actually available in this build.
 *
 * Mobile ThreatGuard is assembled in phases. Each native capability — the
 * device scanning engine, file access, installed-app inspection and the
 * notification listener — is wired up in a later phase. Screens read these
 * flags so they never offer an action that cannot yet produce a real result:
 * a control that is not backed by an implementation is shown as unavailable,
 * never as a working button that silently does nothing.
 *
 * When a capability lands, flip its flag here and the corresponding screen
 * enables its real path.
 */

export interface Capabilities {
  /** On-device quick/full scanning of apps and files (Phase 5 / 8). */
  deviceScan: boolean;
  /** Picking a file and hashing it on-device, then a reputation lookup (Phase 5). */
  fileScan: boolean;
  /** Enumerating installed apps and their permissions (Phase 5). */
  appScan: boolean;
  /** The Android notification listener service (Phase 6). */
  notificationListener: boolean;
  /** Backend reputation lookups: Google Safe Browsing / URLhaus / VirusTotal (Phase 4). */
  urlReputation: boolean;
}

/**
 * All flags are false in the current build: only the design system, navigation
 * and the local data model exist. This is the single place that changes as the
 * remaining phases are implemented.
 */
export const capabilities: Capabilities = {
  deviceScan: false,
  fileScan: false,
  appScan: false,
  notificationListener: false,
  urlReputation: false,
};
