/**
 * Device-side domain model.
 *
 * These types mirror the backend's wire contract but use idiomatic camelCase.
 * The API client is responsible for translating snake_case responses into these
 * shapes, so the rest of the app never sees transport details.
 */

export type VerdictStatus = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ThreatCategory =
  | 'phishing'
  | 'malware'
  | 'scam'
  | 'spam'
  | 'suspicious'
  | 'unwanted-software'
  | 'social-engineering'
  | 'none'
  | 'unknown';

export type AnalysisSource =
  | 'local-url-heuristics'
  | 'local-text-heuristics'
  | 'local-file-analysis'
  | 'local-document-analysis'
  | 'local-apk-analysis'
  | 'local-signature'
  | 'google-safe-browsing'
  | 'urlhaus'
  | 'virustotal';

export type ScanType = 'quick' | 'full' | 'url' | 'file' | 'apk' | 'notification' | 'scheduled';

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface DetectionReason {
  code: string;
  message: string;
  severity: Severity;
}

export interface DetectionSourceResult {
  source: AnalysisSource | string;
  label: string;
  status: VerdictStatus;
  detail?: string;
  categories?: ThreatCategory[];
  error?: string;
}

/** A merged verdict as presented to the user. */
export interface Verdict {
  status: VerdictStatus;
  severity: Severity;
  category: ThreatCategory;
  /** 0–100 confidence/severity score derived from reason weights. */
  score: number;
  /** True when at least one authoritative source gave a definitive answer. */
  definitive: boolean;
  recommendedAction: string;
  reasons: DetectionReason[];
  sources: DetectionSourceResult[];
}

export interface ThreatAlert {
  id: string;
  threatType: string;
  severity: Severity;
  category?: ThreatCategory;
  sourceApplication?: string;
  detectionReason: string;
  target?: string;
  recommendedAction?: string;
  isRead: boolean;
  scannedAt: string;
  createdAt: string;
  readAt?: string;
}

export interface ScanRecord {
  id: string;
  scanType: ScanType;
  target?: string;
  fileName?: string;
  fileHash?: string;
  fileSize?: number;
  scanStatus: ScanStatus;
  threatLevel: VerdictStatus;
  threatType?: string;
  detectionReason?: string;
  filesChecked: number;
  threatsFound: number;
  durationMs: number;
  source: string;
  scannedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface DashboardTotals {
  totalScans: number;
  totalThreats: number;
  unreadAlerts: number;
  alertsBySeverity: Partial<Record<Severity, number>>;
}

export interface DashboardSummary {
  totals: DashboardTotals;
  lastScanAt?: string;
  recentScans: ScanRecord[];
  recentAlerts: ThreatAlert[];
}

export interface PrivacyPreferences {
  /** Collect anonymous usage analytics. */
  analytics: boolean;
  /** Send crash reports. */
  crashReporting: boolean;
  /** Share anonymized threat data to improve detection. */
  shareThreatData: boolean;
}

export interface SecuritySettings {
  notificationMonitoring: boolean;
  backgroundProtection: boolean;
  alertNotifications: boolean;
  /** Packages the user asked us not to analyse (per-app monitoring toggles). */
  notificationIgnoredPackages: string[];
  privacyPreferences: PrivacyPreferences;
  updatedAt?: string;
}

/** A URL scan request/result as the device models it. */
export interface UrlScanResult {
  scanId: string;
  url: string;
  domain: string;
  protocol: string;
  cached: boolean;
  durationMs: number;
  scannedAt: string;
  duplicateAlert: boolean;
  alert: ThreatAlert | null;
  verdict: Verdict;
}

export interface FileScanResult {
  scanId: string;
  sha256: string;
  fileName?: string;
  durationMs: number;
  scannedAt: string;
  duplicateAlert: boolean;
  alert: ThreatAlert | null;
  verdict: Verdict;
}

export interface NotificationScanResult {
  scanId: string;
  sourceApp?: string;
  packageName?: string;
  textScore: number;
  matchedSignals: string[];
  privacyNote: string;
  durationMs: number;
  duplicateAlert: boolean;
  alert: ThreatAlert | null;
  urls: Array<{ url: string; domain: string; status: VerdictStatus; severity: Severity }>;
  verdict: Verdict;
}
