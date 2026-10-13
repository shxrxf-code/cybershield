import type { SourceResult, MergedVerdict } from '../domain/verdict';
import type { ScanHistoryRecord } from '../database/repositories/scan-repository';
import type { ThreatAlertRecord } from '../database/repositories/alert-repository';
import type { UrlScanOutcome } from '../services/url-reputation.service';
import type { FileScanOutcome } from '../services/file-analysis.service';
import type { NotificationAnalysisOutcome } from '../services/notification-analysis.service';
import type { RecordedScan } from '../services/scan-history.service';
import { recommendedAction } from '../services/url-reputation.service';

/**
 * Convert internal records into the stable JSON shapes the mobile client
 * consumes. Keeping this in one place means the wire format is defined once.
 */

const SOURCE_LABELS: Record<string, string> = {
  'local-url-heuristics': 'On-device URL checks',
  'local-text-heuristics': 'On-device message checks',
  'local-file-analysis': 'On-device file checks',
  'local-document-analysis': 'On-device document checks',
  'local-apk-analysis': 'On-device app checks',
  'local-signature': 'Local threat signatures',
  'google-safe-browsing': 'Google Safe Browsing',
  urlhaus: 'URLhaus',
  virustotal: 'VirusTotal',
};

export interface SourceDto {
  source: string;
  label: string;
  status: SourceResult['status'];
  detail?: string;
  categories?: string[];
  /** Present only when the source could not answer. */
  error?: string;
}

export interface ReasonDto {
  code: string;
  message: string;
  severity: string;
}

export interface AlertSummaryDto {
  id: string;
  threat_type: string;
  severity: string;
  detection_reason: string;
  recommended_action?: string;
}

export interface VerdictDto {
  status: MergedVerdict['status'];
  severity: MergedVerdict['severity'];
  category: MergedVerdict['category'];
  score: number;
  definitive: boolean;
  recommended_action: string;
  reasons: ReasonDto[];
  detection_sources: SourceDto[];
}

export function presentVerdict(verdict: MergedVerdict): VerdictDto {
  return {
    status: verdict.status,
    severity: verdict.severity,
    category: verdict.category,
    score: verdict.score,
    definitive: verdict.definitive,
    recommended_action: recommendedAction(verdict.status),
    reasons: verdict.reasons.map((reason) => ({
      code: reason.code,
      message: reason.message,
      severity: reason.severity,
    })),
    detection_sources: verdict.sources.map((source) => ({
      source: source.source,
      label: SOURCE_LABELS[source.source] ?? source.source,
      status: source.status,
      ...(source.detail ? { detail: source.detail } : {}),
      ...(source.categories ? { categories: source.categories } : {}),
      ...(source.error ? { error: source.error } : {}),
    })),
  };
}

export function presentAlert(alert: ThreatAlertRecord | undefined): AlertSummaryDto | null {
  if (!alert) return null;
  return {
    id: alert.id,
    threat_type: alert.threatType,
    severity: alert.severity,
    detection_reason: alert.detectionReason,
    ...(alert.recommendedAction ? { recommended_action: alert.recommendedAction } : {}),
  };
}

export interface UrlScanDto {
  scan_id: string;
  url: string;
  domain: string;
  protocol: string;
  cached: boolean;
  duration_ms: number;
  scanned_at: string;
  duplicate_alert: boolean;
  alert: AlertSummaryDto | null;
  verdict: VerdictDto;
}

export function presentUrlScan(outcome: UrlScanOutcome, recorded: RecordedScan): UrlScanDto {
  return {
    scan_id: recorded.scan.id,
    url: outcome.normalized.original,
    domain: outcome.normalized.domain,
    protocol: outcome.normalized.protocol,
    cached: outcome.cached,
    duration_ms: outcome.durationMs,
    scanned_at: outcome.scannedAt,
    duplicate_alert: recorded.duplicateAlert,
    alert: presentAlert(recorded.alert),
    verdict: presentVerdict(outcome.verdict),
  };
}

export interface FileScanDto {
  scan_id: string;
  sha256: string;
  file_name?: string;
  duration_ms: number;
  scanned_at: string;
  duplicate_alert: boolean;
  alert: AlertSummaryDto | null;
  verdict: VerdictDto;
}

export function presentFileScan(
  outcome: FileScanOutcome,
  recorded: RecordedScan,
  meta: { fileName?: string },
): FileScanDto {
  return {
    scan_id: recorded.scan.id,
    sha256: outcome.sha256,
    ...(meta.fileName ? { file_name: meta.fileName } : {}),
    duration_ms: outcome.durationMs,
    scanned_at: outcome.scannedAt,
    duplicate_alert: recorded.duplicateAlert,
    alert: presentAlert(recorded.alert),
    verdict: presentVerdict(outcome.verdict),
  };
}

export interface NotificationScanDto {
  scan_id: string;
  source_app?: string;
  package_name?: string;
  text_score: number;
  matched_signals: string[];
  privacy_note: string;
  duration_ms: number;
  duplicate_alert: boolean;
  alert: AlertSummaryDto | null;
  urls: Array<{ url: string; domain: string; status: string; severity: string }>;
  verdict: VerdictDto;
}

export function presentNotificationScan(
  outcome: NotificationAnalysisOutcome,
  recorded: RecordedScan,
  meta: { sourceApp?: string; packageName?: string },
): NotificationScanDto {
  return {
    scan_id: recorded.scan.id,
    ...(meta.sourceApp ? { source_app: meta.sourceApp } : {}),
    ...(meta.packageName ? { package_name: meta.packageName } : {}),
    text_score: outcome.textScore,
    matched_signals: outcome.matchedSignals,
    privacy_note: outcome.privacyNote,
    duration_ms: outcome.durationMs,
    duplicate_alert: recorded.duplicateAlert,
    alert: presentAlert(recorded.alert),
    urls: outcome.urls.map((url) => ({
      url: url.normalized.canonical,
      domain: url.normalized.domain,
      status: url.verdict.status,
      severity: url.verdict.severity,
    })),
    verdict: presentVerdict(outcome.verdict),
  };
}

export interface ScanRecordDto {
  id: string;
  scan_type: string;
  target?: string;
  file_name?: string;
  file_hash?: string;
  scan_status: string;
  threat_level: string;
  files_checked: number;
  threats_found: number;
  duration_ms?: number;
  source?: string;
  scanned_at: string;
}

export function presentScanRecord(record: ScanHistoryRecord): ScanRecordDto {
  return {
    id: record.id,
    scan_type: record.scanType,
    ...(record.target ? { target: record.target } : {}),
    ...(record.fileName ? { file_name: record.fileName } : {}),
    ...(record.fileHash ? { file_hash: record.fileHash } : {}),
    scan_status: record.scanStatus,
    threat_level: record.threatLevel,
    files_checked: record.filesChecked,
    threats_found: record.threatsFound,
    ...(record.durationMs !== undefined ? { duration_ms: record.durationMs } : {}),
    ...(record.source ? { source: record.source } : {}),
    scanned_at: record.scannedAt,
  };
}

export interface AlertRecordDto {
  id: string;
  threat_type: string;
  severity: string;
  category?: string;
  source_application?: string;
  detection_reason: string;
  target?: string;
  recommended_action?: string;
  is_read: boolean;
  created_at: string;
}

export function presentAlertRecord(record: ThreatAlertRecord): AlertRecordDto {
  return {
    id: record.id,
    threat_type: record.threatType,
    severity: record.severity,
    ...(record.category ? { category: record.category } : {}),
    ...(record.sourceApplication ? { source_application: record.sourceApplication } : {}),
    detection_reason: record.detectionReason,
    ...(record.target ? { target: record.target } : {}),
    ...(record.recommendedAction ? { recommended_action: record.recommendedAction } : {}),
    is_read: record.isRead,
    created_at: record.createdAt,
  };
}
