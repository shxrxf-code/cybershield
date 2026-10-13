import type { AlertThreatType, ThreatAlertRecord } from '../database/repositories/alert-repository';
import type { ScanHistoryRecord, ScanType } from '../database/repositories/scan-repository';
import type { MergedVerdict } from '../domain/verdict';
import type { AlertRepository } from '../database/repositories/alert-repository';
import type { ScanRepository } from '../database/repositories/scan-repository';
import type { UrlScanOutcome } from './url-reputation.service';
import type { FileScanOutcome } from './file-analysis.service';
import type { NotificationAnalysisOutcome } from './notification-analysis.service';
import { recommendedAction } from './url-reputation.service';

/**
 * Turns scanner outcomes into durable history and (deduplicated) alerts.
 * Keeping this in one place means the alert-dedupe rule exists exactly once.
 */

const ALERT_DEDUPE_WINDOW_MS = 10 * 60 * 1000;

export interface RecordScanOptions {
  userId?: string;
  source?: string;
}

export interface RecordedScan {
  scan: ScanHistoryRecord;
  alert?: ThreatAlertRecord;
  /** True when an equivalent alert already existed and none was created. */
  duplicateAlert: boolean;
}

interface AlertInput {
  threatType: AlertThreatType;
  verdict: MergedVerdict;
  target: string;
  sourceApplication?: string;
  scanId?: string;
  userId?: string;
}

function isThreatening(verdict: MergedVerdict): boolean {
  return verdict.status === 'MALICIOUS' || verdict.status === 'SUSPICIOUS';
}

function fileThreatType(extension: string | undefined): AlertThreatType {
  switch ((extension ?? '').toLowerCase()) {
    case 'pdf':
      return 'suspicious_pdf';
    case 'apk':
      return 'harmful_apk';
    case 'jpg':
    case 'jpeg':
    case 'png':
    case 'webp':
      return 'suspicious_image';
    default:
      return 'suspicious_file';
  }
}

export class ScanHistoryService {
  constructor(
    private readonly scans: ScanRepository,
    private readonly alerts: AlertRepository,
  ) {}

  private async createAlertIfNeeded(input: AlertInput): Promise<{ alert?: ThreatAlertRecord; duplicate: boolean }> {
    if (!isThreatening(input.verdict)) return { duplicate: false };

    const existing = await this.alerts.findRecentDuplicate(
      input.threatType,
      input.target,
      ALERT_DEDUPE_WINDOW_MS,
    );
    if (existing) return { alert: existing, duplicate: true };

    const reason =
      input.verdict.reasons.find((r) => r.weight >= 45)?.message ??
      input.verdict.reasons[0]?.message ??
      `${input.verdict.status} verdict`;

    const alert = await this.alerts.create({
      userId: input.userId,
      scanId: input.scanId,
      threatType: input.threatType,
      severity: input.verdict.severity,
      category: input.verdict.category,
      sourceApplication: input.sourceApplication,
      detectionReason: reason,
      target: input.target,
      recommendedAction: recommendedAction(input.verdict.status),
    });
    return { alert, duplicate: false };
  }

  async recordUrlScan(outcome: UrlScanOutcome, options: RecordScanOptions = {}): Promise<RecordedScan> {
    const scan = await this.scans.create({
      userId: options.userId,
      scanType: 'url',
      target: outcome.normalized.canonical,
      scanStatus: 'completed',
      verdict: outcome.verdict.status,
      threatLevel: outcome.verdict.severity,
      filesChecked: 1,
      threatsFound: isThreatening(outcome.verdict) ? 1 : 0,
      durationMs: outcome.durationMs,
      source: options.source ?? 'api',
      details: {
        domain: outcome.normalized.domain,
        protocol: outcome.normalized.protocol,
        sources: outcome.verdict.sources.map((s) => ({ source: s.source, status: s.status })),
        cached: outcome.cached,
      },
      scannedAt: outcome.scannedAt,
    });

    const { alert, duplicate } = await this.createAlertIfNeeded({
      threatType: outcome.verdict.status === 'MALICIOUS' ? 'malicious_url' : 'suspicious_url',
      verdict: outcome.verdict,
      target: outcome.normalized.canonical,
      scanId: scan.id,
      userId: options.userId,
    });

    return { scan, alert, duplicateAlert: duplicate };
  }

  async recordFileScan(
    outcome: FileScanOutcome,
    meta: { fileName?: string; extension?: string; filesChecked?: number },
    options: RecordScanOptions = {},
  ): Promise<RecordedScan> {
    const scan = await this.scans.create({
      userId: options.userId,
      scanType: meta.extension === 'apk' ? 'apk' : 'file',
      target: meta.fileName,
      fileName: meta.fileName,
      fileHash: outcome.sha256,
      scanStatus: 'completed',
      verdict: outcome.verdict.status,
      threatLevel: outcome.verdict.severity,
      filesChecked: meta.filesChecked ?? 1,
      threatsFound: isThreatening(outcome.verdict) ? 1 : 0,
      durationMs: outcome.durationMs,
      source: options.source ?? 'api',
      details: {
        extension: meta.extension,
        sources: outcome.verdict.sources.map((s) => ({ source: s.source, status: s.status })),
      },
      scannedAt: outcome.scannedAt,
    });

    const { alert, duplicate } = await this.createAlertIfNeeded({
      threatType: fileThreatType(meta.extension),
      verdict: outcome.verdict,
      target: outcome.sha256,
      scanId: scan.id,
      userId: options.userId,
    });

    return { scan, alert, duplicateAlert: duplicate };
  }

  async recordNotificationScan(
    outcome: NotificationAnalysisOutcome,
    meta: { sourceApp?: string; sourcePackage?: string },
    options: RecordScanOptions = {},
  ): Promise<RecordedScan> {
    // The stored `target` is a domain or the source app – never message text.
    const firstUrl = outcome.urls[0]?.normalized.canonical;
    const target = firstUrl ?? meta.sourceApp ?? 'notification';

    const scan = await this.scans.create({
      userId: options.userId,
      scanType: 'notification',
      target,
      scanStatus: 'completed',
      verdict: outcome.verdict.status,
      threatLevel: outcome.verdict.severity,
      filesChecked: 1,
      threatsFound: isThreatening(outcome.verdict) ? 1 : 0,
      durationMs: outcome.durationMs,
      source: options.source ?? 'notification-listener',
      details: {
        signals: outcome.matchedSignals.length,
        urls: outcome.urls.length,
        // Deliberately no message body.
      },
    });

    const threatType: AlertThreatType =
      outcome.urls.length > 0 && isThreatening(outcome.verdict)
        ? 'phishing_notification'
        : 'suspicious_message';

    const { alert, duplicate } = await this.createAlertIfNeeded({
      threatType,
      verdict: outcome.verdict,
      target,
      sourceApplication: meta.sourceApp,
      scanId: scan.id,
      userId: options.userId,
    });

    return { scan, alert, duplicateAlert: duplicate };
  }

  async latest(limit = 10): Promise<ScanHistoryRecord[]> {
    const { items } = await this.scans.list({ limit });
    return items;
  }

  async dashboardSummary(): Promise<{
    totalScans: number;
    totalThreats: number;
    lastScanAt?: string;
    unreadAlerts: number;
    alertsBySeverity: Record<string, number>;
  }> {
    const [summary, unreadAlerts, alertsBySeverity] = await Promise.all([
      this.scans.summary(),
      this.alerts.unreadCount(),
      this.alerts.countBySeverity(),
    ]);
    return { ...summary, unreadAlerts, alertsBySeverity };
  }
}
