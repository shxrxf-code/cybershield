import { randomUUID } from 'node:crypto';
import type { Database } from '../adapter';
import type { Severity, ThreatCategory } from '../../domain/verdict';

export type AlertThreatType =
  | 'malicious_url'
  | 'suspicious_url'
  | 'suspicious_pdf'
  | 'harmful_apk'
  | 'suspicious_image'
  | 'suspicious_file'
  | 'phishing_notification'
  | 'suspicious_message'
  | 'scan_completed'
  | 'permission_disabled';

export interface ThreatAlertRecord {
  id: string;
  userId?: string;
  scanId?: string;
  threatType: AlertThreatType;
  severity: Severity;
  category?: ThreatCategory;
  sourceApplication?: string;
  detectionReason: string;
  target?: string;
  recommendedAction?: string;
  isRead: boolean;
  createdAt: string;
}

export interface CreateAlertInput {
  userId?: string;
  scanId?: string;
  threatType: AlertThreatType;
  severity: Severity;
  category?: ThreatCategory;
  sourceApplication?: string;
  detectionReason: string;
  target?: string;
  recommendedAction?: string;
  createdAt?: string;
}

export interface ListAlertsQuery {
  limit?: number;
  offset?: number;
  severity?: Severity;
  unreadOnly?: boolean;
  search?: string;
}

interface AlertRow {
  id: string;
  user_id: string | null;
  scan_id: string | null;
  threat_type: string;
  severity: string;
  category: string | null;
  source_application: string | null;
  detection_reason: string;
  target: string | null;
  recommended_action: string | null;
  is_read: number;
  created_at: string;
}

function mapRow(row: AlertRow): ThreatAlertRecord {
  return {
    id: row.id,
    userId: row.user_id ?? undefined,
    scanId: row.scan_id ?? undefined,
    threatType: row.threat_type as AlertThreatType,
    severity: row.severity as Severity,
    category: (row.category ?? undefined) as ThreatCategory | undefined,
    sourceApplication: row.source_application ?? undefined,
    detectionReason: row.detection_reason,
    target: row.target ?? undefined,
    recommendedAction: row.recommended_action ?? undefined,
    isRead: row.is_read === 1,
    createdAt: row.created_at,
  };
}

export class AlertRepository {
  constructor(private readonly db: Database) {}

  async create(input: CreateAlertInput): Promise<ThreatAlertRecord> {
    const record: ThreatAlertRecord = {
      id: randomUUID(),
      userId: input.userId,
      scanId: input.scanId,
      threatType: input.threatType,
      severity: input.severity,
      category: input.category,
      sourceApplication: input.sourceApplication,
      detectionReason: input.detectionReason,
      target: input.target,
      recommendedAction: input.recommendedAction,
      isRead: false,
      createdAt: input.createdAt ?? new Date().toISOString(),
    };

    await this.db.execute(
      `INSERT INTO threat_alerts
        (id, user_id, scan_id, threat_type, severity, category, source_application,
         detection_reason, target, recommended_action, is_read, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.id,
        record.userId ?? null,
        record.scanId ?? null,
        record.threatType,
        record.severity,
        record.category ?? null,
        record.sourceApplication ?? null,
        record.detectionReason,
        record.target ?? null,
        record.recommendedAction ?? null,
        record.isRead ? 1 : 0,
        record.createdAt,
      ],
    );
    return record;
  }

  /**
   * Look for an equivalent alert raised recently. Used to avoid duplicate
   * alerts for the same threat, which is an explicit product requirement.
   */
  async findRecentDuplicate(
    threatType: AlertThreatType,
    target: string,
    withinMs: number,
  ): Promise<ThreatAlertRecord | undefined> {
    const since = new Date(Date.now() - withinMs).toISOString();
    const { rows } = await this.db.query<AlertRow>(
      `SELECT * FROM threat_alerts
        WHERE threat_type = ? AND COALESCE(target, '') = ? AND created_at >= ?
        ORDER BY created_at DESC LIMIT 1`,
      [threatType, target, since],
    );
    return rows[0] ? mapRow(rows[0]) : undefined;
  }

  async list(query: ListAlertsQuery = {}): Promise<{ items: ThreatAlertRecord[]; total: number }> {
    const limit = Math.min(Math.max(query.limit ?? 50, 1), 200);
    const offset = Math.max(query.offset ?? 0, 0);

    const clauses: string[] = [];
    const params: Array<string | number> = [];
    if (query.severity) {
      clauses.push('severity = ?');
      params.push(query.severity);
    }
    if (query.unreadOnly) {
      clauses.push('is_read = 0');
    }
    if (query.search) {
      clauses.push('(LOWER(detection_reason) LIKE ? OR LOWER(COALESCE(target, \'\')) LIKE ?)');
      const needle = `%${query.search.toLowerCase()}%`;
      params.push(needle, needle);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';

    const countResult = await this.db.query<{ total: number }>(
      `SELECT COUNT(*) AS total FROM threat_alerts ${where}`,
      params,
    );
    const { rows } = await this.db.query<AlertRow>(
      `SELECT * FROM threat_alerts ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset],
    );

    return { items: rows.map(mapRow), total: Number(countResult.rows[0]?.total ?? 0) };
  }

  async unreadCount(): Promise<number> {
    const { rows } = await this.db.query<{ total: number }>(
      'SELECT COUNT(*) AS total FROM threat_alerts WHERE is_read = 0',
    );
    return Number(rows[0]?.total ?? 0);
  }

  /** Count alerts by severity for the dashboard. */
  async countBySeverity(): Promise<Record<string, number>> {
    const { rows } = await this.db.query<{ severity: string; total: number }>(
      'SELECT severity, COUNT(*) AS total FROM threat_alerts GROUP BY severity',
    );
    const out: Record<string, number> = {};
    for (const row of rows) out[row.severity] = Number(row.total);
    return out;
  }

  async markRead(id: string, isRead = true): Promise<boolean> {
    const result = await this.db.execute('UPDATE threat_alerts SET is_read = ? WHERE id = ?', [
      isRead ? 1 : 0,
      id,
    ]);
    return result.changes > 0;
  }

  async markAllRead(): Promise<number> {
    const result = await this.db.execute('UPDATE threat_alerts SET is_read = 1 WHERE is_read = 0');
    return result.changes;
  }

  async clear(): Promise<number> {
    const result = await this.db.execute('DELETE FROM threat_alerts');
    return result.changes;
  }
}
