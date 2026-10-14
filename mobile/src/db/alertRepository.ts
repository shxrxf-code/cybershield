/**
 * Mobile ThreatGuard — alert repository.
 *
 * Handles all database operations for threat alerts.
 */

import { generateId } from '../utils/format';
import { execute } from './service';
import type { ThreatAlert } from '../domain/types';
import type { AlertRecord as DbAlertRecord } from './schema';
import type { Scalar } from '@op-engineering/op-sqlite';

export interface AlertRepository {
  create(alert: Omit<ThreatAlert, 'id' | 'createdAt'>): Promise<ThreatAlert>;
  findById(id: string): Promise<ThreatAlert | null>;
  findAll(options?: AlertFindOptions): Promise<ThreatAlert[]>;
  findUnread(): Promise<ThreatAlert[]>;
  findRecent(limit: number): Promise<ThreatAlert[]>;
  markRead(id: string): Promise<boolean>;
  markUnread(id: string): Promise<boolean>;
  markAllRead(): Promise<number>;
  delete(id: string): Promise<boolean>;
  deleteAll(): Promise<number>;
  count(): Promise<number>;
  unreadCount(): Promise<number>;
  getById(id: string): Promise<ThreatAlert | undefined>;
}

export interface AlertFindOptions {
  severity?: string;
  threatType?: string;
  isRead?: boolean;
  limit?: number;
  offset?: number;
  orderBy?: 'createdAt' | 'scannedAt';
  orderDir?: 'ASC' | 'DESC';
}

const ALERT_COLUMNS = `
  id, threat_type, severity, category, target, source_application,
  detection_reason, recommended_action, is_read,
  scanned_at, created_at, read_at
`;

function mapDbToDomain(row: DbAlertRecord): ThreatAlert {
  return {
    id: row.id,
    threatType: row.threat_type,
    severity: row.severity as ThreatAlert['severity'],
    category: row.category as ThreatAlert['category'] | undefined,
    target: row.target ?? undefined,
    sourceApplication: row.source_application ?? undefined,
    detectionReason: row.detection_reason,
    recommendedAction: row.recommended_action ?? undefined,
    isRead: row.is_read === 1,
    scannedAt: row.scanned_at,
    createdAt: row.created_at,
    readAt: row.read_at ?? undefined,
  };
}

function mapDomainToDb(alert: Omit<ThreatAlert, 'id' | 'createdAt'>): Record<string, Scalar> {
  return {
    threat_type: alert.threatType,
    severity: alert.severity,
    category: alert.category ?? null,
    target: alert.target ?? null,
    source_application: alert.sourceApplication ?? null,
    detection_reason: alert.detectionReason,
    recommended_action: alert.recommendedAction ?? null,
    is_read: alert.isRead ? 1 : 0,
    scanned_at: alert.scannedAt,
    read_at: alert.readAt ?? null,
  };
}

async function execAlertRows<T>(query: string, params?: Scalar[]): Promise<T[]> {
  const result = await execute(query, params as Scalar[]);
  return result.rows as T[];
}

export const alertRepository: AlertRepository = {
  async create(alert) {
    const id = generateId();
    const now = new Date().toISOString();
    const dbRecord = mapDomainToDb(alert);

    const result = await execute(
      `INSERT INTO alerts (
        id, threat_type, severity, category, target, source_application,
        detection_reason, recommended_action, is_read,
        scanned_at, created_at, read_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        dbRecord.threat_type,
        dbRecord.severity,
        dbRecord.category,
        dbRecord.target,
        dbRecord.source_application,
        dbRecord.detection_reason,
        dbRecord.recommended_action,
        dbRecord.is_read,
        dbRecord.scanned_at,
        now,
        dbRecord.read_at,
      ]
    );

    if (result.rowsAffected === 0) {
      throw new Error('Failed to insert alert record');
    }

    return this.findById(id) as Promise<ThreatAlert>;
  },

  async findById(id) {
    const rows = await execAlertRows<DbAlertRecord>(
      `SELECT ${ALERT_COLUMNS} FROM alerts WHERE id = ?`,
      [id]
    );
    return rows[0] ? mapDbToDomain(rows[0]) : null;
  },

  async findAll(options = {}) {
    const {
      severity,
      threatType,
      isRead,
      limit = 100,
      offset = 0,
      orderBy = 'createdAt',
      orderDir = 'DESC',
    } = options;

    let where = '1=1';
    const params: Scalar[] = [];

    if (severity) {
      where += ' AND severity = ?';
      params.push(severity);
    }
    if (threatType) {
      where += ' AND threat_type = ?';
      params.push(threatType);
    }
    if (isRead !== undefined) {
      where += ' AND is_read = ?';
      params.push(isRead ? 1 : 0);
    }

    const dbOrderBy = orderBy === 'createdAt' ? 'created_at' : 'scanned_at';

    const query = `
      SELECT ${ALERT_COLUMNS}
      FROM alerts
      WHERE ${where}
      ORDER BY ${dbOrderBy} ${orderDir}
      LIMIT ? OFFSET ?
    `;
    params.push(limit, offset);

    const rows = await execAlertRows<DbAlertRecord>(query, params);
    return rows.map(mapDbToDomain);
  },

  async findUnread() {
    return this.findAll({ isRead: false, orderBy: 'createdAt', orderDir: 'DESC' });
  },

  async findRecent(limit = 200) {
    return this.findAll({ limit, orderBy: 'createdAt', orderDir: 'DESC' });
  },

  async markRead(id) {
    const result = await execute(
      'UPDATE alerts SET is_read = 1, read_at = datetime("now") WHERE id = ?',
      [id]
    );
    return result.rowsAffected > 0;
  },

  async markUnread(id) {
    const result = await execute(
      'UPDATE alerts SET is_read = 0, read_at = NULL WHERE id = ?',
      [id]
    );
    return result.rowsAffected > 0;
  },

  async markAllRead() {
    const result = await execute('UPDATE alerts SET is_read = 1, read_at = datetime("now") WHERE is_read = 0');
    return result.rowsAffected;
  },

  async delete(id) {
    const result = await execute('DELETE FROM alerts WHERE id = ?', [id]);
    return result.rowsAffected > 0;
  },

  async deleteAll() {
    const result = await execute('DELETE FROM alerts');
    return result.rowsAffected;
  },

  async count() {
    const result = await execute<{ count: number }>('SELECT COUNT(*) as count FROM alerts');
    return result.rows[0]?.count ?? 0;
  },

  async unreadCount() {
    const result = await execute<{ count: number }>(
      'SELECT COUNT(*) as count FROM alerts WHERE is_read = 0'
    );
    return result.rows[0]?.count ?? 0;
  },

  async getById(id) {
    const alert = await this.findById(id);
    return alert ?? undefined;
  },
};