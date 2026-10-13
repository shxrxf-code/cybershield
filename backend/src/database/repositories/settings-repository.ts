import { randomUUID } from 'node:crypto';
import type { Database } from '../adapter';

export interface SecuritySettingsRecord {
  id: string;
  userId?: string;
  notificationMonitoring: boolean;
  backgroundProtection: boolean;
  alertNotifications: boolean;
  privacyPreferences: Record<string, unknown>;
  updatedAt: string;
}

export interface SettingsPatch {
  notificationMonitoring?: boolean;
  backgroundProtection?: boolean;
  alertNotifications?: boolean;
  privacyPreferences?: Record<string, unknown>;
}

interface SettingsRow {
  id: string;
  user_id: string | null;
  notification_monitoring: number;
  background_protection: number;
  alert_notifications: number;
  privacy_preferences: string;
  updated_at: string;
}

function safeJsonParse(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value);
    return typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function mapRow(row: SettingsRow): SecuritySettingsRecord {
  return {
    id: row.id,
    userId: row.user_id ?? undefined,
    notificationMonitoring: row.notification_monitoring === 1,
    backgroundProtection: row.background_protection === 1,
    alertNotifications: row.alert_notifications === 1,
    privacyPreferences: safeJsonParse(row.privacy_preferences),
    updatedAt: row.updated_at,
  };
}

const DEFAULTS: Omit<SecuritySettingsRecord, 'id' | 'updatedAt'> = {
  notificationMonitoring: false,
  backgroundProtection: true,
  alertNotifications: true,
  privacyPreferences: {},
};

export class SettingsRepository {
  constructor(private readonly db: Database) {}

  /** Return settings for a user, creating the default row on first access. */
  async get(userId?: string): Promise<SecuritySettingsRecord> {
    const { rows } = await this.db.query<SettingsRow>(
      userId
        ? 'SELECT * FROM security_settings WHERE user_id = ?'
        : 'SELECT * FROM security_settings WHERE user_id IS NULL',
      userId ? [userId] : [],
    );
    if (rows[0]) return mapRow(rows[0]);

    const record: SecuritySettingsRecord = {
      id: randomUUID(),
      userId,
      ...DEFAULTS,
      updatedAt: new Date().toISOString(),
    };
    await this.db.execute(
      `INSERT INTO security_settings
        (id, user_id, notification_monitoring, background_protection, alert_notifications,
         privacy_preferences, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        record.id,
        record.userId ?? null,
        record.notificationMonitoring ? 1 : 0,
        record.backgroundProtection ? 1 : 0,
        record.alertNotifications ? 1 : 0,
        JSON.stringify(record.privacyPreferences),
        record.updatedAt,
      ],
    );
    return record;
  }

  async update(userId: string | undefined, patch: SettingsPatch): Promise<SecuritySettingsRecord> {
    const current = await this.get(userId);
    const next: SecuritySettingsRecord = {
      ...current,
      notificationMonitoring: patch.notificationMonitoring ?? current.notificationMonitoring,
      backgroundProtection: patch.backgroundProtection ?? current.backgroundProtection,
      alertNotifications: patch.alertNotifications ?? current.alertNotifications,
      privacyPreferences: patch.privacyPreferences
        ? { ...current.privacyPreferences, ...patch.privacyPreferences }
        : current.privacyPreferences,
      updatedAt: new Date().toISOString(),
    };

    await this.db.execute(
      `UPDATE security_settings
          SET notification_monitoring = ?, background_protection = ?, alert_notifications = ?,
              privacy_preferences = ?, updated_at = ?
        WHERE id = ?`,
      [
        next.notificationMonitoring ? 1 : 0,
        next.backgroundProtection ? 1 : 0,
        next.alertNotifications ? 1 : 0,
        JSON.stringify(next.privacyPreferences),
        next.updatedAt,
        next.id,
      ],
    );
    return next;
  }
}
