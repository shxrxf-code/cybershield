/**
 * Mobile ThreatGuard — settings repository.
 *
 * Handles all database operations for app settings.
 * Provides a simple key-value store with JSON serialization for complex values.
 */

import { execute } from './service';
import type { SettingRecord } from './schema';

export interface SettingsRepository {
  get<K extends keyof SettingsShape>(key: K): Promise<SettingsShape[K] | undefined>;
  getAll(): Promise<Partial<SettingsShape>>;
  set<K extends keyof SettingsShape>(key: K, value: SettingsShape[K]): Promise<void>;
  delete(key: string): Promise<boolean>;
  clear(): Promise<number>;
  reset(): Promise<void>;
}

// Define the shape of all settings we persist
export interface SettingsShape {
  // Security settings
  notificationMonitoring: boolean;
  backgroundProtection: boolean;
  alertNotifications: boolean;
  /** Packages the user asked us not to analyse. */
  notificationIgnoredPackages: string[];

  // Privacy preferences
  privacyPreferences: {
    analytics: boolean;
    crashReporting: boolean;
    shareThreatData: boolean;
  };

  // UI settings
  colorScheme: 'light' | 'dark' | 'system' | undefined;

  // Onboarding
  onboardingComplete: boolean;

  // API configuration
  apiKey?: string;
  apiBaseUrl?: string;
}

// Default values matching the in-memory store
export const DEFAULT_SETTINGS: SettingsShape = {
  notificationMonitoring: false,
  backgroundProtection: false,
  alertNotifications: true,
  notificationIgnoredPackages: [],
  privacyPreferences: {
    analytics: false,
    crashReporting: false,
    shareThreatData: false,
  },
  colorScheme: undefined,
  onboardingComplete: false,
};

function deserialize<T>(value: string): T {
  try {
    return JSON.parse(value);
  } catch {
    return value as unknown as T;
  }
}

function getDefaultValue<K extends keyof SettingsShape>(key: K): SettingsShape[K] {
  return DEFAULT_SETTINGS[key];
}

async function execSettingRows(query: string, params?: unknown[]): Promise<SettingRecord[]> {
  const result = await execute(query, params as never);
  return result.rows as SettingRecord[];
}

export const settingsRepository: SettingsRepository = {
  async get<K extends keyof SettingsShape>(key: K) {
    const rows = await execSettingRows(
      `SELECT key, value, updated_at FROM settings WHERE key = ?`,
      [key]
    );
    const row = rows[0];
    if (!row) return undefined;

    const defaultValue = getDefaultValue(key);
    if (typeof defaultValue === 'object' && defaultValue !== null) {
      return deserialize<SettingsShape[K]>(row.value);
    }
    if (typeof defaultValue === 'boolean') {
      return (row.value === 'true') as SettingsShape[K];
    }
    if (typeof defaultValue === 'number') {
      return Number(row.value) as unknown as SettingsShape[K];
    }
    return row.value as SettingsShape[K];
  },

  async getAll() {
    const rows = await execSettingRows(`SELECT key, value, updated_at FROM settings`);
    const all: Record<string, unknown> = {};
    for (const row of rows) {
      const key = row.key as keyof SettingsShape;
      const defaultValue = getDefaultValue(key);
      if (typeof defaultValue === 'object' && defaultValue !== null) {
        all[key] = deserialize(row.value);
      } else if (typeof defaultValue === 'boolean') {
        all[key] = row.value === 'true';
      } else if (typeof defaultValue === 'number') {
        all[key] = Number(row.value);
      } else {
        all[key] = row.value;
      }
    }
    return all as Partial<SettingsShape>;
  },

  async set<K extends keyof SettingsShape>(key: K, value: SettingsShape[K]) {
    const serialized = JSON.stringify(value);
    await execute(
      `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime("now"))
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime("now")`,
      [key, serialized]
    );
  },

  async delete(key) {
    const result = await execute('DELETE FROM settings WHERE key = ?', [key]);
    return result.rowsAffected > 0;
  },

  async clear() {
    const result = await execute('DELETE FROM settings');
    return result.rowsAffected;
  },

  async reset() {
    await this.clear();
    for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) {
      await this.set(key as keyof SettingsShape, value);
    }
  },
};

/**
 * Initialize settings with defaults if they don't exist.
 * Call this on app startup.
 */
export async function initSettings(): Promise<void> {
  for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) {
    const existing = await settingsRepository.get(key as keyof SettingsShape);
    if (existing === undefined) {
      await settingsRepository.set(key as keyof SettingsShape, value);
    }
  }
}