import type { Request, Response } from 'express';
import type { Container } from '../container';
import { validated } from '../middleware/validate';
import { settingsPatchSchema, type SettingsPatch } from '../validators/list.validator';
import type { SecuritySettingsRecord } from '../database/repositories/settings-repository';

function presentSettings(record: SecuritySettingsRecord) {
  return {
    id: record.id,
    notification_monitoring: record.notificationMonitoring,
    background_protection: record.backgroundProtection,
    alert_notifications: record.alertNotifications,
    privacy_preferences: record.privacyPreferences,
    updated_at: record.updatedAt,
  };
}

/** User preferences (security settings). */
export function createPreferencesController(container: Container) {
  const { settings } = container.repositories;

  return {
    get: async (_req: Request, res: Response): Promise<void> => {
      const record = await settings.get();
      res.status(200).json(presentSettings(record));
    },

    update: async (req: Request, res: Response): Promise<void> => {
      const patch = validated<SettingsPatch>(req, 'body');
      const record = await settings.update(undefined, {
        notificationMonitoring: patch.notificationMonitoring,
        backgroundProtection: patch.backgroundProtection,
        alertNotifications: patch.alertNotifications,
        privacyPreferences: patch.privacyPreferences,
      });
      res.status(200).json(presentSettings(record));
    },
  };
}
