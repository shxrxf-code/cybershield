import { z } from 'zod';
import { paginationQuerySchema, scanTypeSchema, severitySchema } from './common';

export const scanListQuerySchema = paginationQuerySchema.extend({
  scanType: scanTypeSchema.optional(),
  threatLevel: severitySchema.optional(),
});

export type ScanListQuery = z.infer<typeof scanListQuerySchema>;

const booleanQuery = z
  .enum(['true', 'false'])
  .optional()
  .transform((value) => value === 'true');

export const alertListQuerySchema = paginationQuerySchema.extend({
  severity: severitySchema.optional(),
  unreadOnly: booleanQuery,
});

export type AlertListQuery = z.infer<typeof alertListQuerySchema>;

export const settingsPatchSchema = z
  .object({
    notificationMonitoring: z.boolean().optional(),
    backgroundProtection: z.boolean().optional(),
    alertNotifications: z.boolean().optional(),
    privacyPreferences: z.record(z.string(), z.unknown()).optional(),
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: 'Provide at least one setting to update',
  });

export type SettingsPatch = z.infer<typeof settingsPatchSchema>;
