import { z } from 'zod';

export const MAX_NOTIFICATION_TEXT = 4_000;

/**
 * Notification analysis request.
 *
 * The body is analysed transiently and never persisted. Callers should send
 * only what Android exposed in the notification; the service truncates overly
 * long text defensively.
 */
export const notificationAnalysisSchema = z.object({
  text: z.string().trim().min(1, 'Notification text is required').max(MAX_NOTIFICATION_TEXT),
  title: z.string().trim().max(300).optional(),
  sourceApp: z.string().trim().max(80).optional(),
  packageName: z
    .string()
    .trim()
    .max(160)
    .regex(/^[a-zA-Z0-9_.]+$/, 'packageName must be a valid Android package name')
    .optional(),
});

export type NotificationAnalysisRequest = z.infer<typeof notificationAnalysisSchema>;
