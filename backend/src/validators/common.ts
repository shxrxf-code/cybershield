import { z } from 'zod';

/** Shared enums so schemas, repositories and clients agree on the vocabulary. */
export const verdictStatusSchema = z.enum(['SAFE', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN']);
export const severitySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export const scanTypeSchema = z.enum(['quick', 'full', 'url', 'file', 'apk', 'notification', 'scheduled']);

export const detectionReasonSchema = z.object({
  code: z.string().min(1).max(120),
  message: z.string().min(1).max(500),
  weight: z.number().min(0).max(500),
  severity: severitySchema,
});

/** Query-string pagination shared by list endpoints. */
export const paginationQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).optional(),
  search: z.string().trim().min(1).max(200).optional(),
});

export const idParamSchema = z.object({
  id: z.string().trim().min(1).max(128),
});
