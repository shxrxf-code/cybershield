import { z } from 'zod';
import { detectionReasonSchema, verdictStatusSchema } from './common';

export const MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB

/**
 * File scan request.
 *
 * The bytes never leave the device: the client hashes the file locally and
 * sends only the SHA-256 plus its own structural findings. `localFindings`
 * are the device analyzer's observations (PDF JavaScript, APK permissions,
 * signature mismatch, …) and are merged into the server verdict.
 */
export const fileScanSchema = z.object({
  sha256: z
    .string()
    .trim()
    .regex(/^[a-f0-9]{64}$/i, 'sha256 must be a 64-character hexadecimal hash'),
  fileName: z.string().trim().max(260).optional(),
  sizeBytes: z.number().int().min(0).max(MAX_FILE_BYTES).optional(),
  mimeType: z.string().trim().max(160).optional(),
  extension: z
    .string()
    .trim()
    .max(16)
    .regex(/^[a-z0-9]+$/i, 'extension must be alphanumeric')
    .optional(),
  localStatus: verdictStatusSchema.optional(),
  localSource: z
    .enum(['local-file-analysis', 'local-document-analysis', 'local-apk-analysis'])
    .optional(),
  localFindings: z.array(detectionReasonSchema).max(100).optional(),
});

export type FileScanRequest = z.infer<typeof fileScanSchema>;
