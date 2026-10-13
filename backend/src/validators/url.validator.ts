import { z } from 'zod';

export const MAX_URL_LENGTH = 2048;

/**
 * URL scan request.
 *
 * We only accept a URL string; there is deliberately no "auto-open" or
 * "follow redirects on the server" option, because the server must never
 * dereference a suspect link on the user's behalf.
 */
export const urlScanSchema = z.object({
  url: z
    .string()
    .trim()
    .min(1, 'A URL is required')
    .max(MAX_URL_LENGTH, `URL must be at most ${MAX_URL_LENGTH} characters`),
  skipCache: z.boolean().optional(),
});

export type UrlScanRequest = z.infer<typeof urlScanSchema>;

export const urlBatchScanSchema = z.object({
  urls: z.array(z.string().trim().min(1).max(MAX_URL_LENGTH)).min(1).max(20),
  skipCache: z.boolean().optional(),
});

export type UrlBatchScanRequest = z.infer<typeof urlBatchScanSchema>;
