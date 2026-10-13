import type { Request, Response } from 'express';
import type { Container } from '../container';
import { validated } from '../middleware/validate';
import type { UrlScanRequest, UrlBatchScanRequest } from '../validators/url.validator';
import { presentUrlScan } from './dto';
import { AppError } from '../utils/errors';

/**
 * URL reputation endpoints.
 *
 * The server never fetches the submitted URL. It normalises it, runs local
 * heuristics, queries the configured reputation providers, and returns a
 * merged verdict with the reason behind it.
 */
export function createUrlController(container: Container) {
  return {
    scan: async (req: Request, res: Response): Promise<void> => {
      const body = validated<UrlScanRequest>(req, 'body');
      const outcome = await container.services.urlReputation.analyze(body.url, {
        skipCache: body.skipCache === true,
      });
      const recorded = await container.services.scanHistory.recordUrlScan(outcome, { source: 'api' });
      res.status(200).json(presentUrlScan(outcome, recorded));
    },

    scanBatch: async (req: Request, res: Response): Promise<void> => {
      const body = validated<UrlBatchScanRequest>(req, 'body');
      const results: unknown[] = [];

      for (const url of body.urls) {
        try {
          const outcome = await container.services.urlReputation.analyze(url, {
            skipCache: body.skipCache === true,
          });
          const recorded = await container.services.scanHistory.recordUrlScan(outcome, { source: 'api-batch' });
          results.push(presentUrlScan(outcome, recorded));
        } catch (error) {
          // One bad URL must not fail the whole batch.
          results.push({
            url,
            error: {
              code: error instanceof AppError ? error.code : 'INTERNAL_ERROR',
              message: error instanceof AppError ? error.message : 'This URL could not be analysed',
            },
          });
        }
      }

      res.status(200).json({ results, count: results.length });
    },
  };
}
