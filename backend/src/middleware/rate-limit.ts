import rateLimit from 'express-rate-limit';
import type { RequestHandler } from 'express';
import type { Env } from '../config/env';
import { AppError } from '../utils/errors';

/**
 * Rate limiting.
 *
 * Uses the standard `draft-8` headers so clients can see their remaining
 * budget. Exceeding the limit produces the same error envelope as every other
 * failure, with code RATE_LIMITED.
 */
export function rateLimitMiddleware(env: Env): RequestHandler {
  return rateLimit({
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    limit: env.RATE_LIMIT_MAX,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (_req, _res, next) => {
      next(
        new AppError({
          code: 'RATE_LIMITED',
          statusCode: 429,
          message: 'Too many requests. Please wait a moment and try again.',
        }),
      );
    },
  });
}
