import type { RequestHandler } from 'express';
import type { ZodType } from 'zod';
import { ValidationError } from '../utils/errors';

export type ValidationSource = 'body' | 'query' | 'params';

/**
 * Validate and coerce a request part with a Zod schema.
 *
 * Parsed output is stored on `req.validated[source]` (Express 5 makes
 * `req.query` read-only, so we never mutate the request in place). Failures
 * become a 400 with a per-field list the client can display.
 */
export function validate<T>(schema: ZodType<T>, source: ValidationSource = 'body'): RequestHandler {
  return (req, _res, next) => {
    const raw = source === 'body' ? req.body : source === 'query' ? req.query : req.params;
    const result = schema.safeParse(raw);
    if (!result.success) {
      const details = result.error.issues.map((issue) => ({
        field: issue.path.join('.') || source,
        message: issue.message,
      }));
      next(new ValidationError('Request validation failed', details));
      return;
    }
    req.validated = { ...(req.validated ?? {}), [source]: result.data };
    next();
  };
}

/** Read a value previously validated into the request. */
export function validated<T>(req: { validated?: { body?: unknown; query?: unknown; params?: unknown } }, source: ValidationSource): T {
  if (!req.validated) throw new Error('validate() middleware did not run for this route');
  const value = req.validated[source];
  if (value === undefined) throw new Error(`No validated ${source} on request`);
  return value as T;
}
