import type { RequestHandler } from 'express';
import type { Logger } from 'pino';

/**
 * Request logging.
 *
 * Logs method, path, status and duration only. The path is the *original*
 * request path with the query string stripped: Express rewrites `req.path`
 * inside mounted routers (so it would read `/scans/url` instead of the full
 * `/api/v1/scans/url`), and the query string can carry user search terms we
 * must not persist.
 */
export function requestLogger(logger: Logger): RequestHandler {
  return (req, res, next) => {
    const started = Date.now();
    res.on('finish', () => {
      const context = {
        requestId: req.requestId,
        method: req.method,
        path: req.originalUrl.split('?')[0] ?? req.originalUrl,
        status: res.statusCode,
        durationMs: Date.now() - started,
      };
      if (res.statusCode >= 500) logger.error(context, 'http request');
      else if (res.statusCode >= 400) logger.warn(context, 'http request');
      else logger.info(context, 'http request');
    });
    next();
  };
}
