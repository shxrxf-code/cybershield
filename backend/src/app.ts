import express, { type Express } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import type { Container } from './container';
import { getLogger } from './utils/logger';
import { requestIdMiddleware } from './middleware/request-id';
import { requestLogger } from './middleware/request-logger';
import { apiKeyAuth } from './middleware/api-key-auth';
import { rateLimitMiddleware } from './middleware/rate-limit';
import { errorHandler, notFoundHandler } from './middleware/error-handler';
import { createApiRouter, createHealthRouter } from './routes';

/** Versioned API prefix shared by every private route. */
export const API_PREFIX = '/api/v1';

/** Default JSON body cap. Scans never upload file bytes, so 1 MiB is ample. */
export const DEFAULT_JSON_LIMIT = '1mb';

export interface CreateAppOptions {
  /** Cap JSON request bodies (e.g. '256kb'). Defaults to 1 MiB. */
  jsonLimit?: string;
}

/**
 * Build the Express application around a ready-made container.
 *
 * Middleware order matters:
 *   1. security & parsing (helmet, cors, json),
 *   2. request tracing & logging (request id, request logger),
 *   3. routes – `/api/v1/health` is public, everything else under `/api/v1`
 *      is authenticated and rate-limited,
 *   4. terminal handlers (404 → not found, then the error envelope).
 *
 * Tests build the app the same way production does (injecting an in-memory
 * database and stub providers), so the app tests exercise the real wiring.
 */
export function createApp(container: Container, options: CreateAppOptions = {}): Express {
  const logger = getLogger();
  const app = express();

  app.disable('x-powered-by');
  // Trust proxy only when explicitly configured – rate-limit keys are derived
  // from the peer address, so an attacker must not be able to spoof it by
  // sending `X-Forwarded-For` when no proxy is actually fronting the server.
  // See server.ts / the deployment docs for the reverse-proxy note.
  if (container.env.TRUST_PROXY) {
    app.set('trust proxy', container.env.TRUST_PROXY);
  }

  // Defense-in-depth HTTP response headers. There is no HTML to serve, so the
  // defaults (no CSP issues, nosniff, referrer policy, …) are appropriate.
  app.use(helmet());

  // CORS: the mobile app sends no `Origin`, so it is unaffected regardless.
  // The allow-list only matters if a browser front-end is ever mounted on this
  // API. With an empty list we reflect any origin; nothing here uses cookies,
  // and every private route requires the `X-API-Key` header, which browsers
  // never attach automatically.
  const allowedOrigins = container.env.CORS_ALLOWED_ORIGINS;
  app.use(cors({ origin: allowedOrigins.length > 0 ? allowedOrigins : true }));

  app.use(express.json({ limit: options.jsonLimit ?? DEFAULT_JSON_LIMIT }));

  app.use(requestIdMiddleware());
  app.use(requestLogger(logger));

  // Public liveness / readiness probe – no credentials required.
  app.use(`${API_PREFIX}/health`, createHealthRouter(container));

  // Authenticated surface. The API key gate runs first, then per-IP rate
  // limiting, then the routes themselves.
  app.use(
    API_PREFIX,
    apiKeyAuth(container.env),
    rateLimitMiddleware(container.env),
    createApiRouter(container),
  );

  // Nothing matched: 404, rendered through the same error envelope.
  app.use(notFoundHandler());
  app.use(errorHandler(logger));

  return app;
}