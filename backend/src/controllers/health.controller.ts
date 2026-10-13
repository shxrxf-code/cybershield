import type { Request, Response } from 'express';
import type { Container } from '../container';
import { describeProviders } from '../container';

const STARTED_AT = Date.now();

/**
 * Liveness / readiness probe.
 *
 * It reports "unhealthy" (HTTP 503) when the database cannot be queried rather
 * than a fabricated green status. Provider entries describe *configuration*
 * only – never whether a provider currently has a key value.
 */
export function createHealthController(container: Container) {
  return {
    health: async (_req: Request, res: Response): Promise<void> => {
      const dbStarted = Date.now();
      let databaseOk = true;
      try {
        await container.db.query('SELECT 1 AS ok');
      } catch {
        databaseOk = false;
      }

      const payload = {
        status: databaseOk ? 'ok' : 'unhealthy',
        version: '0.1.0',
        environment: container.env.NODE_ENV,
        uptime_seconds: Math.round((Date.now() - STARTED_AT) / 1000),
        database: {
          client: container.db.dialect,
          ok: databaseOk,
          latency_ms: Date.now() - dbStarted,
        },
        intel_enabled: container.env.INTEL_ENABLED,
        providers: describeProviders(container),
      };

      res.status(databaseOk ? 200 : 503).json(payload);
    },
  };
}
