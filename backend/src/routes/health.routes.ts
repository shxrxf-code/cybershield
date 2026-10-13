import { Router } from 'express';
import type { Container } from '../container';
import { createHealthController } from '../controllers/health.controller';

/** Public health probe – intentionally not API-key protected. */
export function createHealthRouter(container: Container): Router {
  const router = Router();
  const controller = createHealthController(container);
  router.get('/', controller.health);
  return router;
}
