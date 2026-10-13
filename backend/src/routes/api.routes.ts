import { Router } from 'express';
import type { Container } from '../container';
import { validate } from '../middleware/validate';
import { idParamSchema } from '../validators/common';
import { urlScanSchema, urlBatchScanSchema } from '../validators/url.validator';
import { fileScanSchema } from '../validators/file.validator';
import { notificationAnalysisSchema } from '../validators/notification.validator';
import { scanListQuerySchema, alertListQuerySchema, settingsPatchSchema } from '../validators/list.validator';
import { createUrlController } from '../controllers/url.controller';
import { createFileController } from '../controllers/file.controller';
import { createNotificationController } from '../controllers/notification.controller';
import { createHistoryController } from '../controllers/history.controller';
import { createAlertController } from '../controllers/alert.controller';
import { createPreferencesController } from '../controllers/preferences.controller';

/**
 * The authenticated API surface (mounted at /api/v1).
 *
 * Route order matters: literal paths such as `/scans/dashboard` are registered
 * before the parameterised `/scans/:id`.
 */
export function createApiRouter(container: Container): Router {
  const router = Router();
  const url = createUrlController(container);
  const file = createFileController(container);
  const notification = createNotificationController(container);
  const history = createHistoryController(container);
  const alerts = createAlertController(container);
  const preferences = createPreferencesController(container);

  // --- URL reputation ------------------------------------------------------
  router.post('/scans/url', validate(urlScanSchema), url.scan);
  router.post('/scans/url/batch', validate(urlBatchScanSchema), url.scanBatch);

  // --- File analysis -------------------------------------------------------
  router.post('/scans/file', validate(fileScanSchema), file.scan);

  // --- Notification analysis ----------------------------------------------
  router.post('/scans/notification', validate(notificationAnalysisSchema), notification.analyze);

  // --- Scan history & dashboard -------------------------------------------
  router.get('/scans/dashboard', history.dashboard);
  router.get('/scans', validate(scanListQuerySchema, 'query'), history.list);
  router.delete('/scans', history.clear);
  router.get('/scans/:id', validate(idParamSchema, 'params'), history.getById);

  // --- Alerts --------------------------------------------------------------
  router.get('/alerts', validate(alertListQuerySchema, 'query'), alerts.list);
  router.post('/alerts/read-all', alerts.markAllRead);
  router.post('/alerts/:id/read', validate(idParamSchema, 'params'), alerts.markRead);
  router.delete('/alerts', alerts.clear);

  // --- Preferences ---------------------------------------------------------
  router.get('/preferences', preferences.get);
  router.patch('/preferences', validate(settingsPatchSchema), preferences.update);

  return router;
}
