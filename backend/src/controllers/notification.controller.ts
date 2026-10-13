import type { Request, Response } from 'express';
import type { Container } from '../container';
import { validated } from '../middleware/validate';
import type { NotificationAnalysisRequest } from '../validators/notification.validator';
import { presentNotificationScan } from './dto';

/**
 * Notification / message analysis endpoint.
 *
 * PRIVACY: the submitted text is analysed in memory and is never written to the
 * database. Only the derived signals, the verdict and (optionally) a URL domain
 * are persisted by the history service.
 */
export function createNotificationController(container: Container) {
  return {
    analyze: async (req: Request, res: Response): Promise<void> => {
      const body = validated<NotificationAnalysisRequest>(req, 'body');

      const outcome = await container.services.notificationAnalysis.analyze({
        text: body.text,
        title: body.title,
        sourceApp: body.sourceApp,
        packageName: body.packageName,
      });

      const recorded = await container.services.scanHistory.recordNotificationScan(
        outcome,
        { sourceApp: body.sourceApp, sourcePackage: body.packageName },
        { source: 'notification-listener' },
      );

      res.status(200).json(
        presentNotificationScan(outcome, recorded, {
          sourceApp: body.sourceApp,
          packageName: body.packageName,
        }),
      );
    },
  };
}
