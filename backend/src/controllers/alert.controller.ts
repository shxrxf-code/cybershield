import type { Request, Response } from 'express';
import type { Container } from '../container';
import { validated } from '../middleware/validate';
import { alertListQuerySchema, type AlertListQuery } from '../validators/list.validator';
import { presentAlertRecord } from './dto';
import { NotFoundError } from '../utils/errors';

/** Threat alerts: list, mark read, clear. */
export function createAlertController(container: Container) {
  const { alerts } = container.repositories;

  return {
    list: async (req: Request, res: Response): Promise<void> => {
      const query = validated<AlertListQuery>(req, 'query');
      const { items, total } = await alerts.list({
        limit: query.limit,
        offset: query.offset,
        severity: query.severity,
        unreadOnly: query.unreadOnly,
        search: query.search,
      });
      res.status(200).json({
        items: items.map(presentAlertRecord),
        total,
        unread: await alerts.unreadCount(),
        limit: query.limit ?? 50,
        offset: query.offset ?? 0,
      });
    },

    markRead: async (req: Request, res: Response): Promise<void> => {
      const { id } = validated<{ id: string }>(req, 'params');
      const updated = await alerts.markRead(id, true);
      if (!updated) throw new NotFoundError('Alert not found');
      res.status(200).json({ id, is_read: true });
    },

    markAllRead: async (_req: Request, res: Response): Promise<void> => {
      const updated = await alerts.markAllRead();
      res.status(200).json({ updated });
    },

    clear: async (_req: Request, res: Response): Promise<void> => {
      const removed = await alerts.clear();
      res.status(200).json({ removed });
    },
  };
}
