import type { Request, Response } from 'express';
import type { Container } from '../container';
import { validated } from '../middleware/validate';
import { scanListQuerySchema, type ScanListQuery } from '../validators/list.validator';
import { presentScanRecord, presentAlertRecord } from './dto';
import { NotFoundError } from '../utils/errors';

/** Scan history: list, detail, clear, and the dashboard aggregate. */
export function createHistoryController(container: Container) {
  const { scans, alerts } = container.repositories;

  return {
    list: async (req: Request, res: Response): Promise<void> => {
      const query = validated<ScanListQuery>(req, 'query');
      const { items, total } = await scans.list({
        limit: query.limit,
        offset: query.offset,
        scanType: query.scanType,
        threatLevel: query.threatLevel,
        search: query.search,
      });
      res.status(200).json({
        items: items.map(presentScanRecord),
        total,
        limit: query.limit ?? 50,
        offset: query.offset ?? 0,
      });
    },

    getById: async (req: Request, res: Response): Promise<void> => {
      const { id } = validated<{ id: string }>(req, 'params');
      const record = await scans.getById(id);
      if (!record) throw new NotFoundError('Scan not found');
      res.status(200).json(presentScanRecord(record));
    },

    clear: async (_req: Request, res: Response): Promise<void> => {
      const removed = await scans.clear();
      res.status(200).json({ removed });
    },

    dashboard: async (_req: Request, res: Response): Promise<void> => {
      const summary = await container.services.scanHistory.dashboardSummary();
      const latest = await container.services.scanHistory.latest(5);
      const recentAlerts = await alerts.list({ limit: 5 });

      res.status(200).json({
        totals: {
          total_scans: summary.totalScans,
          total_threats: summary.totalThreats,
          unread_alerts: summary.unreadAlerts,
          alerts_by_severity: summary.alertsBySeverity,
        },
        last_scan_at: summary.lastScanAt ?? null,
        recent_scans: latest.map(presentScanRecord),
        recent_alerts: recentAlerts.items.map(presentAlertRecord),
      });
    },
  };
}
