import { create } from 'zustand';
import { scanRepository, createScanFromAPI } from '../db/scanRepository';
import type { ScanRecord, VerdictStatus } from '../domain/types';

/**
 * Scan history backed by the local SQLite database.
 */

export interface ScanState {
  records: ScanRecord[];
  loading: boolean;
  error: string | null;

  addRecord: (record: ScanRecord) => Promise<void>;
  removeRecord: (id: string) => Promise<void>;
  clear: () => Promise<void>;

  getById: (id: string) => ScanRecord | undefined;
  refresh: () => Promise<void>;

  createFromAPI: (data: Parameters<typeof createScanFromAPI>[0]) => Promise<ScanRecord>;
}

export const useScanStore = create<ScanState>((set, get) => ({
  records: [],
  loading: false,
  error: null,

  addRecord: async (record) => {
    try {
      const created = await scanRepository.create(record);
      set((state) => ({ records: [created, ...state.records.filter((r) => r.id !== created.id)] }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to add scan record' });
      throw err;
    }
  },

  removeRecord: async (id) => {
    try {
      await scanRepository.delete(id);
      set((state) => ({ records: state.records.filter((r) => r.id !== id) }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to remove scan record' });
      throw err;
    }
  },

  clear: async () => {
    try {
      await scanRepository.deleteAll();
      set({ records: [] });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to clear scan records' });
      throw err;
    }
  },

  getById: (id) => get().records.find((r) => r.id === id),

  refresh: async () => {
    set({ loading: true, error: null });
    try {
      const records = await scanRepository.findRecent(200);
      set({ records, loading: false });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to load scans', loading: false });
    }
  },

  createFromAPI: async (data) => {
    const record = await createScanFromAPI(data);
    set((state) => ({ records: [record, ...state.records.filter((r) => r.id !== record.id)] }));
    return record;
  },
}));

/**
 * Selector for dashboard totals (same as before, works with persisted records).
 */
export interface DashboardTotals {
  totalScans: number;
  totalThreats: number;
  alertsBySeverity: Partial<Record<VerdictStatus, number>>;
}

export function selectScanTotals(records: ScanRecord[]): DashboardTotals {
  const alertsBySeverity: Partial<Record<VerdictStatus, number>> = {};
  let totalThreats = 0;
  for (const record of records) {
    if (record.threatsFound > 0) {
      totalThreats += record.threatsFound;
      alertsBySeverity[record.threatLevel] = (alertsBySeverity[record.threatLevel] ?? 0) + record.threatsFound;
    }
  }
  return { totalScans: records.length, totalThreats, alertsBySeverity };
}