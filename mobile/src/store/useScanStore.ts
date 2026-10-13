import { create } from 'zustand';
import type { ScanRecord, Severity } from '../domain/types';

/**
 * In-memory scan history.
 *
 * This is the view-layer store. Phase 2 (local data layer) will back it with a
 * repository so records survive restarts; the shape here is deliberately the
 * same so the switch is transparent to screens. It starts empty — no seed data
 * is ever injected.
 */
export interface ScanState {
  records: ScanRecord[];
  addRecord: (record: ScanRecord) => void;
  removeRecord: (id: string) => void;
  clear: () => void;
  getById: (id: string) => ScanRecord | undefined;
}

export const useScanStore = create<ScanState>((set, get) => ({
  records: [],
  addRecord: (record) =>
    set((state) => ({ records: [record, ...state.records.filter((r) => r.id !== record.id)] })),
  removeRecord: (id) => set((state) => ({ records: state.records.filter((r) => r.id !== id) })),
  clear: () => set({ records: [] }),
  getById: (id) => get().records.find((r) => r.id === id),
}));

export interface DashboardTotals {
  totalScans: number;
  totalThreats: number;
  alertsBySeverity: Partial<Record<Severity, number>>;
}

/** Derive dashboard totals from the real record set. */
export function selectScanTotals(records: ScanRecord[]): DashboardTotals {
  const alertsBySeverity: Partial<Record<Severity, number>> = {};
  let totalThreats = 0;
  for (const record of records) {
    if (record.threatsFound > 0) {
      totalThreats += record.threatsFound;
      alertsBySeverity[record.threatLevel] = (alertsBySeverity[record.threatLevel] ?? 0) + record.threatsFound;
    }
  }
  return { totalScans: records.length, totalThreats, alertsBySeverity };
}
