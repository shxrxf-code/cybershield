import { create } from 'zustand';
import { alertRepository } from '../db/alertRepository';
import type { ThreatAlert } from '../domain/types';

/**
 * Alerts backed by the local SQLite database.
 */

export interface AlertState {
  alerts: ThreatAlert[];
  loading: boolean;
  error: string | null;

  addAlert: (alert: ThreatAlert) => Promise<void>;
  markRead: (id: string) => Promise<void>;
  markUnread: (id: string) => Promise<void>;
  markAllRead: () => Promise<void>;
  removeAlert: (id: string) => Promise<void>;
  clear: () => Promise<void>;

  getById: (id: string) => ThreatAlert | undefined;
  unreadCount: () => number;
  refresh: () => Promise<void>;
}

export const useAlertStore = create<AlertState>((set, get) => ({
  alerts: [],
  loading: false,
  error: null,

  addAlert: async (alert) => {
    try {
      const created = await alertRepository.create(alert);
      set((state) => ({ alerts: [created, ...state.alerts.filter((a) => a.id !== created.id)] }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to add alert' });
      throw err;
    }
  },

  markRead: async (id) => {
    try {
      await alertRepository.markRead(id);
      set((state) => ({ alerts: state.alerts.map((a) => (a.id === id ? { ...a, isRead: true } : a)) }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to mark alert read' });
      throw err;
    }
  },

  markUnread: async (id) => {
    try {
      await alertRepository.markUnread(id);
      set((state) => ({ alerts: state.alerts.map((a) => (a.id === id ? { ...a, isRead: false } : a)) }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to mark alert unread' });
      throw err;
    }
  },

  markAllRead: async () => {
    try {
      await alertRepository.markAllRead();
      set((state) => ({ alerts: state.alerts.map((a) => ({ ...a, isRead: true })) }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to mark all alerts read' });
      throw err;
    }
  },

  removeAlert: async (id) => {
    try {
      await alertRepository.delete(id);
      set((state) => ({ alerts: state.alerts.filter((a) => a.id !== id) }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to remove alert' });
      throw err;
    }
  },

  clear: async () => {
    try {
      await alertRepository.deleteAll();
      set({ alerts: [] });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to clear alerts' });
      throw err;
    }
  },

  getById: (id) => get().alerts.find((a) => a.id === id),

  unreadCount: () => get().alerts.filter((a) => !a.isRead).length,

  refresh: async () => {
    set({ loading: true, error: null });
    try {
      const alerts = await alertRepository.findRecent(200);
      set({ alerts, loading: false });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to load alerts', loading: false });
    }
  },
}));