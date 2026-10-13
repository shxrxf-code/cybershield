import { create } from 'zustand';
import type { ThreatAlert } from '../domain/types';

/**
 * In-memory alerts store. Phase 2 will persist alerts and Phase 7 will push new
 * ones from the notification listener; the surface here stays the same.
 */
export interface AlertState {
  alerts: ThreatAlert[];
  addAlert: (alert: ThreatAlert) => void;
  markRead: (id: string) => void;
  markUnread: (id: string) => void;
  markAllRead: () => void;
  removeAlert: (id: string) => void;
  clear: () => void;
  unreadCount: () => number;
  getById: (id: string) => ThreatAlert | undefined;
}

export const useAlertStore = create<AlertState>((set, get) => ({
  alerts: [],
  addAlert: (alert) =>
    set((state) => ({ alerts: [alert, ...state.alerts.filter((a) => a.id !== alert.id)] })),
  markRead: (id) =>
    set((state) => ({
      alerts: state.alerts.map((a) => (a.id === id ? { ...a, isRead: true } : a)),
    })),
  markUnread: (id) =>
    set((state) => ({
      alerts: state.alerts.map((a) => (a.id === id ? { ...a, isRead: false } : a)),
    })),
  markAllRead: () => set((state) => ({ alerts: state.alerts.map((a) => ({ ...a, isRead: true })) })),
  removeAlert: (id) => set((state) => ({ alerts: state.alerts.filter((a) => a.id !== id) })),
  clear: () => set({ alerts: [] }),
  unreadCount: () => get().alerts.filter((a) => !a.isRead).length,
  getById: (id) => get().alerts.find((a) => a.id === id),
}));
