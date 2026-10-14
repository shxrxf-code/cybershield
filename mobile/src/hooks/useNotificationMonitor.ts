/**
 * React view onto the notification monitoring runtime.
 *
 * The runtime (`notifications/monitor`) owns the subscriptions and the analysis;
 * this hook only mirrors its state into React and exposes the few actions the
 * screen needs. Reading through `useSyncExternalStore` keeps a single source of
 * truth and avoids duplicating listener bookkeeping.
 */

import { useCallback, useEffect, useSyncExternalStore } from 'react';
import { AppState, PermissionsAndroid, Platform } from 'react-native';
import {
  clearMonitoredSources,
  getMonitorState,
  refreshMonitorStatus,
  setPackageMonitored,
  startNotificationMonitor,
  subscribeMonitor,
  type MonitorState,
  type RecentFinding,
} from '../notifications/monitor';
import { type NotificationSource } from '../native/NotificationMonitorNative';
import { useSettingsStore } from '../store';
export interface UseNotificationMonitorReturn {
  state: MonitorState;
  monitoringEnabled: boolean;
  alertNotifications: boolean;
  /** Packages the user has muted. */
  ignoredPackages: string[];
  /** High/medium findings seen since the process started. */
  recent: RecentFinding[];
  sources: NotificationSource[];
  canPostNotifications: boolean;
  refresh: () => Promise<void>;
  clearSources: () => Promise<void>;
  setPackageMonitored: (packageName: string, monitored: boolean) => Promise<void>;
  requestNotificationPermission: () => Promise<boolean>;
}

const subscribe = (listener: () => void): (() => void) => subscribeMonitor(listener);

/** Ask for Android 13's notification permission; a no-op on older versions. */
export async function ensureNotificationPermission(): Promise<boolean> {
  if (Platform.OS !== 'android') return false;
  if (typeof Platform.Version === 'number' && Platform.Version < 33) return true;
  try {
    const result = await PermissionsAndroid.request(
      PermissionsAndroid.PERMISSIONS.POST_NOTIFICATIONS,
    );
    return result === PermissionsAndroid.RESULTS.GRANTED;
  } catch {
    return false;
  }
}

export function useNotificationMonitor(): UseNotificationMonitorReturn {
  const state = useSyncExternalStore(subscribe, getMonitorState, getMonitorState);
  const monitoringEnabled = useSettingsStore((s) => s.notificationMonitoring);
  const alertNotifications = useSettingsStore((s) => s.alertNotifications);
  const ignoredPackages = useSettingsStore((s) => s.notificationIgnoredPackages);

  useEffect(() => {
    startNotificationMonitor();
    void refreshMonitorStatus();
  }, []);

  // Re-check status when the app returns to the foreground: the user may have
  // just granted (or revoked) notification access in system settings.
  useEffect(() => {
    const subscription = AppState.addEventListener('change', (next) => {
      if (next === 'active') {
        void refreshMonitorStatus();
      }
    });
    return () => subscription.remove();
  }, []);

  const refresh = useCallback(async () => {
    await refreshMonitorStatus();
  }, []);

  const clearSources = useCallback(async () => {
    await clearMonitoredSources();
  }, []);

  const monitorPackage = useCallback(
    async (packageName: string, monitored: boolean) => {
      await setPackageMonitored(packageName, monitored);
    },
    [],
  );

  const requestNotificationPermission = useCallback(async () => {
    const granted = await ensureNotificationPermission();
    // Re-read native permission state so the UI reflects the real answer.
    await refreshMonitorStatus();
    return granted;
  }, []);

  return {
    state,
    monitoringEnabled,
    alertNotifications,
    ignoredPackages,
    recent: state.recent,
    sources: state.sources,
    canPostNotifications: state.canPostNotifications,
    refresh,
    clearSources,
    setPackageMonitored: monitorPackage,
    requestNotificationPermission,
  };
}
