/**
 * The notification monitoring runtime.
 *
 * This is a small, headless singleton that runs for the lifetime of the app
 * process (started once from the app root). It is deliberately *not* a React
 * hook: notifications must be analysed whenever the process is alive, not only
 * while a particular screen is mounted. A thin React hook
 * (`hooks/useNotificationMonitor`) subscribes to it for display.
 *
 * What it does with each notification the listener forwards:
 *   1. re-checks the user's preferences (monitoring on? app muted?),
 *   2. scores the text with the pure analyser in `domain/notificationAnalyzer`,
 *   3. records a content-free finding (signal labels only) for the UI,
 *   4. raises an in-app alert for medium/high findings, de-duplicated, and posts
 *      a local system notification when the user asked for one.
 *
 * Nothing here persists message text. The most that is kept is a de-duplication
 * timestamp and the derived signal labels.
 */

import {
  addNotificationListener,
  addNotificationStatusListener,
  clearNotificationSources,
  getNotificationSources,
  hasNotificationPermission,
  isNotificationAccessGranted,
  isNotificationListenerConnected,
  isNotificationMonitorAvailable,
  postThreatAlert,
  setIgnoredPackages,
  setNativeMonitoringEnabled,
  type NotificationPayload,
  type NotificationSource,
} from '../native';
import {
  analyzeNotification,
  buildNotificationAlert,
  shouldAlert,
  type NotificationAnalysis,
} from '../domain';
import type { Severity, ThreatCategory } from '../domain/types';
import { useAlertStore, useSettingsStore } from '../store';

/** A content-free summary of an analysed message, for the UI. */
export interface RecentFinding {
  id: string;
  at: string;
  packageName: string;
  appLabel: string;
  score: number;
  severity: Severity;
  category: ThreatCategory;
  /** True when this finding was strong enough to raise an alert. */
  alerted: boolean;
  /** Human-readable signal labels (our own words, never the message text). */
  signalLabels: string[];
}

export interface MonitorState {
  /** Whether the native listener is compiled into this build. */
  available: boolean;
  /** Whether the user has granted notification access in Android settings. */
  accessGranted: boolean;
  /** Whether the OS currently has the listener bound. */
  connected: boolean;
  /** Whether a local alert notification may be posted right now. */
  canPostNotifications: boolean;
  /** Packages observed posting notifications (for per-app toggles). */
  sources: NotificationSource[];
  /** The most recent messages that showed at least one signal. */
  recent: RecentFinding[];
}

const MAX_RECENT = 20;
/** Ignore a repeat of the same (app, content) alert within this window. */
const DEDUPE_WINDOW_MS = 10 * 60 * 1000;

const EMPTY_STATE: MonitorState = {
  available: false,
  accessGranted: false,
  connected: false,
  canPostNotifications: false,
  sources: [],
  recent: [],
};

let state: MonitorState = EMPTY_STATE;
const listeners = new Set<(state: MonitorState) => void>();
const recentAlertKeys = new Map<string, number>();

let started = false;
let cleanups: Array<() => void> = [];

function update(patch: Partial<MonitorState>): void {
  state = { ...state, ...patch };
  for (const listener of listeners) {
    listener(state);
  }
}

/** A snapshot of the current monitor state. */
export function getMonitorState(): MonitorState {
  return state;
}

/** Subscribes to monitor state changes. Returns an unsubscribe function. */
export function subscribeMonitor(listener: (state: MonitorState) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function addRecent(finding: RecentFinding): void {
  update({ recent: [finding, ...state.recent].slice(0, MAX_RECENT) });
}

function isDuplicateAlert(packageName: string, contentHash: string): boolean {
  const key = `${packageName}:${contentHash}`;
  const now = Date.now();
  for (const [existing, at] of recentAlertKeys) {
    if (now - at > DEDUPE_WINDOW_MS) {
      recentAlertKeys.delete(existing);
    }
  }
  const last = recentAlertKeys.get(key);
  if (last != null && now - last < DEDUPE_WINDOW_MS) {
    return true;
  }
  recentAlertKeys.set(key, now);
  return false;
}

function handlePayload(payload: NotificationPayload): void {
  const settings = useSettingsStore.getState();
  // Defensive re-check: the native service already filters, but preferences may
  // have changed while the app was running.
  if (!settings.notificationMonitoring) return;
  if (settings.notificationIgnoredPackages.includes(payload.packageName)) return;

  const analysis: NotificationAnalysis = analyzeNotification({
    packageName: payload.packageName,
    appLabel: payload.appLabel,
    title: payload.title,
    text: payload.text,
    subText: payload.subText,
    postedAt: payload.postedAt,
    key: payload.key,
  });

  if (analysis.score <= 0) return;

  const alerted = shouldAlert(analysis);
  addRecent({
    id: `${payload.packageName}:${analysis.contentHash}:${Date.now()}`,
    at: payload.postedAt ?? new Date().toISOString(),
    packageName: payload.packageName,
    appLabel: payload.appLabel ?? payload.packageName,
    score: analysis.score,
    severity: analysis.severity,
    category: analysis.category,
    alerted,
    signalLabels: analysis.signals.map((signal) => signal.label),
  });

  if (!alerted) return;
  if (isDuplicateAlert(payload.packageName, analysis.contentHash)) return;

  const alert = buildNotificationAlert(
    { packageName: payload.packageName, appLabel: payload.appLabel, postedAt: payload.postedAt },
    analysis,
  );

  void useAlertStore
    .getState()
    .addAlert(alert)
    .catch(() => undefined);

  if (settings.alertNotifications) {
    const source = payload.appLabel ?? payload.packageName;
    const title = analysis.severity === 'high' ? 'Suspicious message blocked' : 'Suspicious message detected';
    void postThreatAlert(`${title} — ${source}`, analysis.recommendedAction);
  }
}

/** Re-reads access/connection state and the observed-source list. */
export async function refreshMonitorStatus(): Promise<void> {
  if (!isNotificationMonitorAvailable()) {
    update({ available: false });
    return;
  }
  const accessGranted = await isNotificationAccessGranted();
  const connected = accessGranted ? await isNotificationListenerConnected() : false;
  const sources = await getNotificationSources();
  const canPostNotifications = await hasNotificationPermission();
  update({ available: true, accessGranted, connected, canPostNotifications, sources });
}

/** Clears the observed-source list (used by the per-app toggle screen). */
export async function clearMonitoredSources(): Promise<void> {
  await clearNotificationSources();
  update({ sources: [] });
}

function syncNativeMirrors(): void {
  const settings = useSettingsStore.getState();
  void setNativeMonitoringEnabled(settings.notificationMonitoring);
  void setIgnoredPackages(settings.notificationIgnoredPackages);
}

/**
 * Starts the monitor. Safe to call more than once — later calls are ignored.
 * Returns a stop function (used by tests).
 */
export function startNotificationMonitor(): () => void {
  if (started) {
    return stopNotificationMonitor;
  }
  started = true;
  update({ available: isNotificationMonitorAvailable() });

  if (!isNotificationMonitorAvailable()) {
    return stopNotificationMonitor;
  }

  cleanups.push(addNotificationListener(handlePayload));
  cleanups.push(
    addNotificationStatusListener((event) => {
      update({ connected: event.connected, accessGranted: event.granted });
      if (event.connected) {
        void refreshMonitorStatus();
      }
    }),
  );

  // Keep the native mirrors in step with the persisted preferences, no matter
  // which screen changed them.
  const unsubscribe = useSettingsStore.subscribe((next, previous) => {
    if (next.notificationMonitoring !== previous.notificationMonitoring) {
      void setNativeMonitoringEnabled(next.notificationMonitoring);
      if (next.notificationMonitoring) {
        void refreshMonitorStatus();
      }
    }
    if (next.notificationIgnoredPackages !== previous.notificationIgnoredPackages) {
      void setIgnoredPackages(next.notificationIgnoredPackages);
    }
  });
  cleanups.push(unsubscribe);

  syncNativeMirrors();
  void refreshMonitorStatus();

  return stopNotificationMonitor;
}

/**
 * Stops the monitor, releases its subscriptions and clears the in-memory
 * findings. Called when the app process is torn down (and between tests), so
 * stale findings never outlive the listener that produced them.
 */
export function stopNotificationMonitor(): void {
  for (const cleanup of cleanups) {
    cleanup();
  }
  cleanups = [];
  started = false;
  recentAlertKeys.clear();
  state = EMPTY_STATE;
}

/** Records that a package should (or should not) be monitored. */
export async function setPackageMonitored(
  packageName: string,
  monitored: boolean,
): Promise<void> {
  const current = useSettingsStore.getState().notificationIgnoredPackages;
  const next = monitored
    ? current.filter((pkg) => pkg !== packageName)
    : Array.from(new Set([...current, packageName]));
  await useSettingsStore.getState().setNotificationIgnoredPackages(next);
}
