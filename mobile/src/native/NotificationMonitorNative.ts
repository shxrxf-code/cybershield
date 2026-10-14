/**
 * TypeScript bridge to the native Android `NotificationMonitor` module and its
 * `NotificationListenerService`.
 *
 * The Kotlin service is deliberately thin: it forwards the *exposed* text of a
 * notification (title/body/sub-text) plus the posting package, and nothing else.
 * It never opens other apps, never reads private storage and never stores the
 * message. All scam/phishing scoring happens in JS (`domain/notificationAnalyzer`)
 * so it can be unit-tested without a device.
 *
 * Everything here degrades safely when the native module or the platform is not
 * present (iOS, tests, older builds): helpers resolve to conservative defaults
 * and the listener subscribe call becomes a no-op.
 */

import { NativeEventEmitter, NativeModules, Platform } from 'react-native';

/** The notification fields the listener forwards. Never the full app data. */
export interface NotificationPayload {
  packageName: string;
  appLabel?: string;
  title?: string;
  text?: string;
  subText?: string;
  /** ISO timestamp supplied by the platform, when available. */
  postedAt?: string;
  /** Opaque platform key, used only for de-duplication. */
  key?: string;
}

/** A package the listener has observed posting a notification. */
export interface NotificationSource {
  packageName: string;
  appLabel: string;
  lastSeen: number;
}

interface NotificationMonitorNativeModule {
  isAccessGranted(): Promise<boolean>;
  isConnected(): Promise<boolean>;
  openNotificationSettings(): void;
  setMonitoringEnabled(enabled: boolean): Promise<boolean>;
  isMonitoringEnabled(): Promise<boolean>;
  getIgnoredPackages(): Promise<string[]>;
  setIgnoredPackages(packages: string[]): Promise<boolean>;
  getSeenSources(): Promise<NotificationSource[]>;
  clearSeenSources(): Promise<boolean>;
  hasNotificationPermission(): Promise<boolean>;
  postThreatAlert(title: string, body: string): Promise<boolean>;
  addListener(eventName: string): void;
  removeListeners(count: number): void;
  ENGINE_VERSION?: number;
}

const nativeModule = (NativeModules as Record<string, unknown>).NotificationMonitor as
  | NotificationMonitorNativeModule
  | undefined;

export const NOTIFICATION_RECEIVED_EVENT = 'ThreatGuardNotificationReceived';
export const NOTIFICATION_STATUS_EVENT = 'ThreatGuardNotificationStatus';

/** True when the native notification monitor is compiled into this build. */
export function isNotificationMonitorAvailable(): boolean {
  return Platform.OS === 'android' && nativeModule != null;
}

/** True when the user has granted notification access for this app. */
export async function isNotificationAccessGranted(): Promise<boolean> {
  if (!nativeModule) return false;
  try {
    return await nativeModule.isAccessGranted();
  } catch {
    return false;
  }
}

/** True when the OS has actually bound our listener service right now. */
export async function isNotificationListenerConnected(): Promise<boolean> {
  if (!nativeModule) return false;
  try {
    return await nativeModule.isConnected();
  } catch {
    return false;
  }
}

/** Opens Android's notification-access settings screen. */
export function openNotificationSettings(): void {
  nativeModule?.openNotificationSettings();
}

/** Mirrors the in-app preference so the service can honour it without JS. */
export async function setNativeMonitoringEnabled(enabled: boolean): Promise<void> {
  if (!nativeModule) return;
  try {
    await nativeModule.setMonitoringEnabled(enabled);
  } catch {
    // Best-effort: the JS preference remains the source of truth.
  }
}

/** The packages the user asked us to ignore. */
export async function getIgnoredPackages(): Promise<string[]> {
  if (!nativeModule) return [];
  try {
    const packages = await nativeModule.getIgnoredPackages();
    return Array.isArray(packages) ? packages : [];
  } catch {
    return [];
  }
}

/** Persists the ignore list so the service can filter without JS. */
export async function setIgnoredPackages(packages: string[]): Promise<void> {
  if (!nativeModule) return;
  try {
    await nativeModule.setIgnoredPackages(packages);
  } catch {
    // Best-effort mirror; JS keeps the authoritative copy in settings.
  }
}

/** Packages the listener has seen post a notification (for per-app toggles). */
export async function getNotificationSources(): Promise<NotificationSource[]> {
  if (!nativeModule) return [];
  try {
    const sources = await nativeModule.getSeenSources();
    return Array.isArray(sources) ? sources : [];
  } catch {
    return [];
  }
}

/** Forgets the observed-source list. */
export async function clearNotificationSources(): Promise<void> {
  if (!nativeModule) return;
  try {
    await nativeModule.clearSeenSources();
  } catch {
    // Best-effort.
  }
}

/** True when a local alert notification may be posted right now. */
export async function hasNotificationPermission(): Promise<boolean> {
  if (!nativeModule) return false;
  try {
    return await nativeModule.hasNotificationPermission();
  } catch {
    return false;
  }
}

/**
 * Posts one local alert notification. Resolves `false` (rather than throwing)
 * when the native module is absent or posting is not permitted, so the caller
 * can carry on regardless.
 */
export async function postThreatAlert(title: string, body: string): Promise<boolean> {
  if (!nativeModule) return false;
  try {
    return await nativeModule.postThreatAlert(title, body);
  } catch {
    return false;
  }
}

let emitter: NativeEventEmitter | null = null;

function getEmitter(): NativeEventEmitter | null {
  if (!nativeModule) return null;
  if (emitter == null) {
    emitter = new NativeEventEmitter(nativeModule as unknown as never);
  }
  return emitter;
}

/**
 * Subscribes to notifications that the OS exposed to the listener. Returns an
 * unsubscribe function; safe to call when the module is absent.
 */
export function addNotificationListener(
  listener: (payload: NotificationPayload) => void,
): () => void {
  const nativeEmitter = getEmitter();
  if (!nativeEmitter) return () => undefined;
  const subscription = nativeEmitter.addListener(NOTIFICATION_RECEIVED_EVENT, (payload: unknown) =>
    listener(payload as NotificationPayload),
  );
  return () => subscription.remove();
}

/**
 * Subscribes to listener connect/disconnect (access granted or revoked while the
 * app is running). Returns an unsubscribe function.
 */
export function addNotificationStatusListener(
  listener: (event: { connected: boolean; granted: boolean }) => void,
): () => void {
  const nativeEmitter = getEmitter();
  if (!nativeEmitter) return () => undefined;
  const subscription = nativeEmitter.addListener(NOTIFICATION_STATUS_EVENT, (payload: unknown) =>
    listener(payload as { connected: boolean; granted: boolean }),
  );
  return () => subscription.remove();
}
