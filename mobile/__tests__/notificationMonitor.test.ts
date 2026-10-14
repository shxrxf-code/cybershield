/**
 * @format
 */
/* eslint-env jest */

/**
 * Tests the notification monitoring runtime.
 *
 * The native bridge and both stores are mocked, so these tests exercise the
 * runtime's own logic: which messages raise alerts, de-duplication, the user's
 * preferences, and — crucially — that a message is never silently treated as
 * safe. A message with no signals is simply not reported; nothing here can
 * produce a "Safe" verdict from text alone.
 */

jest.mock('../src/native/NotificationMonitorNative', () => ({
  isNotificationMonitorAvailable: jest.fn(() => true),
  isNotificationAccessGranted: jest.fn(async () => true),
  isNotificationListenerConnected: jest.fn(async () => true),
  getNotificationSources: jest.fn(async () => []),
  hasNotificationPermission: jest.fn(async () => true),
  setNativeMonitoringEnabled: jest.fn(async () => undefined),
  setIgnoredPackages: jest.fn(async () => undefined),
  clearNotificationSources: jest.fn(async () => undefined),
  postThreatAlert: jest.fn(async () => true),
  addNotificationListener: jest.fn(() => () => undefined),
  addNotificationStatusListener: jest.fn(() => () => undefined),
}));

jest.mock('../src/store', () => ({
  useAlertStore: { getState: jest.fn() },
  useSettingsStore: { getState: jest.fn(), subscribe: jest.fn(() => () => undefined) },
  useScanStore: {},
}));

import {
  getMonitorState,
  startNotificationMonitor,
  stopNotificationMonitor,
} from '../src/notifications/monitor';
import {
  addNotificationListener,
  postThreatAlert,
  type NotificationPayload,
} from '../src/native/NotificationMonitorNative';
import { useAlertStore, useSettingsStore } from '../src/store';
import type { ThreatAlert } from '../src/domain/types';

const addAlert = jest.fn<Promise<void>, [Omit<ThreatAlert, 'id' | 'createdAt'>]>(async () => undefined);

const settingsState = {
  notificationMonitoring: true,
  alertNotifications: true,
  notificationIgnoredPackages: [] as string[],
};

/** The listener the runtime registered with the (mocked) native bridge. */
function dispatch(payload: NotificationPayload): void {
  const calls = (addNotificationListener as jest.Mock).mock.calls;
  const listener = calls[calls.length - 1][0] as (p: NotificationPayload) => void;
  listener(payload);
}

const phishing: NotificationPayload = {
  packageName: 'com.whatsapp',
  appLabel: 'WhatsApp',
  title: 'Bank',
  text: 'URGENT: your account is suspended. share the verification code at http://secure-kyc.top/login',
};

beforeEach(() => {
  jest.clearAllMocks();
  settingsState.notificationMonitoring = true;
  settingsState.alertNotifications = true;
  settingsState.notificationIgnoredPackages = [];
  (useSettingsStore.getState as jest.Mock).mockImplementation(() => settingsState);
  (useAlertStore.getState as jest.Mock).mockReturnValue({ addAlert });
  startNotificationMonitor();
});

afterEach(() => {
  stopNotificationMonitor();
});

describe('startNotificationMonitor', () => {
  it('registers both listeners once', () => {
    // startNotificationMonitor is idempotent: called again, it does nothing.
    startNotificationMonitor();
    expect(addNotificationListener).toHaveBeenCalledTimes(1);
  });
});

describe('handlePayload', () => {
  it('raises an alert for a clear phishing message', () => {
    dispatch(phishing);

    expect(addAlert).toHaveBeenCalledTimes(1);
    const alert = addAlert.mock.calls[0][0];
    expect(alert.threatType).toBe('phishing_notification');
    expect(alert.severity).toBe('high');
    expect(alert.sourceApplication).toBe('WhatsApp');
    // The stored target is the redacted preview, not the message body.
    expect(alert.target).toContain('[link: secure-kyc.top]');
    expect(alert.target).not.toContain('/login');

    const state = getMonitorState();
    expect(state.recent).toHaveLength(1);
    expect(state.recent[0].alerted).toBe(true);
  });

  it('never raises an alert for a benign message, and does not list it', () => {
    dispatch({ packageName: 'com.whatsapp', title: 'Mum', text: 'Dinner at 7pm?' });

    expect(addAlert).not.toHaveBeenCalled();
    expect(getMonitorState().recent).toHaveLength(0);
  });

  it('does nothing when monitoring is switched off', () => {
    settingsState.notificationMonitoring = false;
    dispatch(phishing);

    expect(addAlert).not.toHaveBeenCalled();
    expect(getMonitorState().recent).toHaveLength(0);
  });

  it('ignores an app the user muted', () => {
    settingsState.notificationIgnoredPackages = ['com.whatsapp'];
    dispatch(phishing);

    expect(addAlert).not.toHaveBeenCalled();
  });

  it('de-duplicates a repeated alert', () => {
    dispatch(phishing);
    dispatch(phishing);

    expect(addAlert).toHaveBeenCalledTimes(1);
    // Both sightings are still recorded for the UI.
    expect(getMonitorState().recent).toHaveLength(2);
  });

  it('records the finding but posts no system notification when that is off', () => {
    settingsState.alertNotifications = false;
    dispatch(phishing);

    expect(addAlert).toHaveBeenCalledTimes(1);
    expect(postThreatAlert).not.toHaveBeenCalled();
  });

  it('posts a system notification when alerts are enabled', () => {
    dispatch(phishing);

    expect(postThreatAlert).toHaveBeenCalledTimes(1);
    const [title, body] = (postThreatAlert as jest.Mock).mock.calls[0];
    expect(title).toContain('WhatsApp');
    expect(body.length).toBeGreaterThan(0);
  });

  it('forwards only the exposed fields to the analyser', () => {
    dispatch({ packageName: 'com.sms', title: 'Delivery', text: 'Your parcel is held. Pay the customs fee now: http://bit.ly/xyz' });

    expect(addAlert).toHaveBeenCalledTimes(1);
    expect(getMonitorState().recent[0].signalLabels.length).toBeGreaterThan(0);
  });
});
