import type { NavigatorScreenParams } from '@react-navigation/native';

/**
 * The single source of truth for navigation. Typing params here means
 * `navigation.navigate('AlertDetail', { alertId })` is checked at compile time
 * and every screen gets an accurate `useRoute()` type.
 */

export type MainTabParamList = {
  Dashboard: undefined;
  Protection: undefined;
  Alerts: undefined;
  History: undefined;
  Settings: undefined;
};

export type RootStackParamList = {
  Onboarding: undefined;
  MainTabs: NavigatorScreenParams<MainTabParamList> | undefined;
  /** Runs an on-device scan; `mode` selects quick vs full coverage. */
  DeviceScan: { mode: 'quick' | 'full' };
  UrlScanner: { initialUrl?: string } | undefined;
  FileScanner: undefined;
  AppScanner: undefined;
  NotificationProtection: undefined;
  AlertDetail: { alertId: string };
  ScanDetail: { scanId: string };
  Report: undefined;
  Permissions: undefined;
  About: undefined;
};

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace ReactNavigation {
    interface RootParamList extends RootStackParamList {}
  }
}
