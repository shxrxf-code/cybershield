import { create } from 'zustand';
import type { PrivacyPreferences, SecuritySettings } from '../domain/types';
import type { ColorScheme } from '../theme/tokens';

/**
 * User security preferences and appearance.
 *
 * Defaults are privacy-first: notification monitoring and background protection
 * stay OFF until the user explicitly grants permission, and hash lookups are
 * opt-in. Phase 2 persists these; the defaults are applied until then.
 */
export interface SettingsState extends SecuritySettings {
  /** `undefined` follows the device colour scheme. */
  colorScheme?: ColorScheme;
  setNotificationMonitoring: (value: boolean) => void;
  setBackgroundProtection: (value: boolean) => void;
  setAlertNotifications: (value: boolean) => void;
  setPrivacyPreference: <K extends keyof PrivacyPreferences>(key: K, value: PrivacyPreferences[K]) => void;
  setColorScheme: (scheme: ColorScheme | undefined) => void;
  reset: () => void;
}

const DEFAULT_PRIVACY: PrivacyPreferences = {
  analyzeNotificationsLocally: true,
  storeNotificationBodies: false,
  allowHashLookups: false,
};

const DEFAULTS: SecuritySettings = {
  notificationMonitoring: false,
  backgroundProtection: false,
  alertNotifications: true,
  privacyPreferences: DEFAULT_PRIVACY,
};

export const useSettingsStore = create<SettingsState>((set) => ({
  ...DEFAULTS,
  colorScheme: undefined,
  setNotificationMonitoring: (value) => set({ notificationMonitoring: value }),
  setBackgroundProtection: (value) => set({ backgroundProtection: value }),
  setAlertNotifications: (value) => set({ alertNotifications: value }),
  setPrivacyPreference: (key, value) =>
    set((state) => ({
      privacyPreferences: { ...state.privacyPreferences, [key]: value },
    })),
  setColorScheme: (scheme) => set({ colorScheme: scheme }),
  reset: () => set({ ...DEFAULTS, colorScheme: undefined }),
}));
