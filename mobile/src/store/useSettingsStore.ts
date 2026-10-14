import { create } from 'zustand';
import { settingsRepository, initSettings } from '../db/settingsRepository';
import type { PrivacyPreferences, SecuritySettings } from '../domain/types';
import type { ColorScheme } from '../theme/tokens';

/**
 * User security preferences and appearance, persisted to SQLite.
 */
type StoredColorScheme = ColorScheme | 'system' | undefined;

/**
 * User security preferences and appearance, persisted to SQLite.
 */

export interface SettingsState extends SecuritySettings {
  /** `undefined` follows the device colour scheme. */
  colorScheme?: StoredColorScheme;
  /** Whether the first-run introduction has been completed. */
  onboardingComplete: boolean;
  loading: boolean;
  error: string | null;

  setNotificationMonitoring: (value: boolean) => Promise<void>;
  setBackgroundProtection: (value: boolean) => Promise<void>;
  setAlertNotifications: (value: boolean) => Promise<void>;
  setNotificationIgnoredPackages: (packages: string[]) => Promise<void>;
  setPrivacyPreference: <K extends keyof PrivacyPreferences>(key: K, value: PrivacyPreferences[K]) => Promise<void>;
  setColorScheme: (scheme: StoredColorScheme) => Promise<void>;
  completeOnboarding: () => Promise<void>;
  reset: () => Promise<void>;
  refresh: () => Promise<void>;
}

const DEFAULT_PRIVACY: PrivacyPreferences = {
  analytics: false,
  crashReporting: false,
  shareThreatData: false,
};

const DEFAULTS: SecuritySettings = {
  notificationMonitoring: false,
  backgroundProtection: false,
  alertNotifications: true,
  notificationIgnoredPackages: [],
  privacyPreferences: DEFAULT_PRIVACY,
};

export const useSettingsStore = create<SettingsState>((set, get) => ({
  ...DEFAULTS,
  colorScheme: undefined,
  onboardingComplete: false,
  loading: false,
  error: null,

  setNotificationMonitoring: async (value) => {
    try {
      await settingsRepository.set('notificationMonitoring', value);
      set({ notificationMonitoring: value });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to save setting' });
      throw err;
    }
  },

  setBackgroundProtection: async (value) => {
    try {
      await settingsRepository.set('backgroundProtection', value);
      set({ backgroundProtection: value });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to save setting' });
      throw err;
    }
  },

  setAlertNotifications: async (value) => {
    try {
      await settingsRepository.set('alertNotifications', value);
      set({ alertNotifications: value });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to save setting' });
      throw err;
    }
  },

  setNotificationIgnoredPackages: async (packages) => {
    try {
      await settingsRepository.set('notificationIgnoredPackages', packages);
      set({ notificationIgnoredPackages: packages });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to save setting' });
      throw err;
    }
  },

  setPrivacyPreference: async <K extends keyof PrivacyPreferences>(key: K, value: PrivacyPreferences[K]) => {
    try {
      const current = get().privacyPreferences;
      const updated = { ...current, [key]: value };
      await settingsRepository.set('privacyPreferences', updated);
      set({ privacyPreferences: updated });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to save setting' });
      throw err;
    }
  },

  setColorScheme: async (scheme) => {
    try {
      await settingsRepository.set('colorScheme', scheme);
      set({ colorScheme: scheme });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to save setting' });
      throw err;
    }
  },

  completeOnboarding: async () => {
    try {
      await settingsRepository.set('onboardingComplete', true);
      set({ onboardingComplete: true });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to save setting' });
      throw err;
    }
  },

  reset: async () => {
    try {
      await settingsRepository.reset();
      set({
        ...DEFAULTS,
        colorScheme: undefined,
        onboardingComplete: false,
      });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to reset settings' });
      throw err;
    }
  },

  refresh: async () => {
    set({ loading: true, error: null });
    try {
      const all = await settingsRepository.getAll();
      set({
        notificationMonitoring: all.notificationMonitoring ?? DEFAULTS.notificationMonitoring,
        backgroundProtection: all.backgroundProtection ?? DEFAULTS.backgroundProtection,
        alertNotifications: all.alertNotifications ?? DEFAULTS.alertNotifications,
        notificationIgnoredPackages: all.notificationIgnoredPackages ?? DEFAULTS.notificationIgnoredPackages,
        privacyPreferences: all.privacyPreferences ?? DEFAULTS.privacyPreferences,
        colorScheme: all.colorScheme,
        onboardingComplete: all.onboardingComplete ?? false,
        loading: false,
      });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to load settings', loading: false });
    }
  },
}));

/**
 * Initialize the database and load settings on app startup.
 * Call this once from the app root.
 */
export async function initializeSettings(): Promise<void> {
  await initSettings();
}