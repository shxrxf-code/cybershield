/**
 * Jest environment tweaks.
 *
 * - Safe-area-context ships an official Jest mock; we register it so its native
 *   module is not required in the test environment.
 * - react-native-screens is mocked down to plain views, which is all the
 *   navigators need to render a tree in tests.
 * - The database service is mocked to avoid native SQLite in tests.
 */

require('react-native-safe-area-context/jest/mock');

jest.mock('react-native-screens', () => {
  const React = require('react');
  const { View } = require('react-native');
  const passthrough = (name) => {
    const Component = ({ children, ...props }) => React.createElement(View, props, children);
    Component.displayName = name;
    return Component;
  };
  return {
    enableScreens: jest.fn(),
    enableFreeze: jest.fn(),
    screensEnabled: jest.fn(() => false),
    Screen: passthrough('Screen'),
    ScreenContainer: passthrough('ScreenContainer'),
    ScreenStack: passthrough('ScreenStack'),
    ScreenStackHeaderConfig: passthrough('ScreenStackHeaderConfig'),
    ScreenStackHeaderSubview: passthrough('ScreenStackHeaderSubview'),
  };
});

jest.mock('@op-engineering/op-sqlite', () => ({
  openAsync: jest.fn().mockResolvedValue({
    execute: jest.fn().mockResolvedValue({ rows: [], rowsAffected: 0 }),
    executeSync: jest.fn().mockReturnValue({ rows: [], rowsAffected: 0 }),
    closeAsync: jest.fn().mockResolvedValue(undefined),
    getDbPath: jest.fn().mockReturnValue('/mock/path'),
  }),
  open: jest.fn(),
}));

jest.mock('src/db/service', () => ({
  getDB: jest.fn().mockResolvedValue({
    execute: jest.fn().mockResolvedValue({ rows: [], rowsAffected: 0 }),
    executeSync: jest.fn().mockReturnValue({ rows: [], rowsAffected: 0 }),
    closeAsync: jest.fn().mockResolvedValue(undefined),
    getDbPath: jest.fn().mockReturnValue('/mock/path'),
    transaction: jest.fn(),
  }),
  execute: jest.fn().mockResolvedValue({ rows: [], rowsAffected: 0 }),
  executeSync: jest.fn().mockReturnValue({ rows: [], rowsAffected: 0 }),
  transaction: jest.fn(),
  closeDB: jest.fn(),
  deleteDB: jest.fn(),
  getDBPath: jest.fn().mockResolvedValue('/mock/path'),
}));

jest.mock('src/db/scanRepository', () => ({
  scanRepository: {
    create: jest.fn().mockResolvedValue({}),
    findById: jest.fn().mockResolvedValue(null),
    findAll: jest.fn().mockResolvedValue([]),
    findRecent: jest.fn().mockResolvedValue([]),
    findByType: jest.fn().mockResolvedValue([]),
    findByHash: jest.fn().mockResolvedValue(null),
    update: jest.fn().mockResolvedValue(false),
    delete: jest.fn().mockResolvedValue(false),
    deleteAll: jest.fn().mockResolvedValue(0),
    count: jest.fn().mockResolvedValue(0),
    countByThreatLevel: jest.fn().mockResolvedValue({}),
  },
  createScanFromAPI: jest.fn().mockResolvedValue({}),
}));

jest.mock('src/db/alertRepository', () => ({
  alertRepository: {
    create: jest.fn().mockResolvedValue({}),
    findById: jest.fn().mockResolvedValue(null),
    findAll: jest.fn().mockResolvedValue([]),
    findUnread: jest.fn().mockResolvedValue([]),
    findRecent: jest.fn().mockResolvedValue([]),
    markRead: jest.fn().mockResolvedValue(false),
    markUnread: jest.fn().mockResolvedValue(false),
    markAllRead: jest.fn().mockResolvedValue(0),
    delete: jest.fn().mockResolvedValue(false),
    deleteAll: jest.fn().mockResolvedValue(0),
    count: jest.fn().mockResolvedValue(0),
    unreadCount: jest.fn().mockResolvedValue(0),
    getById: jest.fn().mockResolvedValue(undefined),
  },
}));

jest.mock('src/db/settingsRepository', () => ({
  settingsRepository: {
    get: jest.fn().mockResolvedValue(undefined),
    getAll: jest.fn().mockResolvedValue({}),
    set: jest.fn().mockResolvedValue(undefined),
    delete: jest.fn().mockResolvedValue(false),
    clear: jest.fn().mockResolvedValue(0),
    reset: jest.fn().mockResolvedValue(undefined),
  },
  initSettings: jest.fn().mockResolvedValue(undefined),
  DEFAULT_SETTINGS: {},
}));

jest.mock('src/store/useScanStore', () => ({
  useScanStore: () => ({
    records: [],
    loading: false,
    error: null,
    addRecord: jest.fn(),
    removeRecord: jest.fn(),
    clear: jest.fn(),
    getById: jest.fn(),
    refresh: jest.fn(),
    createFromAPI: jest.fn(),
  }),
  selectScanTotals: () => ({ totalScans: 0, totalThreats: 0, alertsBySeverity: {} }),
}));

jest.mock('src/store/useAlertStore', () => ({
  useAlertStore: () => ({
    alerts: [],
    loading: false,
    error: null,
    addAlert: jest.fn(),
    markRead: jest.fn(),
    markUnread: jest.fn(),
    markAllRead: jest.fn(),
    removeAlert: jest.fn(),
    clear: jest.fn(),
    getById: jest.fn(),
    unreadCount: () => 0,
    refresh: jest.fn(),
  }),
}));

jest.mock('src/store/useSettingsStore', () => ({
  useSettingsStore: () => ({
    notificationMonitoring: false,
    backgroundProtection: false,
    alertNotifications: true,
    privacyPreferences: { analytics: false, crashReporting: false, shareThreatData: false },
    colorScheme: undefined,
    onboardingComplete: false,
    loading: false,
    error: null,
    setNotificationMonitoring: jest.fn(),
    setBackgroundProtection: jest.fn(),
    setAlertNotifications: jest.fn(),
    setPrivacyPreference: jest.fn(),
    setColorScheme: jest.fn(),
    completeOnboarding: jest.fn(),
    reset: jest.fn(),
    refresh: jest.fn(),
  }),
  initializeSettings: jest.fn().mockResolvedValue(undefined),
}));