/**
 * Build-time application metadata.
 *
 * Kept in one place so the About screen and the report header never drift from
 * the package manifest. There are deliberately no secrets here: API keys and
 * service endpoints live only on the backend, never in the app bundle.
 */

export const APP_NAME = 'Mobile ThreatGuard';
export const APP_VERSION = '0.0.1';
export const APP_BUILD = 'dev';
export const APP_PACKAGE = 'com.threatguard.mobile';

/** Plain-language privacy commitments shown in Onboarding and About. */
export const PRIVACY_COMMITMENTS = [
  'Message text is analysed on this device and is never stored or uploaded.',
  'File and app checks send only a fingerprint (a SHA-256 hash) — never the file.',
  'ThreatGuard does not read other apps\u2019 private data or intercept encrypted traffic.',
] as const;

/** Third-party libraries shipped in the app, with their licence. */
export const OPEN_SOURCE = [
  { name: 'React Native', licence: 'MIT' },
  { name: 'React Navigation', licence: 'MIT' },
  { name: 'Zustand', licence: 'MIT' },
  { name: 'Lucide', licence: 'ISC' },
  { name: 'react-native-svg', licence: 'MIT' },
] as const;
