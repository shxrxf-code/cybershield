/**
 * Design tokens for Mobile ThreatGuard.
 *
 * Tokens are the single source of truth for colour, spacing, radii, type and
 * motion. Screens and components never hard-code a hex value or a magic number;
 * they read from the active theme so light/dark and future high-contrast modes
 * stay consistent.
 *
 * The palette is deliberately calm and high-contrast: this is a security tool
 * that must remain legible under stress, and threat colours must never rely on
 * hue alone (icons/labels carry the meaning too).
 */

export type ColorScheme = 'light' | 'dark';

/** A complete, scheme-agnostic set of colour roles. */
export interface ColorTokens {
  /** App background behind all surfaces. */
  background: string;
  /** Default card / panel surface. */
  surface: string;
  /** Raised surface (modals, menus, pressed cards). */
  elevated: string;
  /** Recessed surface (inputs, code, progress tracks). */
  sunken: string;
  /** Subtle overlay used for pressed states. */
  overlay: string;
  border: string;
  borderStrong: string;

  textPrimary: string;
  textSecondary: string;
  textTertiary: string;
  textInverse: string;

  accent: string;
  accentPressed: string;
  accentMuted: string;
  onAccent: string;

  /** Threat semantic colours. */
  safe: string;
  suspicious: string;
  malicious: string;
  unknown: string;
  info: string;

  /** Translucent status backgrounds for badges/banners. */
  safeSurface: string;
  suspiciousSurface: string;
  maliciousSurface: string;
  unknownSurface: string;
  infoSurface: string;

  shadow: string;
  scrim: string;
}

export const palette = {
  // Neutrals
  slate950: '#070C16',
  slate900: '#0B1220',
  slate850: '#111A2C',
  slate800: '#17233B',
  slate700: '#24324D',
  slate600: '#334461',
  slate400: '#64748B',
  slate300: '#94A3B8',
  slate200: '#CBD5E1',
  slate100: '#E2E8F0',
  slate50: '#F5F7FB',
  white: '#FFFFFF',

  // Brand
  blue600: '#2563EB',
  blue500: '#3B82F6',
  blue400: '#4F8CFF',
  blue300: '#7DA9FF',
  blue950: '#0A1A3A',

  // Threat semantics
  green500: '#22C55E',
  green400: '#4ADE80',
  green950: '#052E16',
  amber500: '#F59E0B',
  amber400: '#FBBF24',
  amber950: '#3A2503',
  red500: '#EF4444',
  red400: '#F87171',
  red950: '#3B0A0A',
  sky500: '#38BDF8',
  sky950: '#082F49',

  black: '#000000',
} as const;

export const darkColors: ColorTokens = {
  background: palette.slate950,
  surface: palette.slate850,
  elevated: palette.slate800,
  sunken: palette.slate900,
  overlay: 'rgba(255,255,255,0.06)',
  border: palette.slate700,
  borderStrong: palette.slate600,

  textPrimary: '#F1F5F9',
  textSecondary: '#A5B4CB',
  textTertiary: palette.slate400,
  textInverse: palette.slate950,

  accent: palette.blue400,
  accentPressed: palette.blue500,
  accentMuted: 'rgba(79,140,255,0.16)',
  onAccent: palette.white,

  safe: palette.green400,
  suspicious: palette.amber400,
  malicious: palette.red400,
  unknown: palette.slate300,
  info: palette.sky500,

  safeSurface: 'rgba(74,222,128,0.14)',
  suspiciousSurface: 'rgba(251,191,36,0.14)',
  maliciousSurface: 'rgba(248,113,113,0.16)',
  unknownSurface: 'rgba(148,163,184,0.14)',
  infoSurface: 'rgba(56,189,248,0.14)',

  shadow: 'rgba(0,0,0,0.5)',
  scrim: 'rgba(2,6,16,0.7)',
};

export const lightColors: ColorTokens = {
  background: palette.slate50,
  surface: palette.white,
  elevated: palette.white,
  sunken: '#EEF2F9',
  overlay: 'rgba(15,23,42,0.05)',
  border: palette.slate100,
  borderStrong: palette.slate200,

  textPrimary: '#0F172A',
  textSecondary: '#475569',
  textTertiary: palette.slate400,
  textInverse: palette.white,

  accent: palette.blue600,
  accentPressed: '#1D4ED8',
  accentMuted: 'rgba(37,99,235,0.10)',
  onAccent: palette.white,

  safe: '#15803D',
  suspicious: '#B45309',
  malicious: '#B91C1C',
  unknown: '#475569',
  info: '#0369A1',

  safeSurface: 'rgba(34,197,94,0.14)',
  suspiciousSurface: 'rgba(245,158,11,0.16)',
  maliciousSurface: 'rgba(239,68,68,0.14)',
  unknownSurface: 'rgba(100,116,139,0.12)',
  infoSurface: 'rgba(14,165,233,0.14)',

  shadow: 'rgba(15,23,42,0.12)',
  scrim: 'rgba(15,23,42,0.4)',
};

/** 4pt spacing scale. */
export const spacing = {
  none: 0,
  xxs: 2,
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  xxl: 24,
  xxxl: 32,
  huge: 48,
} as const;

export const radius = {
  xs: 6,
  sm: 10,
  md: 14,
  lg: 20,
  xl: 28,
  pill: 999,
} as const;

export const typography = {
  display: { fontSize: 34, lineHeight: 40, fontWeight: '800' },
  title: { fontSize: 26, lineHeight: 32, fontWeight: '700' },
  heading: { fontSize: 20, lineHeight: 26, fontWeight: '700' },
  subheading: { fontSize: 17, lineHeight: 22, fontWeight: '600' },
  body: { fontSize: 15, lineHeight: 22, fontWeight: '400' },
  bodyStrong: { fontSize: 15, lineHeight: 22, fontWeight: '600' },
  label: { fontSize: 13, lineHeight: 18, fontWeight: '600' },
  caption: { fontSize: 12, lineHeight: 16, fontWeight: '500' },
  mono: { fontSize: 13, lineHeight: 18, fontWeight: '500' },
} as const;

export type TypographyToken = keyof typeof typography;

/** Elevation shadows for the raised surfaces. */
export const elevation = {
  none: {},
  sm: {
    shadowColor: palette.black,
    shadowOpacity: 0.12,
    shadowRadius: 4,
    shadowOffset: { width: 0, height: 1 },
    elevation: 1,
  },
  md: {
    shadowColor: palette.black,
    shadowOpacity: 0.18,
    shadowRadius: 10,
    shadowOffset: { width: 0, height: 4 },
    elevation: 4,
  },
  lg: {
    shadowColor: palette.black,
    shadowOpacity: 0.24,
    shadowRadius: 20,
    shadowOffset: { width: 0, height: 10 },
    elevation: 8,
  },
} as const;

export const motion = {
  fast: 140,
  base: 220,
  slow: 360,
} as const;

export const layout = {
  screenPadding: spacing.lg,
  maxContentWidth: 720,
  hitSlop: { top: 8, bottom: 8, left: 8, right: 8 },
} as const;
