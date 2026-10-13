import {
  darkColors,
  elevation,
  layout,
  lightColors,
  motion,
  radius,
  spacing,
  typography,
  type ColorScheme,
  type ColorTokens,
} from './tokens';

/**
 * A resolved theme: the active colour scheme plus the scheme-independent
 * scales. Components receive this object and never import raw tokens directly,
 * so a future high-contrast or branded theme is a drop-in addition.
 */
export interface Theme {
  scheme: ColorScheme;
  isDark: boolean;
  colors: ColorTokens;
  spacing: typeof spacing;
  radius: typeof radius;
  typography: typeof typography;
  elevation: typeof elevation;
  motion: typeof motion;
  layout: typeof layout;
}

export function buildTheme(scheme: ColorScheme): Theme {
  return {
    scheme,
    isDark: scheme === 'dark',
    colors: scheme === 'dark' ? darkColors : lightColors,
    spacing,
    radius,
    typography,
    elevation,
    motion,
    layout,
  };
}

export const darkTheme = buildTheme('dark');
export const lightTheme = buildTheme('light');

/**
 * Map a threat/verdict status to its semantic colour roles. Centralising this
 * stops individual screens from inventing their own green/red meanings.
 */
export type ThreatTone = 'safe' | 'suspicious' | 'malicious' | 'unknown' | 'info';

export interface ToneColors {
  fg: string;
  bg: string;
}

export function toneColors(theme: Theme, tone: ThreatTone): ToneColors {
  switch (tone) {
    case 'safe':
      return { fg: theme.colors.safe, bg: theme.colors.safeSurface };
    case 'suspicious':
      return { fg: theme.colors.suspicious, bg: theme.colors.suspiciousSurface };
    case 'malicious':
      return { fg: theme.colors.malicious, bg: theme.colors.maliciousSurface };
    case 'info':
      return { fg: theme.colors.info, bg: theme.colors.infoSurface };
    default:
      return { fg: theme.colors.unknown, bg: theme.colors.unknownSurface };
  }
}
