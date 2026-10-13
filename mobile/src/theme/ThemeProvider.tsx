import React, { createContext, useContext, useMemo, useState } from 'react';
import { useColorScheme } from 'react-native';
import { buildTheme, darkTheme, type Theme } from './theme';
import type { ColorScheme } from './tokens';

interface ThemeContextValue {
  theme: Theme;
  scheme: ColorScheme;
  /** Pin a scheme, or pass `undefined` to follow the device again. */
  setScheme: (scheme: ColorScheme | undefined) => void;
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: darkTheme,
  scheme: 'dark',
  setScheme: () => undefined,
});

export interface ThemeProviderProps {
  children: React.ReactNode;
  /** Initial explicit scheme; omit to follow the system setting. */
  initialScheme?: ColorScheme;
}

/**
 * Provides the active theme. Follows the device colour scheme by default and
 * allows an explicit override (used by the Settings screen).
 */
export function ThemeProvider({ children, initialScheme }: ThemeProviderProps): React.JSX.Element {
  const systemScheme = useColorScheme();
  const [override, setOverride] = useState<ColorScheme | undefined>(initialScheme);

  const scheme: ColorScheme = override ?? (systemScheme === 'light' ? 'light' : 'dark');

  const value = useMemo<ThemeContextValue>(
    () => ({
      theme: buildTheme(scheme),
      scheme,
      setScheme: setOverride,
    }),
    [scheme],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): Theme {
  return useContext(ThemeContext).theme;
}

export function useThemeController(): ThemeContextValue {
  return useContext(ThemeContext);
}

/** Convenience hook for components that need both theme and scheme control. */
export function useAppScheme(): ColorScheme {
  return useContext(ThemeContext).scheme;
}
