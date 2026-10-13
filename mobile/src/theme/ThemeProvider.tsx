import React, { createContext, useContext, useMemo } from 'react';
import { useColorScheme } from 'react-native';
import { buildTheme, darkTheme, type Theme } from './theme';
import type { ColorScheme } from './tokens';

interface ThemeContextValue {
  theme: Theme;
  /** The effective scheme currently in use. */
  scheme: ColorScheme;
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: darkTheme,
  scheme: 'dark',
});

export interface ThemeProviderProps {
  children: React.ReactNode;
  /**
   * Explicit scheme from user settings. Pass `undefined` to follow the device
   * system setting. The provider is fully controlled so the settings store is
   * the single source of truth for the user's choice.
   */
  scheme?: ColorScheme;
}

export function ThemeProvider({ children, scheme }: ThemeProviderProps): React.JSX.Element {
  const systemScheme = useColorScheme();
  const effective: ColorScheme = scheme ?? (systemScheme === 'light' ? 'light' : 'dark');

  const value = useMemo<ThemeContextValue>(
    () => ({ theme: buildTheme(effective), scheme: effective }),
    [effective],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): Theme {
  return useContext(ThemeContext).theme;
}

export function useThemeController(): ThemeContextValue {
  return useContext(ThemeContext);
}

/** Convenience hook for components that need the active scheme name. */
export function useAppScheme(): ColorScheme {
  return useContext(ThemeContext).scheme;
}
