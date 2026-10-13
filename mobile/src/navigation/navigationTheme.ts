import { DarkTheme, DefaultTheme, type Theme as NavigationTheme } from '@react-navigation/native';
import type { Theme } from '../theme';

/**
 * Bridge our design tokens into React Navigation's theme so headers, tab bars
 * and screen backgrounds follow the same palette as the rest of the app.
 */
export function toNavigationTheme(theme: Theme): NavigationTheme {
  const base = theme.isDark ? DarkTheme : DefaultTheme;
  return {
    ...base,
    dark: theme.isDark,
    colors: {
      ...base.colors,
      primary: theme.colors.accent,
      background: theme.colors.background,
      card: theme.colors.surface,
      text: theme.colors.textPrimary,
      border: theme.colors.border,
      notification: theme.colors.malicious,
    },
  };
}
