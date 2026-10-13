/**
 * Mobile ThreatGuard — application root.
 *
 * Provider order matters: the safe-area provider sits outermost, the theme
 * provider sits inside it (so it can read the system colour scheme), and the
 * navigation container sits inside the theme (so headers and tab bars can use
 * the same design tokens as the rest of the UI).
 */

import React from 'react';
import { StatusBar } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { ThemeProvider, useTheme } from './src/theme';
import { toNavigationTheme } from './src/navigation/navigationTheme';
import { RootNavigator } from './src/navigation/RootNavigator';
import { useSettingsStore } from './src/store';

function Root(): React.JSX.Element {
  const theme = useTheme();

  return (
    <NavigationContainer theme={toNavigationTheme(theme)}>
      <StatusBar barStyle={theme.isDark ? 'light-content' : 'dark-content'} />
      <RootNavigator />
    </NavigationContainer>
  );
}

function App(): React.JSX.Element {
  const colorScheme = useSettingsStore((s) => s.colorScheme);

  return (
    <SafeAreaProvider>
      <ThemeProvider scheme={colorScheme}>
        <Root />
      </ThemeProvider>
    </SafeAreaProvider>
  );
}

export default App;
