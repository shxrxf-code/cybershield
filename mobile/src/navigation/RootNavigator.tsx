import React from 'react';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { useTheme } from '../theme';
import { useSettingsStore } from '../store';
import { TabNavigator } from './TabNavigator';
import {
  AboutScreen,
  AlertDetailScreen,
  AppScannerScreen,
  DeviceScanScreen,
  FileScannerScreen,
  NotificationProtectionScreen,
  OnboardingScreen,
  PermissionsScreen,
  ReportScreen,
  ScanDetailScreen,
  UrlScannerScreen,
} from '../screens';
import type { RootStackParamList } from './types';

const Stack = createNativeStackNavigator<RootStackParamList>();

/**
 * The root navigator. On a fresh install it opens the introduction; once that
 * is completed it starts on the main tabs. Every pushed screen shares the same
 * themed header, so back navigation and titles are consistent.
 */
export function RootNavigator(): React.JSX.Element {
  const theme = useTheme();
  const onboardingComplete = useSettingsStore((s) => s.onboardingComplete);

  return (
    <Stack.Navigator
      initialRouteName={onboardingComplete ? 'MainTabs' : 'Onboarding'}
      screenOptions={{
        headerStyle: {
          backgroundColor: theme.colors.surface,
        },
        headerTitleStyle: { color: theme.colors.textPrimary, fontSize: 18, fontWeight: '700' },
        headerTintColor: theme.colors.accent,
        headerShadowVisible: false,
        headerBackButtonDisplayMode: 'minimal',
        contentStyle: { backgroundColor: theme.colors.background },
      }}
    >
      <Stack.Screen name="Onboarding" component={OnboardingScreen} options={{ headerShown: false }} />
      <Stack.Screen name="MainTabs" component={TabNavigator} options={{ headerShown: false }} />
      <Stack.Screen
        name="DeviceScan"
        component={DeviceScanScreen}
        options={({ route }) => ({ title: route.params.mode === 'quick' ? 'Quick scan' : 'Full scan' })}
      />
      <Stack.Screen name="UrlScanner" component={UrlScannerScreen} options={{ title: 'Check a link' }} />
      <Stack.Screen name="FileScanner" component={FileScannerScreen} options={{ title: 'Scan a file' }} />
      <Stack.Screen name="AppScanner" component={AppScannerScreen} options={{ title: 'Installed apps' }} />
      <Stack.Screen
        name="NotificationProtection"
        component={NotificationProtectionScreen}
        options={{ title: 'Message monitoring' }}
      />
      <Stack.Screen name="AlertDetail" component={AlertDetailScreen} options={{ title: 'Alert' }} />
      <Stack.Screen name="ScanDetail" component={ScanDetailScreen} options={{ title: 'Scan result' }} />
      <Stack.Screen name="Report" component={ReportScreen} options={{ title: 'Security report' }} />
      <Stack.Screen name="Permissions" component={PermissionsScreen} options={{ title: 'Permissions' }} />
      <Stack.Screen name="About" component={AboutScreen} options={{ title: 'About' }} />
    </Stack.Navigator>
  );
}
