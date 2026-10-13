import React from 'react';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import {
  Bell,
  History as HistoryIcon,
  ScanLine,
  Settings as SettingsIcon,
  Shield,
} from 'lucide-react-native';
import { useTheme } from '../theme';
import { useAlertStore } from '../store';
import {
  AlertsScreen,
  DashboardScreen,
  HistoryScreen,
  ProtectionScreen,
  SettingsScreen,
} from '../screens';
import type { MainTabParamList } from './types';

const Tab = createBottomTabNavigator<MainTabParamList>();

type IconProps = { color: string; size: number };

const ICONS: Record<keyof MainTabParamList, (props: IconProps) => React.JSX.Element> = {
  Dashboard: (props) => <Shield {...props} />,
  Protection: (props) => <ScanLine {...props} />,
  Alerts: (props) => <Bell {...props} />,
  History: (props) => <HistoryIcon {...props} />,
  Settings: (props) => <SettingsIcon {...props} />,
};

/**
 * The five primary destinations. Headers come from the tab navigator so every
 * tab respects the same safe area and theme; the Alerts tab carries a live
 * unread badge driven by the alert store.
 */
export function TabNavigator(): React.JSX.Element {
  const theme = useTheme();
  const unread = useAlertStore((s) => s.alerts.filter((a) => !a.isRead).length);

  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        headerStyle: {
          backgroundColor: theme.colors.surface,
          borderBottomWidth: 1,
          borderBottomColor: theme.colors.border,
        },
        headerTitleStyle: { color: theme.colors.textPrimary, fontSize: 18, fontWeight: '700' },
        headerTintColor: theme.colors.accent,
        headerShadowVisible: false,
        tabBarActiveTintColor: theme.colors.accent,
        tabBarInactiveTintColor: theme.colors.textTertiary,
        tabBarStyle: {
          backgroundColor: theme.colors.surface,
          borderTopColor: theme.colors.border,
        },
        tabBarLabelStyle: { fontSize: 11, fontWeight: '600' },
        tabBarIcon: ({ color, size }) => ICONS[route.name]({ color, size }),
        tabBarBadge: route.name === 'Alerts' && unread > 0 ? unread : undefined,
        tabBarBadgeStyle: { backgroundColor: theme.colors.malicious, color: theme.colors.onAccent },
      })}
    >
      <Tab.Screen name="Dashboard" component={DashboardScreen} options={{ title: 'Dashboard' }} />
      <Tab.Screen name="Protection" component={ProtectionScreen} options={{ title: 'Protection' }} />
      <Tab.Screen name="Alerts" component={AlertsScreen} options={{ title: 'Alerts' }} />
      <Tab.Screen name="History" component={HistoryScreen} options={{ title: 'History' }} />
      <Tab.Screen name="Settings" component={SettingsScreen} options={{ title: 'Settings' }} />
    </Tab.Navigator>
  );
}
