import React from 'react';
import { View } from 'react-native';
import { useTheme } from '../theme';
import {
  AppText,
  Button,
  Card,
  Chip,
  Divider,
  ListRow,
  Screen,
  SectionHeader,
  SettingRow,
} from '../components/ui';
import { Bell, ChevronRight, ClipboardList, Info, KeyRound, Moon, ShieldCheck, Sun, Monitor, Lock } from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useSettingsStore } from '../store';
import type { ColorScheme } from '../theme/tokens';

const THEME_OPTIONS: Array<{ id: ColorScheme | 'system'; label: string; icon: React.ReactNode }> = [
  { id: 'system', label: 'System', icon: <Monitor size={16} /> },
  { id: 'light', label: 'Light', icon: <Sun size={16} /> },
  { id: 'dark', label: 'Dark', icon: <Moon size={16} /> },
];

export function SettingsScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();
  const settings = useSettingsStore();

  const themeChoice: ColorScheme | 'system' = settings.colorScheme ?? 'system';

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={{ gap: theme.spacing.xl }}>
        {/* Appearance */}
        <View>
          <SectionHeader title="Appearance" />
          <Card>
            <View style={{ flexDirection: 'row', gap: theme.spacing.sm, flexWrap: 'wrap' }}>
              {THEME_OPTIONS.map((option) => (
                <Chip
                  key={option.id}
                  label={option.label}
                  icon={option.icon}
                  selected={themeChoice === option.id}
                  onPress={() =>
                    settings.setColorScheme(option.id === 'system' ? undefined : (option.id as ColorScheme))
                  }
                />
              ))}
            </View>
          </Card>
        </View>

        {/* Protection */}
        <View>
          <SectionHeader title="Protection" />
          <Card flush>
            <SettingRow
              title="Message monitoring"
              description="Read notification text to detect scams. Requires notification access."
              value={settings.notificationMonitoring}
              onValueChange={settings.setNotificationMonitoring}
              icon={<Bell size={20} color={theme.colors.textSecondary} />}
            />
            <Divider />
            <SettingRow
              title="Background protection"
              description="Run periodic scans while the app is closed."
              value={settings.backgroundProtection}
              onValueChange={settings.setBackgroundProtection}
              icon={<ShieldCheck size={20} color={theme.colors.textSecondary} />}
            />
            <Divider />
            <SettingRow
              title="Alert notifications"
              description="Show a system notification when a threat is found."
              value={settings.alertNotifications}
              onValueChange={settings.setAlertNotifications}
              icon={<Bell size={20} color={theme.colors.textSecondary} />}
            />
          </Card>
        </View>

        {/* Privacy */}
        <View>
          <SectionHeader title="Privacy" subtitle="What leaves this device" />
          <Card flush>
            <SettingRow
              title="Analyse messages on-device"
              description="Scam checks run locally. Turning this off disables message analysis."
              value={settings.privacyPreferences.analyzeNotificationsLocally ?? true}
              onValueChange={(v) => settings.setPrivacyPreference('analyzeNotificationsLocally', v)}
              icon={<Lock size={20} color={theme.colors.textSecondary} />}
            />
            <Divider />
            <SettingRow
              title="Allow file fingerprint lookups"
              description="Send only a file's SHA-256 to the reputation service. The file itself is never uploaded."
              value={settings.privacyPreferences.allowHashLookups ?? false}
              onValueChange={(v) => settings.setPrivacyPreference('allowHashLookups', v)}
              icon={<KeyRound size={20} color={theme.colors.textSecondary} />}
            />
            <Divider />
            <SettingRow
              title="Store message contents"
              description="Always off. ThreatGuard never stores the text of your messages."
              value={false}
              onValueChange={() => undefined}
              disabled
              icon={<Lock size={20} color={theme.colors.textSecondary} />}
            />
          </Card>
        </View>

        {/* More */}
        <View>
          <SectionHeader title="More" />
          <Card flush>
            <ListRow
              title="Security report"
              subtitle="A summary of your protection and findings"
              leading={<ClipboardList size={20} color={theme.colors.textSecondary} />}
              trailing={<ChevronRight size={18} color={theme.colors.textTertiary} />}
              onPress={() => navigation.navigate('Report')}
            />
            <Divider />
            <ListRow
              title="Permissions"
              subtitle="Review what ThreatGuard can access"
              leading={<KeyRound size={20} color={theme.colors.textSecondary} />}
              trailing={<ChevronRight size={18} color={theme.colors.textTertiary} />}
              onPress={() => navigation.navigate('Permissions')}
            />
            <Divider />
            <ListRow
              title="About ThreatGuard"
              subtitle="Version, licences and privacy"
              leading={<Info size={20} color={theme.colors.textSecondary} />}
              trailing={<ChevronRight size={18} color={theme.colors.textTertiary} />}
              onPress={() => navigation.navigate('About')}
            />
          </Card>
        </View>

        <Button
          label="Reset preferences"
          variant="ghost"
          onPress={settings.reset}
          accessibilityHint="Restores all settings to their defaults"
        />
      </View>
    </Screen>
  );
}
