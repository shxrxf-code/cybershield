import React from 'react';
import { Linking, View } from 'react-native';
import { useTheme } from '../theme';
import {
  AlertBanner,
  AppText,
  Button,
  Card,
  Divider,
  Screen,
  SectionHeader,
  SettingRow,
} from '../components/ui';
import {
  Bell,
  BellRing,
  ExternalLink,
  Info as InfoIcon,
  Lock,
  MessageSquare,
  ShieldAlert,
  TriangleAlert,
} from 'lucide-react-native';
import { useRootNavigation } from '../navigation/hooks';
import { useSettingsStore } from '../store';
import { capabilities } from '../capabilities';

/**
 * Controls message monitoring. The real system permission ("notification
 * access") can be opened from here, but the listener service that turns that
 * access into analysis is a later phase, so the toggle alone does not start
 * scanning.
 */
export function NotificationProtectionScreen(): React.JSX.Element {
  const theme = useTheme();
  const navigation = useRootNavigation();
  const monitoring = useSettingsStore((s) => s.notificationMonitoring);
  const setMonitoring = useSettingsStore((s) => s.setNotificationMonitoring);
  const alertNotifications = useSettingsStore((s) => s.alertNotifications);
  const setAlertNotifications = useSettingsStore((s) => s.setAlertNotifications);

  const openNotificationAccess = () => {
    void Linking.sendIntent('android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS').catch(() => {
      void Linking.openSettings();
    });
  };

  return (
    <Screen scroll edges={['left', 'right']}>
      <View style={{ gap: theme.spacing.xl }}>
        <Card>
          <View style={{ flexDirection: 'row', gap: theme.spacing.md }}>
            <MessageSquare size={24} color={theme.colors.accent} />
            <View style={{ flex: 1, gap: theme.spacing.xs }}>
              <AppText variant="heading">Message monitoring</AppText>
              <AppText variant="body" color="secondary">
                Watch message notifications for scam and phishing signals, then warn you before you
                tap anything.
              </AppText>
            </View>
          </View>
        </Card>

        {!capabilities.notificationListener ? (
          <AlertBanner
            tone="info"
            icon={<InfoIcon size={20} color={theme.colors.info} />}
            title="The listener is not running yet"
            message="This build can open Android's notification-access settings, but the service that reads exposed notification content is added in a later phase. Turning the switch on only records your preference for now."
          />
        ) : null}

        <View>
          <SectionHeader title="Monitoring" />
          <Card flush>
            <SettingRow
              title="Monitor message notifications"
              description="Scan the text Android exposes for suspicious links and scam wording."
              value={monitoring}
              onValueChange={setMonitoring}
              icon={<Bell size={20} color={monitoring ? theme.colors.safe : theme.colors.textSecondary} />}
            />
            <Divider />
            <SettingRow
              title="Notify me about threats"
              description="Raise a system notification when a monitored message is flagged."
              value={alertNotifications}
              onValueChange={setAlertNotifications}
              icon={<BellRing size={20} color={theme.colors.textSecondary} />}
            />
          </Card>
        </View>

        <View>
          <SectionHeader title="System access" subtitle="Granted in Android settings, not in this app" />
          <Card>
            <View style={{ gap: theme.spacing.md }}>
              <AppText variant="body" color="secondary">
                Android only lets an app read notifications if you allow notification access for it.
                ThreatGuard can only see the content Android exposes — it cannot open other apps or
                read their private data.
              </AppText>
              <Button
                label="Open notification access"
                variant="secondary"
                icon={<ExternalLink size={18} color={theme.colors.accent} />}
                onPress={openNotificationAccess}
              />
            </View>
          </Card>
        </View>

        <View>
          <SectionHeader title="What an alert tells you" />
          <Card flush>
            <AlertField icon={<MessageSquare size={18} color={theme.colors.textSecondary} />} label="Source app" />
            <Divider />
            <AlertField icon={<TriangleAlert size={18} color={theme.colors.textSecondary} />} label="Threat type and severity" />
            <Divider />
            <AlertField icon={<ShieldAlert size={18} color={theme.colors.textSecondary} />} label="Why it was flagged" />
            <Divider />
            <AlertField icon={<Lock size={18} color={theme.colors.textSecondary} />} label="A recommended action, without opening anything" />
          </Card>
        </View>

        <Card>
          <View style={{ gap: theme.spacing.md }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: theme.spacing.sm }}>
              <Lock size={18} color={theme.colors.textSecondary} />
              <AppText variant="subheading">Privacy limits</AppText>
            </View>
            <AppText variant="body" color="secondary">
              Message text is analysed on this device and is never stored or uploaded. ThreatGuard
              does not access private app data, bypass the Android sandbox, or intercept encrypted
              traffic.
            </AppText>
            <Button
              label="Review privacy and permissions"
              variant="ghost"
              icon={<ShieldAlert size={18} color={theme.colors.textSecondary} />}
              onPress={() => navigation.navigate('Permissions')}
            />
          </View>
        </Card>
      </View>
    </Screen>
  );
}

interface AlertFieldProps {
  icon: React.ReactNode;
  label: string;
}

function AlertField({ icon, label }: AlertFieldProps): React.JSX.Element {
  const theme = useTheme();
  return (
    <View
      style={{
        flexDirection: 'row',
        alignItems: 'center',
        gap: theme.spacing.md,
        paddingVertical: theme.spacing.md,
        paddingHorizontal: theme.spacing.lg,
      }}
    >
      {icon}
      <AppText variant="body" color="secondary" style={{ flex: 1 }}>
        {label}
      </AppText>
    </View>
  );
}
